// vim:set ts=4 sw=4 ai:

/*
 * Copyright (c) 2010-2013 BitTorrent, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#else
    #include <io.h>
#endif
#ifndef HAVE_GETOPT
    #include "getopt.h"
#endif

#ifdef HAVE_POLL
    #include <poll.h>
#endif
#ifdef HAVE_SIGNAL
	#include <signal.h>
#endif

#ifdef __linux__
    #include <sys/socket.h>
    
    #include <netinet/in.h>
    #include <netinet/ip.h>
    
    #include <netdb.h>
	#include <linux/errqueue.h>
	#include <netinet/ip_icmp.h>
#endif

#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/util.h"

#include "utp.h"
#ifdef WINDOWS
	#include "Stdin.h"
#endif
#include "Log.h"
#include "Buffer.h"
#include "Socket.h"

#ifndef STDOUT_FILENO
	#define STDOUT_FILENO 1
#endif
#ifndef STDIN_FILENO
    #define	STDIN_FILENO 0
#endif

// options
static CBuffer *g_pBuffer = NULL;
static utp_context *g_pUtpContext = NULL;
static utp_socket *g_pUtpSocket = NULL;
static bool g_bListen = false;
static int g_nDebug = false;

struct event_base* g_pBase = NULL;
app::CUdpSocket g_Udp;

void hexdump(const void *p, size_t len)
{
    int count = 1;
	unsigned char* c = (unsigned char*)p;
	unsigned char* cc = c;
    while (len--) {
        if (count == 1)
			printf("    %p: ", c);
		
		printf(" %02x", *(unsigned char*)c++ & 0xff);

        if (count++ == 8) {
			printf("        ");
			while(c != cc)
            {
                unsigned char a = *cc++;
                if(a>=37 && a<=126)
					printf("%c ", a);
                else 
					printf(". ");
            }
			printf("\n");
            count = 1;
        }
    }

    if (count != 1)
		printf("\n");
}

int write_data(void)
{
	if (!g_pUtpSocket)
	{
		LOG_MODEL_ERROR("ucat", "g_utpSocket is null\n");
		g_pBuffer->SubContent(g_pBuffer->GetContentLength());
		return -1;
	}

	while (g_pBuffer->GetContentLength()) {
		size_t sent;

		sent = utp_write(g_pUtpSocket, g_pBuffer->GetContent(),
			g_pBuffer->GetContentLength());
		if (0 > sent)
		{
			LOG_MODEL_ERROR("ucat", "utp_write fail: %d\n", sent);
		}else if(sent == 0) {
			LOG_MODEL_DEBUG("ucat", "socket no longer writable\n");
			return 0;
		}
		g_pBuffer->SubContent(sent);
		LOG_MODEL_DEBUG("ucat", "wrote %zd bytes; %d bytes left in buffer\n",
			sent, g_pBuffer->GetContentLength());
	}

	return 0;
}

uint64 callback_on_accept(utp_callback_arguments *a)
{
	assert(!g_pUtpSocket);
	if (g_pUtpSocket)
	{
		LOG_MODEL_ERROR("ucat", "g_pUtpSocket isn't null\n");
		return -1;
	}
	g_pUtpSocket = a->socket;
	LOG_MODEL_DEBUG("ucat", "Accepted inbound socket %p\n", g_pUtpSocket);
	write_data();
	return 0;
}

uint64 callback_on_read(utp_callback_arguments *a)
{
	const unsigned char *p;
	ssize_t len, left;

	left = a->len;
	p = a->buf;

	while (left) {
		len = write(STDOUT_FILENO, p, left);
		left -= len;
		p += len;
		LOG_MODEL_DEBUG("ucat", "Wrote %d bytes, %d left\n", len, left);
	}
	utp_read_drained(a->socket);
	return 0;
}

uint64 callback_on_firewall(utp_callback_arguments *a)
{
	if (!g_bListen) {
		LOG_MODEL_DEBUG("ucat",
			"Firewalling unexpected inbound connection in non-listen mode\n");
		return 1;
	}

	if (g_pUtpSocket) {
		LOG_MODEL_DEBUG("ucat",
			"Firewalling unexpected second inbound connection\n");
		return 1;
	}

	LOG_MODEL_DEBUG("ucat", "Firewall allowing inbound connection\n");
	return 0;
}

uint64 callback_on_error(utp_callback_arguments *a)
{
	LOG_MODEL_ERROR("ucat", "%s\n", utp_error_code_names[a->error_code]);
	event_base_loopexit(g_pBase, NULL);
	return 0;
}

uint64 callback_on_state_change(utp_callback_arguments *a)
{
	LOG_MODEL_DEBUG("ucat", "state %d: %s\n",
		a->state, utp_state_names[a->state]);
	utp_socket_stats *stats;

	switch (a->state) {
		case UTP_STATE_CONNECT:
			LOG_MODEL_DEBUG("ucat", "UTP_STATE_CONNECT\n");
		case UTP_STATE_WRITABLE:
			LOG_MODEL_DEBUG("ucat", "UTP_STATE_WRITABLE\n");
			write_data();
			break;

		case UTP_STATE_EOF:
			LOG_MODEL_DEBUG("ucat", "Received EOF from socket\n");
			utp_close(a->socket);
			event_base_loopexit(g_pBase, NULL);
			break;

		case UTP_STATE_DESTROYING:
			LOG_MODEL_DEBUG("ucat",
				"UTP socket is being destroyed; exiting\n");

			stats = utp_get_stats(a->socket);
			if (stats) {
				printf("Socket Statistics:\n");
				printf("    Bytes sent:          %d\n", stats->nbytes_xmit);
				printf("    Bytes received:      %d\n", stats->nbytes_recv);
				printf("    Packets received:    %d\n", stats->nrecv);
				printf("    Packets sent:        %d\n", stats->nxmit);
				printf("    Duplicate receives:  %d\n", stats->nduprecv);
				printf("    Retransmits:         %d\n", stats->rexmit);
				printf("    Fast Retransmits:    %d\n", stats->fastrexmit);
				printf("    Best guess at MTU:   %d\n", stats->mtu_guess);
			}
			else {
				LOG_MODEL_DEBUG("ucat", "No socket statistics available\n");
			}

			g_pUtpSocket = NULL;
			break;
	}

	return 0;
}

uint64 callback_sendto(utp_callback_arguments *a)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) a->address;

	LOG_MODEL_DEBUG("ucat", "sendto: %zd byte packet to %s:%d%s\n",
		a->len, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
		(a->flags & UTP_UDP_DONTFRAG) ?
		"  (DF bit requested, but not yet implemented)" : "");

	if (g_nDebug >= 3)
		hexdump(a->buf, a->len);

	g_Udp.SendTo((const char*)a->buf, a->len, 0,
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	return 0;
}

uint64 callback_log(utp_callback_arguments *a)
{
	fprintf(stderr, "log: %s\n", a->buf);
	return 0;
}

int setup(const char* pszRemoteIp, unsigned int nRemotePort)
{
	int ret = 0;

    do{       
        g_pUtpContext = utp_init(2);
		if (NULL == g_pUtpContext)
		{
			LOG_MODEL_ERROR("ucat", "utp_init fail\n");
			return -1;
		}
        assert(g_pUtpContext);
		LOG_MODEL_DEBUG("ucat", "UTP context %p\n", g_pUtpContext);

        utp_set_callback(g_pUtpContext, UTP_LOG,			 &callback_log);
        utp_set_callback(g_pUtpContext, UTP_SENDTO,			 &callback_sendto);
        utp_set_callback(g_pUtpContext, UTP_ON_ERROR,		 &callback_on_error);
        utp_set_callback(g_pUtpContext, UTP_ON_STATE_CHANGE, &callback_on_state_change);
        utp_set_callback(g_pUtpContext, UTP_ON_READ,		 &callback_on_read);
        utp_set_callback(g_pUtpContext, UTP_ON_FIREWALL,	 &callback_on_firewall);
        utp_set_callback(g_pUtpContext, UTP_ON_ACCEPT,		 &callback_on_accept);
        
        if (g_nDebug >= 2) {
            utp_context_set_option(g_pUtpContext, UTP_LOG_NORMAL, 1);
            utp_context_set_option(g_pUtpContext, UTP_LOG_MTU,    1);
            utp_context_set_option(g_pUtpContext, UTP_LOG_DEBUG,  1);
        }
        
        if (!g_bListen) {
            g_pUtpSocket = utp_create_socket(g_pUtpContext);
            assert(g_pUtpSocket);
			LOG_MODEL_INFO("ucat", "UTP socket %p\n", g_pUtpSocket);
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = inet_addr(pszRemoteIp);
			addr.sin_port = htons(nRemotePort);
           
			LOG_MODEL_INFO("ucat", "Connecting to %s:%d\n",
				pszRemoteIp, nRemotePort);
            
            utp_connect(g_pUtpSocket,
				(struct sockaddr*)&addr, sizeof(struct sockaddr_in));
        }
    }while(0);

    return ret;
}

static void
CallbackTimeout(evutil_socket_t fd, short event, void *arg)
{
	if(g_pUtpContext)
		utp_check_timeouts(g_pUtpContext);
}

static void
CallbackSignal(evutil_socket_t fd, short event, void *arg)
{
	struct timeval delay = { 2, 0 };
    
	LOG_MODEL_DEBUG("ucat", "caught signal\n");
	if (g_pUtpSocket)
		utp_close(g_pUtpSocket);
    
	LOG_MODEL_DEBUG("ucat", "Caught an interrupt signal; exiting cleanly.\n");

	event_base_loopexit(g_pBase, NULL);
}

void CallbackUdpSocketRead(evutil_socket_t fd, short events, void *arg)
{
    int nLen = 0;
    char data[4096];
	char szIp[32];
	unsigned int nPort;
	struct sockaddr_in addr;

	if (!g_pUtpContext)
	{
		LOG_MODEL_ERROR("ucat", "g_pUtpContext is null\n");
		return;
	}

	while (1) {
		nLen = g_Udp.ReceiveFrom(data, sizeof(data), 0, szIp, &nPort);
        if (nLen < 0) {
			if(g_Udp.IsWOULDBLOCK())
            {
                utp_issue_deferred_acks(g_pUtpContext);
                break;
            }
            else
            {
				LOG_MODEL_ERROR("ucat", "pUdp->ReceiveFrom fail: %d\n",
					g_Udp.GetLastError());
                event_base_loopexit(g_pBase, NULL);
                break;
            }
        }

        LOG_MODEL_INFO("ucat", "Received %d byte UDP packet from %s:%d\n",
			nLen, szIp, nPort);

		if(g_nDebug >= 3)
			hexdump(data, nLen);

		struct sockaddr_in src_addr;
		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = inet_addr(szIp);
		src_addr.sin_port = htons(nPort);
        if (! utp_process_udp(g_pUtpContext, (const byte*)data, nLen,
			(struct sockaddr *)&src_addr, sizeof(struct sockaddr_in)))
			LOG_MODEL_DEBUG("ucat",
				"UDP packet not handled by UTP.  Ignoring.\n");
    }
}

void CallbackStdin(evutil_socket_t fd, short events, void* arg)
{
    int nLen = 0;

#ifdef WINDOWS
	app::CTcpSocket* s = (app::CTcpSocket*)arg;
	nLen = s->Receive(g_pBuffer->GetBuffer(), g_pBuffer->GetLength(), 0);
#else
	nLen = read(STDIN_FILENO, g_pBuffer->GetBuffer(), g_pBuffer->GetLength());
#endif
    if (nLen < 0 && errno != EINTR)
    { 
        LOG_MODEL_ERROR("ucat", "read stdin fail\n");
        event_base_loopexit(g_pBase, NULL);
    }
    if (nLen == 0) {
        LOG_MODEL_DEBUG("ucat", "EOF from file\n");
		
#ifndef WINDOWS
        close(STDIN_FILENO);
#endif
		event_base_loopexit(g_pBase, NULL);
		return;
    }
    else {
		g_pBuffer->AddContent(nLen);
        LOG_MODEL_DEBUG("ucat",
			"Read stdin %d bytes, buffer now %d bytes long\n", nLen, g_pBuffer->GetContentLength());
    }
    write_data();
}

void usage(char *name)
{
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "    %s [options] <destination-IP> <destination-port>\n", name);
	fprintf(stderr, "    %s [options] -l -p <listening-port>\n", name);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h          Help\n");
	fprintf(stderr, "    -d          Debug mode; use multiple times to increase verbosity.\n");
	fprintf(stderr, "    -l          Listen mode\n");
	fprintf(stderr, "    -p <port>   Local port\n");
	fprintf(stderr, "    -s <IP>     Source IP\n");
	fprintf(stderr, "    -B <size>   Buffer size\n");
	fprintf(stderr, "    -n          Don't resolve hostnames\n");
	fprintf(stderr, "\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int nRet = 0, i = 0;
	std::string szLocalAddr = "0.0.0.0";
	unsigned int nLocalPort = 0;
	std::string szRemoteAddr;
	unsigned int nRemotePort = 0;
	
	bool bNumeric = false;
	int nBufSize = 4096;

	struct event *pEvSignal = NULL;
	struct event *pEvTimeout = NULL;
	struct event *pEvStdin = NULL;
	struct event *pEvUdpSock = NULL;
	struct timeval tv = { 0, 500 };

	while (1) {
		int c = getopt (argc, argv, "hdlp:B:s:n");
		if (c == -1) break;
		switch(c) {
			case 'h': usage(argv[0]);				break;
			case 'd': g_nDebug++;       			break;
			case 'l': g_bListen = true;		        break;
			case 'p': nLocalPort = atoi(optarg);	break;
			case 'B': nBufSize = atoi(optarg);	    break;
			case 's': szLocalAddr = optarg;		    break;
			case 'n': bNumeric = true;				break;
			//case 'w': break;	// timeout for connects and final net reads
			default:
				LOG_MODEL_ERROR("ucat", "Unhandled argument: %c\n", c);
				return -1;
		}
	}

	for (i = optind; i < argc; i++) {
		switch(i - optind) {
			case 0:	szRemoteAddr = argv[i]; 	 break;
			case 1:	nRemotePort = atoi(argv[i]); break;
		}
	}

	if (g_bListen && (nRemotePort || !szRemoteAddr.empty()))
		usage(argv[0]);

	if (!g_bListen && (!nRemotePort || szRemoteAddr.empty()))
		usage(argv[0]);

	g_pBuffer = new CBuffer(nBufSize);
	if (!g_pBuffer)
	{
		LOG_MODEL_ERROR("ucat", "new buffer fail\n");
		return -2;
	}
   
    do{
        //event_enable_debug_logging(EVENT_DBG_ALL);
		g_pBase = event_base_new();
        if (!g_pBase)
        {
            LOG_MODEL_ERROR("ucat", "Could not initialize libevent!\n");
			nRet = -3;
            break;
        }
		
        /* Initalize signal */
		pEvSignal = evsignal_new(g_pBase, SIGINT, CallbackSignal, NULL);
        if (!pEvSignal || event_add(pEvSignal, NULL))
        {
			LOG_MODEL_ERROR("ucat", "Could not create/add a signal event!\n");
			nRet = -4;
            break;
        }
        
		pEvTimeout = event_new(g_pBase, -1, EV_PERSIST, CallbackTimeout, NULL);
        if(!pEvTimeout || event_add(pEvTimeout, &tv))
        {
			LOG_MODEL_ERROR("ucat", "Could not create/add a timeout event!\n");
			nRet = -5;
            break;
        }

#ifdef WINDOWS
		CStdin *pStdin = CStdin::GetInstance();
		if (NULL == pStdin)
		{
			nRet = -6;
			break;
		}

		pEvStdin = event_new(g_pBase,
			pStdin->GetSocket()->GetSocket(),
			EV_READ | EV_PERSIST,
			CallbackStdin,
			pStdin->GetSocket());
		if (!pEvStdin || event_add(pEvStdin, NULL))
		{
			LOG_MODEL_ERROR("ucat",
				"Could not create / add a stdin_fileno event!\n");
			nRet = -7;
			break;
		}
#else
		pEvStdin = event_new(g_pBase,
                           STDIN_FILENO,
                           EV_READ | EV_PERSIST,
						   CallbackStdin,
		                   NULL);
        if(!pEvStdin || event_add(pEvStdin, NULL))
        {
			LOG_MODEL_ERROR("ucat",
				"Could not create / add a stdin_fileno event!\n");
			nRet = -6;
			break;
        }
#endif

		nRet = g_Udp.Create(nLocalPort, szLocalAddr.c_str());
		if (nRet)
		{
			LOG_MODEL_ERROR("ucat", "create udp fail: %d\n",
				g_Udp.GetLastError());
			nRet = -8;
			break;
		}
		pEvUdpSock = event_new(g_pBase,
				g_Udp.GetSocket(),
				EV_READ | EV_PERSIST,
			    CallbackUdpSocketRead,
			    NULL);
		if (!pEvUdpSock || event_add(pEvUdpSock, NULL))
		{
			LOG_MODEL_ERROR("ucat", "Could not create/add a socket event!\n");
			nRet = -9;
			break;
		}
		
		g_Udp.SetGetError();
		g_Udp.SetNonBlocking();

		if (setup(szRemoteAddr.c_str(), nRemotePort))
			break;

        event_base_dispatch(g_pBase);
        
        if (g_pBuffer->GetContentLength()) {
			LOG_MODEL_WARNING("ucat", "send buffer not empty\n");
			nRet = -10;
        }
        
        utp_context_stats *stats = utp_get_context_stats(g_pUtpContext);
        
        if (stats) {
			printf("           Bucket size:    <23    <373    <723    <1400    >1400\n");
			printf("Number of packets sent:  %5d   %5d   %5d    %5d    %5d\n",
                  stats->_nraw_send[0], stats->_nraw_send[1], stats->_nraw_send[2], stats->_nraw_send[3], stats->_nraw_send[4]);
			printf("Number of packets recv:  %5d   %5d   %5d    %5d    %5d\n",
                  stats->_nraw_recv[0], stats->_nraw_recv[1], stats->_nraw_recv[2], stats->_nraw_recv[3], stats->_nraw_recv[4]);
        }
        else {
			printf("utp_get_context_stats() failed?\n");
        }

		if(g_pUtpSocket) utp_close(g_pUtpSocket);
		utp_check_timeouts(g_pUtpContext);
		LOG_MODEL_INFO("ucat", "Destroying context\n");
        utp_destroy(g_pUtpContext);
    }while(0);
    
	if (pEvUdpSock) event_free(pEvUdpSock);
	if (pEvStdin) event_free(pEvStdin);
	if (pEvTimeout) event_free(pEvTimeout);
    if (pEvSignal) event_free(pEvSignal);
    if (g_pBase) event_base_free(g_pBase);
    
	if (g_pBuffer) delete g_pBuffer;
    
	return nRet;
}
