#ifdef WIN32
#define _CRT_SECURE_NO_DEPRECATE
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>

#ifdef WIN32
// newer versions of MSVC define these in errno.h
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#define EMSGSIZE WSAEMSGSIZE
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define ETIMEDOUT WSAETIMEDOUT
#endif
#endif

// platform-specific includes
#ifdef POSIX
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#ifdef FREEBSD
#include <strings.h>            // POSIX requires this split-up between string.h and strings.h
#include <sys/uio.h>            // FreeBSD:  for readv, writev
#include <sys/mount.h>          // FreeBSD:  for statfs
#include <ifaddrs.h>            // FreeBSD:  for ifaddrs, getifaddrs, freeifaddrs
#include <net/if_dl.h>          // FreeBSD:  for sockaddr_dl
#include <sys/sysctl.h>         // FreeBSD:  for system control in util_posix.cpp
#endif

#else  // WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win32_inet_ntop.h"

#endif //WIN32

#ifdef POSIX
typedef sockaddr_storage SOCKADDR_STORAGE;
#endif // POSIX

#include "utp.h"
#include "utp_utils.h"

#include "udp.h"

// These are for casting the options for getsockopt
// and setsockopt which if incorrect can cause these
// calls to fail.
#ifdef WIN32
typedef char * SOCKOPTP;
typedef const char * CSOCKOPTP;
#else
typedef void * SOCKOPTP;
typedef const void * CSOCKOPTP;
#endif

FILE *log_file = NULL;
UTPSocket *utp_socket = NULL;
FILE *file = NULL;
size_t total_sent = 0;
size_t file_size = 0;

void utp_log(char const* fmt, ...)
{
	fprintf(log_file, "[%u] ", UTP_GetMilliseconds());
	va_list vl;
	va_start(vl, fmt);
	vfprintf(log_file, fmt, vl);
	va_end(vl);
	fputs("\n", log_file);
}

UDPSocketManager::UDPSocketManager()
	: _socket(INVALID_SOCKET), pos(0), count(0)
{
}

// Send a message on the actual UDP socket
void UDPSocketManager::Send(const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	assert(len <= UTP_GetUDPMTU(to, tolen));

	if (count > 0 ||
		sendto(_socket, (char*)p, len, 0, (struct sockaddr*)to, tolen) < 0) {
		// Buffer a packet.
		if (
#ifndef WIN32
			errno != EPERM && errno != EINVAL && 
#endif
			count < UDP_OUTGOING_SIZE) {
			UdpOutgoing *q = (UdpOutgoing*)malloc(sizeof(UdpOutgoing) - 1 + len);
			memcpy(&q->to, to, tolen);
			q->len = len;
			memcpy(q->mem, p, len);
			buff[pos] = q;
			pos = (pos + 1) & (UDP_OUTGOING_SIZE-1);
			count++;
			printf("buffering packet: %d %s\n", count, strerror(errno));
		} else {
			printf("sendto failed: %s\n", strerror(errno));
		}
	}
}

void UDPSocketManager::Flush()
{
	assert(count >= 0);
	while (count != 0) {
		UdpOutgoing *uo = buff[(pos - count) & (UDP_OUTGOING_SIZE-1)];

		if (sendto(_socket, (char*)uo->mem, uo->len, 0, (struct sockaddr*)&uo->to, sizeof(uo->to)) < 0) {
#ifndef WIN32
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				printf("sendto failed: %s\n", strerror(errno));
				break;
			}
#endif
		}

		free(uo);
		count--;
	}
	assert(count >= 0);
}

SOCKET make_socket(const struct sockaddr *addr, socklen_t addrlen)
{
	SOCKET s = socket(addr->sa_family, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET) return s;

	if (bind(s, addr, addrlen) < 0) {
		char str[20];
		printf("UDP port bind failed %s: (%d) %s\n",
			   inet_ntop(addr->sa_family, (sockaddr*)addr, str, sizeof(str)), errno, strerror(errno));
		closesocket(s);
		return INVALID_SOCKET;
	}

	// Mark to hold a couple of megabytes
	int size = 2 * 1024 * 1024;

	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (CSOCKOPTP)&size, sizeof(size)) < 0) {
		printf("UDP setsockopt(SO_RCVBUF, %d) failed: %d %s\n", size, errno, strerror(errno));
	}
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (CSOCKOPTP)&size, sizeof(size)) < 0) {
		printf("UDP setsockopt(SO_SNDBUF, %d) failed: %d %s\n", size, errno, strerror(errno));
	}

	// make socket non blocking
#ifdef _WIN32
	u_long b = 1;
	ioctlsocket(s, FIONBIO, &b);
#else
	int flags = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

	return s;
}

void UDPSocketManager::set_socket(SOCKET s)
{
	if (_socket != INVALID_SOCKET) closesocket(_socket);
	assert(s != INVALID_SOCKET);
	_socket = s;
}

void send_to(void *userdata, const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	((UDPSocketManager*)userdata)->Send(p, len, to, tolen);
}

void UDPSocketManager::select(int microsec)
{
	struct timeval tv = {microsec / 1000000, microsec % 1000000};
	fd_set r, e;
	FD_ZERO(&r);
	FD_ZERO(&e);
	FD_SET(_socket, &r);
	FD_SET(_socket, &e);
	int ret = ::select(_socket + 1, &r, 0, &e, &tv);

	if (ret == 0) return;

	if (ret < 0) {
		printf("select() failed: %s\n", strerror(errno));
		return;
	}

	Flush();

	if (FD_ISSET(_socket, &r)) {
		byte buffer[8192];
		SOCKADDR_STORAGE sa;
		socklen_t salen = sizeof(sa);

		for (;;) {
			int len = recvfrom(_socket, (char*)buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, &salen);
			if (len < 0) {
				int err = WSAGetLastError();
				// ECONNRESET - On a UDP-datagram socket
				// this error indicates a previous send operation
				// resulted in an ICMP Port Unreachable message.
				if (err == ECONNRESET) continue;
				// EMSGSIZE - The message was too large to fit into
				// the buffer pointed to by the buf parameter and was
				// truncated.
				if (err == EMSGSIZE) continue;
				// any other error (such as EWOULDBLOCK) results in breaking the loop
				break;
			}

			// Lookup the right UTP socket that can handle this message
			if (UTP_IsIncomingUTP(NULL, &send_to, this,
								  buffer, (size_t)len, (const struct sockaddr*)&sa, salen))
				continue;
		}

		if (FD_ISSET(_socket, &e)) {
			// error!
			printf("socket error!\n");
		}
	}

}

void utp_read(void* socket, const byte* bytes, size_t count)
{
	assert(utp_socket == socket);
	printf("utp on_read %u\n", count);
	assert(false);
}

void utp_write(void* socket, byte* bytes, size_t count)
{
	assert(utp_socket == socket);
	const size_t read = fread(bytes, 1, count, file);
	assert(read == count);
	total_sent += read;
}

size_t utp_get_rb_size(void* socket)
{
	assert(utp_socket == socket);
	return 0;
}

void utp_state(void* socket, int state)
{
	assert(utp_socket == socket);
	if (state == UTP_STATE_CONNECT || state == UTP_STATE_WRITABLE) {
		if (UTP_Write(utp_socket, file_size - ftell(file))) {
			printf("upload complete\n");
			UTP_Close(utp_socket);
			fclose(file);
			file = NULL;
		}
	} else if (state == UTP_STATE_DESTROYING) {
		utp_socket = NULL;
	}
}

void utp_error(void* socket, int errcode)
{
	assert(utp_socket == socket);
	printf("socket error: (%d) %s\n", errcode, strerror(errcode));
	if (file) {
		UTP_Close(utp_socket);
		fclose(file);
		file = NULL;
	}
}

void utp_overhead(void *socket, bool send, size_t count, int type)
{
}

int main(int argc, char* argv[])
{
	int port = 0;

	if (argc < 4) {
		printf("usage: %s log-file destination file\n\n"
			"   log-file: name and path of the file to log uTP logs to\n"
			"   destination: destination node to connect to, in the form <host>:<port>\n"
			"   file: the file to upload\n\n"
			, argv[0]);
		return 1;
	}

	char const* log_file_name = argv[1];
	char *dest = argv[2];
	char *file_name = argv[3];

	printf("logging to '%s'\n", log_file_name);
	printf("connecting to %s\n", dest);
	printf("sending '%s'\n", file_name);

	log_file = fopen(log_file_name, "w+");
	file = fopen(file_name, "rb");
	assert(file);
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	if (file_size == 0) {
		printf("file is 0 bytes\n");
		return -1;
	}

#ifdef WIN32
	// ow
	WSADATA wsa;
	BYTE byMajorVersion = 2, byMinorVersion = 2;
	int result = WSAStartup(MAKEWORD(byMajorVersion, byMinorVersion), &wsa);
	if (result != 0 || LOBYTE(wsa.wVersion) != byMajorVersion || HIBYTE(wsa.wVersion) != byMinorVersion ) {
		if (result == 0) WSACleanup();
		return -1;
	}
#endif

	UDPSocketManager sm;

	sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	SOCKET sock = make_socket((const struct sockaddr*)&sin, sizeof(sin));

	sm.set_socket(sock);

	char *portchr = strchr(dest, ':');
	*portchr = 0;
	portchr++;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(dest);
	sin.sin_port = htons(atoi(portchr));

	utp_socket = UTP_Create(&send_to, &sm, (const struct sockaddr*)&sin, sizeof(sin));
	UTP_SetSockopt(utp_socket, SO_SNDBUF, 100*300);
	printf("creating socket %p\n", utp_socket);

	UTPFunctionTable utp_callbacks = {
		&utp_read,
		&utp_write,
		&utp_get_rb_size,
		&utp_state,
		&utp_error,
		&utp_overhead
	};
	UTP_SetCallbacks(utp_socket, &utp_callbacks, utp_socket);

	printf("connecting socket %p\n", utp_socket);
	UTP_Connect(utp_socket);

	int last_sent = 0;
	unsigned int last_time = UTP_GetMilliseconds();

	while (utp_socket) {
		sm.select(50000);
		UTP_CheckTimeouts();
		unsigned int cur_time = UTP_GetMilliseconds();
		if (cur_time >= last_time + 1000) {
			float rate = (total_sent - last_sent) * 1000.f / (cur_time - last_time);
			last_sent = total_sent;
			last_time = cur_time;
			printf("\r[%u] sent: %d/%d  %.1f bytes/s  ", cur_time, total_sent, file_size, rate);
			fflush(stdout);
		}
	}

	fclose(log_file);
}
