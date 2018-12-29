//Author: KangLin<kl222@126.com>

#ifndef __SOCKET_H_KL2018_12_14__
#define __SOCKET_H_KL2018_12_14__

#pragma once

#ifdef WINDOWS
    #include <Windows.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <stddef.h>
    #include <errno.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>

    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

namespace app
{
	class CSocket
	{
	protected:
		CSocket();
		virtual ~CSocket();
	
	public:
		/*
		* @param: nPort: The host order
		*/
		virtual int Create(int nPort = 0, const char* pszAddress = NULL) = 0;
		virtual int Close();
		/*
		* @param: nPort: The host order
		*/
		virtual int Bind(unsigned int nPort, const char* pszAddress = NULL);
		virtual int Listen(unsigned int nConnecttionBack = 5);
		/*
		* @param: nPort: The host order
		*/
		virtual int Connect(const char *pszAddress, unsigned int nPort);
		virtual int Receive(char *pBuf, int nLen, int nFlags);
		/*
		 * @param: pnPort: The host order
		 */
		virtual int ReceiveFrom(char *pBuf, int nLen, int nFlags,
			char* pszAddress = NULL, unsigned int *pnPort = NULL);
		virtual int Send(const char *pBuf, int nLen, int nFlags);
		/*
		* @param: nPort: The host order
		*/
		virtual int SendTo(const char *pBuf, int nLen, int nFlags,
			const char* pszAddress, unsigned int nPort);
		virtual int IoCtl(long lCommand, unsigned long *pArg) ;

		int SetNonBlocking(bool bNonBlocking = true);
		int SetGetError(bool bErr = true);
		SOCKET GetSocket();

		int GetLastError();
		bool IsWOULDBLOCK();

	protected:
		SOCKET m_Socket;
	};

	class CTcpSocket : public CSocket
	{
	public:
		CTcpSocket();
		virtual ~CTcpSocket();

		virtual int Create(int nPort = 0, const char* pszAddress = "0.0.0.0");
		virtual int Accept(CTcpSocket& socket, char* pszAddress = NULL,
			unsigned int *pnPort = NULL);
		void operator = (const SOCKET &s);
	};

	class CUdpSocket : public CSocket
	{
	public:
		CUdpSocket();
		virtual ~CUdpSocket();
		virtual int Create(int nPort = 0, const char* pszAddress = NULL);
	};
    
} //namespace app

#endif //__SOCKET_H_KL2018_12_14__
