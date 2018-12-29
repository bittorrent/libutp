//Author: KangLin<kl222@126.com>

#include "Socket.h"
#include "Log.h"
#include <string.h>
#include <assert.h>

#ifdef WINDOWS
    typedef int socklen_t;
#endif

namespace app
{

#ifdef WINDOWS
	class CWinSocketInit
	{
	public:
		CWinSocketInit(){
			WORD version_requested = MAKEWORD(2, 0);
			WSADATA wsa_data;
			WSAStartup(version_requested, &wsa_data);
		}
		~CWinSocketInit() { WSACleanup(); }
	};
	
	CWinSocketInit g_winSocketInit;
#endif

	CSocket::CSocket()
	{
		m_Socket = INVALID_SOCKET;
	}

	CSocket::~CSocket()
	{
	}
	
	int CSocket::GetLastError()
	{
#ifdef WINDOWS
		return WSAGetLastError();
#else
		return errno;
#endif
	}

	bool CSocket::IsWOULDBLOCK()
	{
#ifdef WINDOWS
		if (WSAEWOULDBLOCK == GetLastError())
#else
		if (GetLastError() == EAGAIN || GetLastError() == EWOULDBLOCK)
#endif
			return true;
		else
			return false;
	}

	int CSocket::Close()
	{
		int nRet = 0;
		if (INVALID_SOCKET != m_Socket)
		{
#ifdef WINDOWS
			nRet = closesocket(m_Socket);
#else
			nRet = close(m_Socket);
#endif
		}
		return nRet;
	}

	int CSocket::Bind(unsigned int nPort, const char* pszAddress)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		assert(pszAddress);
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(pszAddress);
		addr.sin_port = htons(nPort);
		nRet = bind(m_Socket, (const sockaddr*)&addr, sizeof(addr));
		if (nRet)
		{
			LOG_MODEL_ERROR("CSocket", "Bind fail[%d]: %s:%d\n",
				GetLastError(), pszAddress, nPort);
		}
		else
		{
			struct sockaddr_in sin;
			socklen_t len = sizeof(sin);
			if (getsockname(m_Socket, (struct sockaddr *) &sin, &len) != 0)
			{
				LOG_MODEL_ERROR("CSocket", "getsockname fail: %d\n",
					this->GetLastError());
			}
			LOG_MODEL_DEBUG("CSocket", "Bound to local %s:%d\n",
				inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
		}
		return nRet;
	}

	int CSocket::Listen(unsigned int nConnecttionBack)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		nRet = listen(m_Socket, nConnecttionBack);
		if (nRet)
		{
			LOG_MODEL_ERROR("CSocket", "listen fail[%d]\n", GetLastError());
		}
		return nRet;
	}

	int CSocket::Connect(const char * pszAddress, unsigned int nPort)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		assert(pszAddress);
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(pszAddress);
		addr.sin_port = htons(nPort);
		nRet = connect(m_Socket,(sockaddr*) &addr, sizeof(addr));
		if (nRet)
		{	
			LOG_MODEL_ERROR("CSocket",
				"Connect fail[%d]: %s:%d\n",
				GetLastError(), pszAddress, nPort);
		}
		return nRet;
	}

	int CSocket::Receive(char * pBuf, int nLen, int nFlags)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		if(pBuf && nLen > 0)
			nRet = recv(m_Socket, (char*)pBuf, nLen, nFlags);
		return nRet;
	}

	int CSocket::ReceiveFrom(char * pBuf, int nLen, int nFlags,
		char * pszAddress, unsigned int * pnPort)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		assert(pBuf);
		struct sockaddr_in addr;
		socklen_t nLength = sizeof(struct sockaddr_in);
		nRet = recvfrom(m_Socket, (char*)pBuf, nLen, nFlags,
			(sockaddr*) &addr, &nLength);
		if (SOCKET_ERROR != nRet)
		{
			if (pszAddress)
				strcpy(pszAddress, inet_ntoa(addr.sin_addr));
			if (pnPort) *pnPort = ntohs(addr.sin_port);
		}
		//else
		//	LOG_MODEL_ERROR("CSocket", "recvform fail: %d\n", GetLastError());
		return nRet;
	}

	int CSocket::Send(const char * pBuf, int nLen, int nFlags)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		nRet = send(m_Socket, pBuf, nLen, nFlags);
		//if (SOCKET_ERROR == nRet)
		//	LOG_MODEL_ERROR("CSocket", "send fail: %d\n", GetLastError());
		return nRet;
	}

	int CSocket::SendTo(const char * pBuf, int nLen, int nFlags,
		const char * pszAddress, unsigned int nPort)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		assert(pBuf);
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(pszAddress);
		addr.sin_port = htons(nPort);
		nRet = sendto(m_Socket, pBuf, nLen, nFlags,
			(sockaddr*)&addr, sizeof(addr));
		if (SOCKET_ERROR == nRet)
			LOG_MODEL_ERROR("CSocket", "sendto fail: %d\n", GetLastError());
		return nRet;
	}

	int CSocket::IoCtl(long lCommand, unsigned long * pArg)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
#ifdef WINDOWS
		nRet = ioctlsocket(m_Socket, lCommand, pArg);
#else
		int flags = 0;
		if ((flags = fcntl(m_Socket, F_GETFL, NULL)) < 0)
		{
			LOG_MODEL_ERROR("CSocket", "fcntl F_GETFL fail \n");
			return -2;
		}
		if (!(flags & lCommand))
		{
			nRet = fcntl(m_Socket, F_SETFL, flags | lCommand);
			if (nRet)
			{
				LOG_MODEL_ERROR("CSocket", "fcntl F_SETFL fail \n");
			}
		}
#endif

		return nRet;
	}

	int CSocket::SetNonBlocking(bool bNonBlocking)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		unsigned long nonblocking = 0;
		if (bNonBlocking)
			nonblocking = 1;
		long cmd;
#ifdef WINDOWS
		cmd = FIONBIO;
#else
		cmd = O_NONBLOCK;
#endif
		nRet = IoCtl(cmd, &nonblocking);
		return nRet;
	}

	int CSocket::SetGetError(bool bErr)
	{
		int nRet = 0;
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		
		int nErr = 0;
		if (bErr)
			nErr = 1;
#ifdef __linux__
		nRet = setsockopt(m_Socket, SOL_IP, IP_RECVERR, &bErr, sizeof(bErr));
#else
		LOG_MODEL_ERROR("CSocket", " CSocket::SetGetError isn't completed\n");
#endif
		return nRet;
		
	}

	SOCKET CSocket::GetSocket()
	{
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CSocket",
				"Don't call CSocket::Create(), please call it. \n");
		}
		return m_Socket;
	}

	CTcpSocket::CTcpSocket() : CSocket()
	{
	}

	CTcpSocket::~CTcpSocket()
	{
	}

	int CTcpSocket::Create(int nPort, const char * pszAddress)
	{
		int nRet = 0;
		if (INVALID_SOCKET != m_Socket)
		{
			LOG_MODEL_ERROR("CTcpSocket", "The socket is exists\n");
			return -2;
		}

		m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CTcpSocket",
				"Create socket fail: %d\n", GetLastError());
			return -1;
		}

		nRet = Bind(nPort, pszAddress);

		return nRet;
	}

	int CTcpSocket::Accept(CTcpSocket & socket, char * pszAddress, unsigned int *pnPort)
	{
		int nRet = 0;
		struct sockaddr_in addr;
		socklen_t nLength = sizeof(struct sockaddr_in);
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CTcpSocket", 
				"Don't call CSocket::Create(), please call it. \n");
			return -1;
		}
		SOCKET s = accept(m_Socket, (sockaddr*)&addr, &nLength);
		if (INVALID_SOCKET == s)
		{
			LOG_MODEL_ERROR("CTcpSocket", "Accept fail: %d\n", GetLastError());
			return -3;
		}
		socket = s;
		if(pszAddress) strcpy(pszAddress,
			inet_ntoa(addr.sin_addr));
		if(pnPort) *pnPort = ntohs(addr.sin_port);

		return nRet;
	}

	void CTcpSocket::operator=(const SOCKET & s)
	{
		if (INVALID_SOCKET == m_Socket)
			m_Socket = s;
		else
			LOG_MODEL_ERROR("CTcpSocket", "The socket is exist\n");
	}

	CUdpSocket::CUdpSocket()
	{
	}

	CUdpSocket::~CUdpSocket()
	{
	}

	int CUdpSocket::Create(int nPort, const char * pszAddress)
	{
		int nRet = 0;
		if (INVALID_SOCKET != m_Socket)
		{
			LOG_MODEL_ERROR("CTcpSocket", "The socket is exists\n");
			return -2;
		}

		m_Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (INVALID_SOCKET == m_Socket)
		{
			LOG_MODEL_ERROR("CTcpSocket",
				"Create socket fail: %d\n", GetLastError());
			return -1;
		}

		nRet = Bind(nPort, pszAddress);

		return nRet;
	}
    
} //namespace app
