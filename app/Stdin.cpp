//Author: KangLin<kl222@126.com>

#include "Stdin.h"
#include "Log.h"
#include <stdio.h>

CStdin::CStdin()
{
	m_iPort = RangedRand(18888, 18988);
	m_szIp = "127.0.0.1";
}

CStdin::~CStdin()
{
}

CStdin* CStdin::GetInstance()
{
	static CStdin *p = NULL;
	if (!p)
	{
		p = new CStdin();
		if (p)
		{
			if (p->Init())
			{
				delete p;
				p = NULL;
			}
		}
	}
	return p;
}

app::CTcpSocket* CStdin::GetSocket()
{
	return &m_Socket;
}

int CStdin::Init()
{
	int nRet = 0;

	nRet = m_ListerSocket.Create(m_iPort, m_szIp.c_str());
	if (nRet)
		return nRet;
	else
		LOG_MODEL_INFO("CStdin", "stdin lister bind: %d\n", m_iPort);

	nRet = m_ListerSocket.SetNonBlocking(false);
	if (nRet)
		return nRet;
	
	nRet = m_ListerSocket.Listen();
	if (nRet)
		return nRet;

	HANDLE hThread = CreateThread(NULL, 0,
		(LPTHREAD_START_ROUTINE)CStdin::StdinThread, this, NULL, NULL);
	if (NULL == hThread)
	{
		LOG_MODEL_ERROR("Stdin", "Create Thread fail: %d\n", GetLastError());
	}
	char szIP[24];
	unsigned int nPort;
	bool bRet = m_ListerSocket.Accept(m_Socket, szIP, &nPort);
	if (INVALID_SOCKET != m_Socket.GetSocket())
	{
		nRet = m_ListerSocket.SetNonBlocking(true);
		LOG_MODEL_DEBUG("CStdin", "Accept socket from %s:%d\n",
			szIP, nPort);
	}

	return nRet;
}

int CStdin::OnStdin()
{
	int nRet = 0;
	char buf[256];
	app::CTcpSocket s;

	Sleep(1000); //wait lister socket is accepted 

	nRet = s.Create();
	if (nRet)
		return nRet;

	nRet = s.Connect(m_szIp.c_str(), m_iPort);
	if (nRet)
	{
		LOG_MODEL_ERROR("CStdin",
			"connect stdin fail:%d. in stdin_thread!\n", WSAGetLastError());
		return nRet;
	}

	while (fgets(buf, sizeof(buf), stdin))
	{
		send(s.GetSocket(), buf, strlen(buf), 0);
	}
	
	LOG_MODEL_INFO("CStdin", "The stdin thread exit\n");

	return 0;
}

DWORD CStdin::StdinThread(LPVOID lpParam)
{
	CStdin* p = (CStdin*)lpParam;
	if (p)
		p->OnStdin();
	return 0;
}

int CStdin::RangedRand(int min, int max)
{
	srand(GetTickCount());
	return (double)rand() / (max + 1) * (max - min) + min;
}