//Author: KangLin<kl222@126.com>

#ifndef __STDIN_H_KL_2018_12_14__
#define __STDIN_H_KL_2018_12_14__

#pragma once

#include <string>
#include "Socket.h"

class CStdin
{
private:
	CStdin();
	virtual ~CStdin();

public:
	static CStdin *GetInstance();
	app::CTcpSocket* GetSocket();

	int OnStdin();
	static DWORD StdinThread(LPVOID lpParam);

private:
	app::CTcpSocket m_ListerSocket, m_Socket;

protected:
	int Init();
private:
	int RangedRand(int min, int max);
	std::string m_szIp;
	int m_iPort;
};

#endif //__STDIN_H_KL_2018_12_14__
