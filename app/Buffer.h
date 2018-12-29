//Author: KangLin<kl222@126.com>

#ifndef __BUFFER_H_KL_2018_12_18__
#define __BUFFER_H_KL_2018_12_18__

#pragma once

class CBuffer
{
public:
	CBuffer(int nLength = 4096);
	virtual ~CBuffer();

	char* GetBuffer();
	int GetLength();
	char* GetContent();
	int GetContentLength();
	int SubContent(int nLength);
	int AddContent(int nLength);

private:
	char *m_pBuffer;
	char *m_pStart;
	char *m_pEnd;
	int m_nLenght;
};

#endif //__BUFFER_H_KL_2018_12_18__