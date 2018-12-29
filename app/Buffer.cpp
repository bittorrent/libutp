//Author: KangLin<kl222@126.com>

#include "Buffer.h"
#include "Log.h"

CBuffer::CBuffer(int nLength)
{
	m_nLenght = nLength;
	m_pBuffer = new char[m_nLenght];
	m_pStart = m_pEnd = m_pBuffer;
}

CBuffer::~CBuffer()
{
	if (m_pBuffer)
		delete m_pBuffer;
}

char* CBuffer::GetBuffer()
{
	return m_pEnd;
}

int CBuffer::GetLength()
{
	return m_nLenght - (m_pEnd - m_pBuffer);
}

char* CBuffer::GetContent()
{
	return m_pStart;
}

int CBuffer::GetContentLength()
{
	return m_pEnd - m_pStart;
}

int CBuffer::SubContent(int nLength)
{
	if (nLength > m_pEnd - m_pStart)
	{
		LOG_MODEL_ERROR("CBuffer", "Add content length less than the buffer\n");
		return -1;
	}
	m_pStart += nLength;
	return 0;
}

int CBuffer::AddContent(int nLength)
{
	if (nLength > m_nLenght + m_pBuffer - m_pEnd)
	{
		LOG_MODEL_ERROR("CBuffer", "Add content length more than the buffer\n");
		return -1;			
	}
	m_pEnd += nLength;
	return 0;
}
