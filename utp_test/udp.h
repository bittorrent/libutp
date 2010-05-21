#ifndef __UDP_H__
#define __UDP_H__

// since Win32 also defines these, we create definitions for these on other platforms
#ifndef WIN32
#define closesocket close
#define WSAGetLastError() errno
#define SOCKET int
#define INVALID_SOCKET -1
#endif

struct UdpOutgoing {
	SOCKADDR_STORAGE to;
	uint len;
	byte mem[1];
};

// this must be a power of 2.
#define UDP_OUTGOING_SIZE 32

class UDPSocketManager {
public:
	SOCKET _socket;

	int pos,count;
	UdpOutgoing *buff[UDP_OUTGOING_SIZE];

	UDPSocketManager();

	void set_socket(SOCKET s);
	void select(int microsec);
	void Send(const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen);
	void Flush();
};

#endif //__UDP_H__
