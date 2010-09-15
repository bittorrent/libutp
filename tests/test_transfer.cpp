#include "utp.h"
#include "utp_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "templates.h"

#include <errno.h>
#ifdef WIN32
// newer versions of MSVC define these in errno.h
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#endif

#ifdef POSIX
typedef sockaddr_storage SOCKADDR_STORAGE;
#endif // POSIX

#ifdef _WIN32
#define msleep(x) Sleep(x)
#else
#include <unistd.h>
#define msleep(x) usleep(x*1000)
#endif

#define utassert assert
#define utassert_failmsg(expr,failstmt) if (!(expr)) { failstmt; utassert(#expr); }

extern uint32 g_current_ms;

struct utp_socket {

	utp_socket(UTPSocket* s);
	~utp_socket();

	void close();
	size_t write(char const* buf, size_t count);
	void flush_write();

	static void utp_read(void* socket, const byte* bytes, size_t count);
	static void on_utp_write(void *socket, byte *bytes, size_t count);
	static void on_utp_state(void *socket, int state);
	static void on_utp_error(void *socket, int errcode);
	static void on_utp_overhead(void *socket, bool send, size_t count, int type) {}

	static size_t get_rb_size(void *socket)
	{ return 0; }

	// write buffer
	size_t _buf_size;
	char _buffer[10*1024*2];

	size_t _read_bytes;
	bool _connected;
	bool _readable;
	bool _writable;
	bool _ignore_reset;
	bool _destroyed;

	UTPSocket* _sock;
};

UTPFunctionTable utp_callbacks = {
	&utp_socket::utp_read,
	&utp_socket::on_utp_write,
	&utp_socket::get_rb_size,
	&utp_socket::on_utp_state,
	&utp_socket::on_utp_error,
	&utp_socket::on_utp_overhead
};

utp_socket* incoming = NULL;

struct TestUdpOutgoing {
	int timestamp;
	SOCKADDR_STORAGE addr;
	socklen_t addrlen;
	size_t len;
	byte mem[1];
};

struct test_manager
{
	test_manager() :
		_receiver(NULL), _loss_counter(0), _loss_every(0), _reorder_counter(0), _reorder_every(0)
	{
		_send_buffer.Init();
	}
	void drop_one_packet_every(int x) { _loss_every = x; }
	void reorder_one_packet_every(int x) { _reorder_every = x; }
	void IncomingUTP(UTPSocket* conn)
	{
		//printf("\nIn IncomingUTP\n");
		utassert_failmsg(incoming == NULL, printf("\nincoming expected NULL actual %p\n", incoming));
		incoming = new utp_socket(conn);
		incoming->_connected = true;
		incoming->_writable = true;
	}

	void Send(const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen);
	void Flush(uint32 start_time, uint32 max_time);
	void clear();
	void bind(test_manager* receiver)
	{
		_receiver = receiver;
	}

	~test_manager()
	{
		clear();
		_send_buffer.Free();
	}

	test_manager* _receiver;
	int _loss_counter;
	int _loss_every;

	int _reorder_counter;
	int _reorder_every;

	Array<TestUdpOutgoing*> _send_buffer;
};

int ComparePacketTimestamp(TestUdpOutgoing* const* lhs, TestUdpOutgoing* const* rhs)
{
	return (*lhs)->timestamp - (*rhs)->timestamp;
}

void test_incoming_proc(void *userdata, UTPSocket* conn)
{
	((test_manager*)userdata)->IncomingUTP(conn);
}

void test_send_to_proc(void *userdata, const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	((test_manager*)userdata)->Send(p, len, to, tolen);
}

void test_manager::Flush(uint32 start_time, uint32 max_time)
{
	//printf("In test_manager::Flush");
	_send_buffer.Sort(&ComparePacketTimestamp);

	for (size_t i = 0; i < _send_buffer.GetCount(); ++i) {
		TestUdpOutgoing *uo = _send_buffer[i];
//		utassert(uo);

		if ((uint32)uo->timestamp > g_current_ms) continue;

		if (_receiver) {
			// Lookup the right UTP socket that can handle this message
			UTP_IsIncomingUTP(&test_incoming_proc, &test_send_to_proc, _receiver, uo->mem, uo->len,
							  (const struct sockaddr*)&uo->addr, uo->addrlen);
		}

		_send_buffer.MoveUpLast(i);
		--i;
		free(uo);
	}
}

void test_manager::clear()
{
	_loss_every = 0;
	_reorder_every = 0;
	_loss_counter = 0;
	_reorder_counter = 0;
	for(size_t i = 0; i < _send_buffer.GetCount(); i++) {
		free(_send_buffer[i]);
	}
	_send_buffer.Clear();
}

void test_manager::Send(const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	if (_loss_every > 0 && _loss_counter == _loss_every) {
		_loss_counter = 0;
		//printf("DROP!\n");
		return;
	} else {
		++_loss_counter;
	}

	int delay = 10 + rand() % 30;

	++_reorder_counter;
	if (_reorder_counter >= _reorder_every && _reorder_every > 0) {
		delay = 9;
		_reorder_counter = 0;
	}

	TestUdpOutgoing *q = (TestUdpOutgoing*)malloc(sizeof(TestUdpOutgoing) - 1 + len);
	q->timestamp = g_current_ms + delay;
	memcpy(&q->addr, to, tolen);
	q->addrlen = tolen;
	q->len = len;
	memcpy(q->mem, p, len);
	_send_buffer.Append(q);
}

test_manager* send_udp_manager = 0;
test_manager* receive_udp_manager = 0;

utp_socket::utp_socket(UTPSocket* s) :
	_buf_size(0), _read_bytes(0),
	_connected(false), _readable(false), _writable(false), _ignore_reset(false),
	_destroyed(false),  _sock(s)
{
//	printf("utp_socket: %x sock: %x\n", this, _sock);
	utassert(s);
	UTP_SetCallbacks(_sock, &utp_callbacks, this);
}

void utp_socket::close()
{
//	printf("~utp_socket: %x\n", this);
	UTP_Close(_sock);
}

utp_socket::~utp_socket()
{
	utassert(_sock == NULL);
}

void utp_socket::utp_read(void* socket, const byte* bytes, size_t count)
{
	utp_socket* s = (utp_socket*)socket;
	//printf("received %d\n", count);
	s->_read_bytes += count;
	//printf("utp_socket::read %x sock: %x bytes: %d\n", s, s->_sock, bytes);
// TODO: assert the bytes we receive matches the pattern we sent
}

// called when the socket is ready to write count bytes
void utp_socket::on_utp_write(void *socket, byte *bytes, size_t count)
{
	utp_socket* s = (utp_socket*)socket;
	//printf("utp_socket::write %x sock: %x\n", s, s->_sock);
//	utassert(count <= s->_buf_size);
	memcpy(bytes, s->_buffer, count);
	memmove(s->_buffer, s->_buffer+count, s->_buf_size - count);
	s->_buf_size -= count;
	//printf("sending %d bytes (%d left)\n", count, s->_buf_size);
}

void utp_socket::flush_write()
{
	//printf("utp_socket::flush_write %x sock: %x\n", this, _sock);
	if (!_writable) return;
	if (_buf_size == 0) return;

	_writable = UTP_Write(_sock, _buf_size);
//	if (!_writable) printf("not writable\n");
}

void utp_socket::on_utp_state(void *socket, int state)
{
	utp_socket* s = (utp_socket*)socket;
	utassert(s->_sock);
	//printf("utp_socket::state %x sock: %x\n", s, s->_sock);
	switch(state) {
	case UTP_STATE_CONNECT:
		utassert(!s->_destroyed);
		s->_connected = true;
//		printf("connected!\n");
		s->_writable = true;
		s->flush_write();
		break;
	case UTP_STATE_WRITABLE:
		utassert(s->_connected && !s->_destroyed);
		s->_writable = true;
//		printf("writable!\n");
		s->flush_write();
		break;
	case UTP_STATE_DESTROYING:
		utassert(!s->_destroyed);
		s->_connected = false;
		s->_readable = false;
		s->_writable = false;
		s->_destroyed = true;
		s->_sock = NULL;
		break;
	case UTP_STATE_EOF:
		utassert(s->_connected && !s->_destroyed);
		s->_readable = false;
		s->_connected = false;
		break;
	}
}

bool g_error = false;

void utp_socket::on_utp_error(void *socket, int errcode)
{
	printf("\nUTP ERROR: %d for socket %p\n", errcode, socket);
	utp_socket* usock = ((utp_socket*)socket);
	if (!usock->_ignore_reset || errcode != ECONNRESET) {
		g_error = true;
		utassert(false);
	}
	usock->close();
}

size_t utp_socket::write(char const* buf, size_t count)
{
	assert(_buf_size <= sizeof(_buffer));
	size_t free = sizeof(_buffer) - _buf_size;
	size_t to_write = count < free ? count : free;
	if (to_write == 0) return 0;
	memcpy(_buffer + _buf_size, buf, to_write);
	_buf_size += count;
	//printf("writing %d bytes to write buffer\n", count);
	flush_write();
	return to_write;
}

void tick()
{
	static int tick_counter = 0;

	++tick_counter;
	if (tick_counter == 10) {
		tick_counter = 0;
		UTP_CheckTimeouts();
	}

	uint32 start_time = UTP_GetMilliseconds();
	uint32 max_time = 1000;

	send_udp_manager->Flush(start_time, max_time);
	receive_udp_manager->Flush(start_time, max_time);

	msleep(5);
}

enum flags_t {
	use_utp_v1 = 1,
	simulate_packetloss = 2,
	simulate_packetreorder = 4,
	heavy_loss = 8,
};

void test_transfer(int flags)
{
	sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(12345);

	UTPSocket* sock = UTP_Create(&test_send_to_proc, send_udp_manager,
								 (const struct sockaddr*)&sin, sizeof(sin));

	utp_socket* sender = new utp_socket(sock);
	if (flags & use_utp_v1) {
		UTP_SetSockopt(sender->_sock, SO_UTPVERSION, 1);
	} else {
		UTP_SetSockopt(sender->_sock, SO_UTPVERSION, 0);
	}

	send_udp_manager->clear();
	receive_udp_manager->clear();

	if (flags & simulate_packetloss) {
		send_udp_manager->drop_one_packet_every(33);
		receive_udp_manager->drop_one_packet_every(47);

		if (flags & heavy_loss) {
			send_udp_manager->drop_one_packet_every(7);
			receive_udp_manager->drop_one_packet_every(13);
		}
	}

	if (flags & simulate_packetreorder) {
		send_udp_manager->reorder_one_packet_every(27);
		receive_udp_manager->reorder_one_packet_every(23);
	}

	UTP_Connect(sender->_sock);

	for (int i = 0; i < 1500; ++i) {
		tick();
		if (sender->_connected && incoming) break;
	}
	utassert(incoming);
	if (!incoming) return;
	utassert(sender->_connected);
	if (!sender->_connected) return;

	char buffer[16*1024];
	for (size_t i = 0; i < sizeof(buffer); ++i) buffer[i] = i & 0xff;

	const size_t send_target = 10 * 16 * 1024;

	size_t written = sender->write(buffer, sizeof(buffer));
	utassert(written > 0);

	for (int i = 0; i < 20000; ++i) {
		tick();
//		utassert(incoming->_read_bytes <= written);
//		utassert(written <= send_target);
		if (incoming->_read_bytes == send_target) break;
		if (written < send_target && sender->_writable)
		{
			int offset = written % (16 * 1024);
			written += sender->write(buffer + offset, 1024 * 16 - offset);
//			printf("written: %d\n", written);
		}
	}
	utassert_failmsg(incoming->_read_bytes == written, printf("\nread_bytes: %d written: %d\n", incoming->_read_bytes, written));

	sender->close();

	for (int i = 0; i < 1500; ++i) {
		tick();
		if (incoming->_connected == false) break;
	}
	utassert(incoming->_connected == false);

	incoming->close();

	// we know at this point that the sender sent all the data and the receiver got EOF.
	// shutdown might be disrupted by dropped packets, so ignore RSTs
	if (flags & simulate_packetloss) {
		sender->_ignore_reset = true;
		incoming->_ignore_reset = true;
	}

	for (int i = 0; i < 1500; ++i) {
		tick();
		if (sender->_destroyed == true) break;
	}
	utassert(sender->_destroyed == true);

	for (int i = 0; i < 1500; ++i) {
		tick();
		if (incoming->_destroyed == true) break;
	}
	utassert(incoming->_destroyed == true);

	delete sender;
	delete incoming;
	incoming = NULL;
}

bool wrapping_compare_less(uint32 lhs, uint32 rhs);

int main()
{
	utassert(wrapping_compare_less(0xfffffff0, 0xffffffff) == true);
	utassert(wrapping_compare_less(0xffffffff, 0xfffffff0) == false);
	utassert(wrapping_compare_less(0xfff, 0xfffffff0) == false);
	utassert(wrapping_compare_less(0xfffffff0, 0xfff) == true);
	utassert(wrapping_compare_less(0x0, 0x1) == true);
	utassert(wrapping_compare_less(0x1, 0x0) == false);
	utassert(wrapping_compare_less(0x1, 0x1) == false);

	send_udp_manager = new test_manager;
	receive_udp_manager = new test_manager;
	send_udp_manager->bind(receive_udp_manager);
	receive_udp_manager->bind(send_udp_manager);

#define _ if (!g_error)

	printf("\nTesting transfer\n");
	test_transfer(0);
	_ printf("\nTesting transfer with simulated packet loss\n");
	_ test_transfer(simulate_packetloss);
	_ printf("\nTesting transfer with simulated packet loss and reorder\n");
	_ test_transfer(simulate_packetloss | simulate_packetreorder);
	_ printf("\nTesting transfer with heavy simulated packet loss and reorder\n");
	_ test_transfer(simulate_packetloss | simulate_packetreorder | heavy_loss);
	_ printf("\nTesting transfer with simulated packet reorder\n");
	_ test_transfer(simulate_packetreorder);

	_ printf("\nTesting transfer using utp v1\n");
	_ test_transfer(use_utp_v1);
	_ printf("\nTesting transfer using utp v1 with simulated packet loss\n");
	_ test_transfer(use_utp_v1 | simulate_packetloss);
	_ printf("\nTesting transfer using utp v1 with simulated packet loss and reorder\n");
	_ test_transfer(use_utp_v1 | simulate_packetloss | simulate_packetreorder);
	_ printf("\nTesting transfer using utp v1 with heavy simulated packet loss and reorder\n");
	_ test_transfer(use_utp_v1 | simulate_packetloss | simulate_packetreorder | heavy_loss);
	_ printf("\nTesting transfer using utp v1 with simulated packet reorder\n");
	_ test_transfer(use_utp_v1 | simulate_packetreorder);

	return 0;
}

