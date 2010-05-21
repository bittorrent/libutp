all: utp_send utp_recv

utp_send: utp_send.cpp
	g++ -Wall -ansi -o utp_send -g utp_send.cpp ../utp.cpp ../utp_utils.cpp -DPOSIX -I . -I .. -lrt -fno-exceptions -fno-rtti

utp_recv: utp_recv.cpp
	g++ -Wall -ansi -o utp_recv -g utp_recv.cpp ../utp.cpp ../utp_utils.cpp -DPOSIX -I . -I .. -lrt -fno-exceptions -fno-rtti
