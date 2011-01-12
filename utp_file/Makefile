all: utp_send utp_recv

lrt:=$(shell echo "int main() {}"|gcc -x c - -lrt 2>&1)

ifeq ($(lrt),)
  libs:=-lrt
else
  libs:=
endif

utp:=../utp.cpp ../utp_utils.cpp
cflags:=-fno-exceptions -fno-rtti

utp_send: utp_send.cpp
	g++ -Wall -ansi -o utp_send -g utp_send.cpp $(utp) -DPOSIX -I . -I .. $(libs) $(cflags)

utp_recv: utp_recv.cpp
	g++ -Wall -ansi -o utp_recv -g utp_recv.cpp $(utp) -DPOSIX -I . -I .. $(libs) $(cflags)
