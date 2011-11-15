rm       = /bin/rm
bin_send = utp_send
bin_recv = utp_recv
binaries = $(bin_send) $(bin_recv)

all: $(binaries)

lrt:=$(shell echo "int main() {}"|gcc -x c - -lrt 2>&1)

ifeq ($(lrt),)
  libs:=-lrt
else
  libs:=
endif

utp:=../utp.cpp ../utp_utils.cpp
cflags:=-fno-exceptions -fno-rtti

$(bin_send): utp_send.cpp
	g++ -Wall -o utp_send -g utp_send.cpp $(utp) -DPOSIX -I . -I .. $(libs) $(cflags)

$(bin_recv): utp_recv.cpp
	g++ -Wall -o utp_recv -g utp_recv.cpp $(utp) -DPOSIX -I . -I .. $(libs) $(cflags)

clean:
	$(RM) -f $(binaries) a.out
