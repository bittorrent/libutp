all: tests

lrt:=$(shell echo "int main() {}"|gcc -x c - -lrt 2>&1)

ifeq ($(lrt),)
  libs:=-lrt
else
  libs:=
endif

utp:=../libutp.a
cflags:=-fno-exceptions -fno-rtti

tests: test_transfer.cpp
	g++ -Wall -o tests -g test_transfer.cpp $(utp) -DPOSIX -I . -I .. -I ../utp_config_lib $(libs) $(cflags)
