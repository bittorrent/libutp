all: libutp.so

lrt:=$(shell echo "int main() {}"|gcc -x c - -lrt 2>&1)

ifeq ($(lrt),)
  libs:=-lrt
else
  libs:=
endif

utp:=utp.cpp utp_utils.cpp
cflags:=-fno-exceptions -fno-rtti

libutp.so:
	g++ -Wall -ansi -fPIC --shared -o libutp.so -g $(utp) -DPOSIX -I . -I utp_config_lib $(libs) $(cflags)
