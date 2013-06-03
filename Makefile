SRCS = utp.cpp utp_utils.cpp
OBJS = utp.o utp_utils.o
CXXFLAGS = -fno-exceptions -fno-rtti -fPIC -Wall -g

all: libutp.a libutp.so

libutp.a: $(OBJS)
	-rm -f libutp.a
	ar q libutp.a $(OBJS)
	ranlib libutp.a

libutp.so: libutp.a
	-rm -f libutp.so{.1.0,.1,}
	gcc -shared -o libutp.so.1.0 $(OBJS) -lrt
	ln -s libutp.so.1.0 libutp.so.1
	ln -s libutp.so.1.0 libutp.so

.cpp.o:
	g++ -c -DPOSIX -I . -I utp_config_lib $(CXXFLAGS) $<

.PHONY: clean

clean:
	-rm -f $(OBJS) libutp.a libutp.so{.1.0,.1,}
