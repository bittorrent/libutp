SRCS = utp.cpp utp_utils.cpp
OBJS = utp.o utp_utils.o
CXXFLAGS = -fno-exceptions -fno-rtti -Wall -g

all: libutp.a

libutp.a: $(OBJS)
	-rm -f libutp.a
	ar q libutp.a $(OBJS)
	ranlib libutp.a

.cpp.o:
	g++ -c -DPOSIX -I . -I utp_config_lib $(CXXFLAGS) $<

.PHONY: clean

clean:
	-rm -f $(OBJS) libutp.a
