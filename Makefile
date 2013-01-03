SRCS = utp.cpp utp_utils.cpp
OBJS = utp.o utp_utils.o
CXXFLAGS = -fno-exceptions -fno-rtti -Wall -g

all: libutp.a

libutp.a: .gitversion $(OBJS)
	-rm -f libutp.a
	ar q libutp.a $(OBJS)
	ranlib libutp.a

.cpp.o:
	g++ -c -DPOSIX -DGITVERSION="\"$$(cat .gitversion)\"" -I . -I utp_config_lib $(CXXFLAGS) $<

.gitversion: $(SRCS)
	@ver='tarball'; \
	if test -d $(CURDIR)/.git; then \
	  export LANG=C; \
	  branch=`git branch | grep '^\*' | cut -d ' ' -f 2`; \
	  version=`git log --no-color --first-parent -n1 --pretty=format:%h`; \
	  if [ "$$branch" = '(no' ]; then \
	    ver="$$version"; \
	  else \
	    ver="$$branch/$$version"; \
	  fi; \
	fi; \
	echo "$${ver} >$@"; \
	echo "$${ver}" >$@

.PHONY: clean

clean:
	-rm -f $(OBJS) libutp.a utp_gitversion.h
