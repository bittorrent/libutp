# -*- coding: utf-8 -*-
import os
from setuptools import setup, Library

from utp import VERSION

sources = [os.path.join("..", "utp.cpp"),
           os.path.join("..", "utp_utils.cpp")]
include_dirs = ["..", os.path.join("..", "utp_config_lib")]
define_macros = []
libraries = []
extra_link_args = []
if os.name == "nt":
    define_macros.append(("WIN32", 1))
    libraries.append("ws2_32")
    sources.append(os.path.join("..", "win32_inet_ntop.cpp"))
    extra_link_args.append('/DEF:"../utp.def"')
else:
    define_macros.append(("POSIX", 1))
    r = os.system('echo "int main() {}"|gcc -x c - -lrt 2>/dev/null')
    if r == 0:
        libraries.append("rt")

# http://bugs.python.org/issue9023
sources = [os.path.abspath(x) for x in sources]

ext = Library(name="utp",
              sources=sources,
              include_dirs=include_dirs,
              libraries=libraries,
              define_macros=define_macros,
              extra_link_args=extra_link_args
              )

setup(name="utp",
      version=VERSION,
      description="The uTorrent Transport Protocol library",
      author="Greg Hazel",
      author_email="greg@bittorrent.com",
      maintainer="Greg Hazel",
      maintainer_email="greg@bittorrent.com",
      url="http://github.com/bittorrent/libutp",
      packages=['utp',
                'utp.tests'],
      ext_modules=[ext],
      zip_safe=False,
      license='MIT'
      )
