import ctypes
import platform
import socket
import struct


class SOCKADDR(ctypes.Structure):
    _fields_ = (
        ('family', ctypes.c_ushort),
        ('data', ctypes.c_byte*14),
        )

LPSOCKADDR = ctypes.POINTER(SOCKADDR)

class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = (
        ('address', LPSOCKADDR),
        ('length', ctypes.c_int),
        )

if platform.system() == "Darwin":
    # uint8 on OSX
    ADDRESS_FAMILY = ctypes.c_ubyte
else:
    ADDRESS_FAMILY = ctypes.c_ushort

_SS_MAXSIZE = 128
_SS_ALIGNSIZE = ctypes.sizeof(ctypes.c_int64)

_SS_PAD1SIZE = (_SS_ALIGNSIZE - ctypes.sizeof(ADDRESS_FAMILY))
_SS_PAD2SIZE = (_SS_MAXSIZE - (ctypes.sizeof(ADDRESS_FAMILY) + _SS_PAD1SIZE +
                               _SS_ALIGNSIZE))

class IPAddr(ctypes.Structure):
    _fields_ = (
        ("S_addr", ctypes.c_uint),
        )

    def __str__(self):
        return socket.inet_ntoa(struct.pack("=L", self.S_addr))

class in_addr(ctypes.Structure):
    _fields_ = (
        ("s_addr", IPAddr),
        )

class in6_addr(ctypes.Structure):
    _fields_ = (
        ("Byte", ctypes.c_ubyte * 16),
        )

if platform.system() == "Darwin":
    # All these structures have a length byte on OSX, using the space
    # left by making sa_address_t a uint8. This causes the address
    # family to look like it has the wrong byte order if you leave out
    # the length byte!
    class SOCKADDR_STORAGE(ctypes.Structure):
        _fields_ = (
            ('ss_len', ctypes.c_ubyte),
            ('ss_family', ADDRESS_FAMILY),
            ('__ss_pad1', ctypes.c_char * _SS_PAD1SIZE),
            ('__ss_align', ctypes.c_int64),
            ('__ss_pad2', ctypes.c_char * _SS_PAD2SIZE),
            )

    class sockaddr_in(ctypes.Structure):
        _fields_ = (
            ("sin_len", ctypes.c_ubyte),
            ("sin_family", ADDRESS_FAMILY),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", in_addr),
            ("szDescription", ctypes.c_char * 8),
            )

    class sockaddr_in6(ctypes.Structure):
        _fields_ = (
            ("sin6_len", ctypes.c_ubyte),
            ("sin6_family", ADDRESS_FAMILY),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", in6_addr),
            ("sin6_scope_id", ctypes.c_ulong),
            )
else:
    class SOCKADDR_STORAGE(ctypes.Structure):
        _fields_ = (
            ('ss_family', ADDRESS_FAMILY),
            ('__ss_pad1', ctypes.c_char * _SS_PAD1SIZE),
            ('__ss_align', ctypes.c_int64),
            ('__ss_pad2', ctypes.c_char * _SS_PAD2SIZE),
            )

    class sockaddr_in(ctypes.Structure):
        _fields_ = (
            ("sin_family", ADDRESS_FAMILY),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", in_addr),
            ("szDescription", ctypes.c_char * 8),
            )

    class sockaddr_in6(ctypes.Structure):
        _fields_ = (
            ("sin6_family", ADDRESS_FAMILY),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", in6_addr),
            ("sin6_scope_id", ctypes.c_ulong),
            )

LPSOCKADDR_STORAGE = ctypes.POINTER(SOCKADDR_STORAGE)

psockaddr_in = ctypes.POINTER(sockaddr_in)

psockaddr_in6 = ctypes.POINTER(sockaddr_in6)

socklen_t = ctypes.c_int

def inet_addr(ip):
    return IPAddr(struct.unpack("=L", socket.inet_aton(ip))[0])
