import ctypes
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

ADDRESS_FAMILY = ctypes.c_ushort

_SS_MAXSIZE = 128
_SS_ALIGNSIZE = ctypes.sizeof(ctypes.c_int64)

_SS_PAD1SIZE = (_SS_ALIGNSIZE - ctypes.sizeof(ctypes.c_ushort))
_SS_PAD2SIZE = (_SS_MAXSIZE - (ctypes.sizeof(ctypes.c_ushort) + _SS_PAD1SIZE + _SS_ALIGNSIZE))

class SOCKADDR_STORAGE(ctypes.Structure):
    _fields_ = (
        ('ss_family', ADDRESS_FAMILY),
        ('__ss_pad1', ctypes.c_char * _SS_PAD1SIZE),
        ('__ss_align', ctypes.c_int64),
        ('__ss_pad2', ctypes.c_char * _SS_PAD2SIZE),
        )

LPSOCKADDR_STORAGE = ctypes.POINTER(SOCKADDR_STORAGE)

class IPAddr(ctypes.Structure):
    _fields_ = (
        ("S_addr", ctypes.c_ulong),
        )

    def __str__(self):
        return socket.inet_ntoa(struct.pack("L", self.S_addr))

class in_addr(ctypes.Structure):
    _fields_ = (
        ("s_addr", IPAddr),
        )

class in6_addr(ctypes.Structure):
    _fields_ = (
        ("Byte", ctypes.c_ubyte * 16),
        )

class sockaddr_in(ctypes.Structure):
    _fields_ = (
        ("sin_family", ADDRESS_FAMILY),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", in_addr),
        ("szDescription", ctypes.c_char * 8),
        )

psockaddr_in = ctypes.POINTER(sockaddr_in)

class sockaddr_in6(ctypes.Structure):
    _fields_ = (
        ("sin6_family", ADDRESS_FAMILY),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_ulong),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", ctypes.c_ulong),
        )

psockaddr_in6 = ctypes.POINTER(sockaddr_in6)

socklen_t = ctypes.c_int

def inet_addr(ip):
    return IPAddr(struct.unpack("L", socket.inet_aton(ip))[0])
