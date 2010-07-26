# This module can go away when Python supports IPv6 (meaning inet_ntop and inet_pton on all platforms)
# http://bugs.python.org/issue7171

import socket
import ctypes
from utp.utp_socket import utp

# XXX: the exception types vary from socket.inet_ntop
def inet_ntop(address_family, packed_ip):
    if address_family == socket.AF_INET:
        # The totals are derived from the following data:
        #  15: IPv4 address 
        #   1: Terminating null byte
        length = 16
        packed_length = 4
    elif address_family == socket.AF_INET6:
        # The totals are derived from the following data:
        #  45: IPv6 address including embedded IPv4 address
        #  11: Scope Id
        #   1: Terminating null byte
        length = 57
        packed_length = 16
    else:
        raise ValueError("unknown address family " + str(address_family))
    if len(packed_ip) != packed_length:
        raise ValueError("invalid length of packed IP address string")
    dest = ctypes.create_string_buffer(length)
    r = utp.inet_ntop(address_family, packed_ip, dest, length)
    if r is None:
        raise ValueError
    return dest.value

# XXX: the exception types vary from socket.inet_pton
def inet_pton(address_family, ip_string):
    if address_family == socket.AF_INET:
        length = 4
    elif address_family == socket.AF_INET6:
        length = 16
    else:
        raise ValueError("unknown address family " + str(address_family))
    dest = ctypes.create_string_buffer(length)
    r = utp.inet_pton(address_family, ip_string.encode(), dest)
    if r != 1:
        raise ValueError("illegal IP address string passed to inet_pton")
    return dest.raw

inet_ntop = getattr(socket, "inet_ntop", inet_ntop)
inet_pton = getattr(socket, "inet_pton", inet_pton)
