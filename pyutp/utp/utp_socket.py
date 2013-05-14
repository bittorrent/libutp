import os
import ctypes
import socket
import platform
from utp.utp_h import *
from utp.sockaddr_types import *

basepath = os.path.join(os.path.dirname(__file__), "..")
if platform.system() == "Windows":
    utp = ctypes.cdll.LoadLibrary(os.path.join(basepath, "utp.dll"))
elif platform.system() == "Darwin":
    utp = ctypes.cdll.LoadLibrary(os.path.join(basepath, "libutp.dylib"))
else:
    utp = ctypes.cdll.LoadLibrary(os.path.join(basepath, "libutp.so"))

from utp.inet_ntop import inet_ntop, inet_pton

CONNECT = UTP_STATE_CONNECT
WRITABLE = UTP_STATE_WRITABLE
EOF = UTP_STATE_EOF
DESTROYING = UTP_STATE_DESTROYING

CheckTimeouts = utp.UTP_CheckTimeouts

# Set appropriate return types.
utp.UTP_Create.restype = ctypes.c_void_p

def to_sockaddr(ip, port):
    if ":" not in ip:
        sin = sockaddr_in()
        ctypes.memset(ctypes.byref(sin), 0, ctypes.sizeof(sin))
        sin.sin_family = socket.AF_INET
        sin.sin_addr.s_addr = inet_addr(ip)
        sin.sin_port = socket.htons(port)
        return sin
    else:
        sin6 = sockaddr_in6()
        ctypes.memset(ctypes.byref(sin6), 0, ctypes.sizeof(sin6))
        sin6.sin6_family = socket.AF_INET6
        d = inet_pton(socket.AF_INET6, ip)
        # it seems like there should be a better way to do this...
        ctypes.memmove(sin6.sin6_addr.Byte, d, ctypes.sizeof(sin6.sin6_addr.Byte))
        sin6.sin6_port = socket.htons(port)
        return sin6

def from_lpsockaddr(sa, salen):
    if sa.contents.ss_family == socket.AF_INET:
        assert salen >= ctypes.sizeof(sockaddr_in)
        sin = ctypes.cast(sa, psockaddr_in).contents
        ip = str(sin.sin_addr.s_addr)
        port = socket.ntohs(sin.sin_port)
    elif sa.contents.ss_family == socket.AF_INET6:
        assert salen >= ctypes.sizeof(sockaddr_in6)
        sin6 = ctypes.cast(sa, psockaddr_in6).contents
        ip = inet_ntop(socket.AF_INET6, sin6.sin6_addr.Byte)
        port = socket.ntohs(sin6.sin6_port)
    else:
        raise ValueError("unknown address family " + str(sa.contents.ss_family))
    return (ip, port)

def wrap_send_to(f):
    def unwrap_send_to(userdata, ptr, count, to, tolen):
        sa = ctypes.cast(to, LPSOCKADDR_STORAGE)
        f(ctypes.string_at(ptr, count), from_lpsockaddr(sa, tolen))
    return unwrap_send_to

def wrap_callback(f):
    def unwrap_callback(userdata, *a, **kw):
      return f(*a, **kw)
    return unwrap_callback


class Socket(object):

    def set_socket(self, utp_socket, send_to_proc):
        # Store this as a void pointer to prevent ctypes from assuming
        # it's a 32 bit integer. Causes problems on 64 bit Darwin
        # otherwise.
        self.utp_socket = ctypes.c_void_p(utp_socket)
        self.send_to_proc = send_to_proc

    def init_outgoing(self, send_to, addr):
        send_to_proc = SendToProc(wrap_send_to(send_to))
        sin = to_sockaddr(*addr)
        utp_socket = utp.UTP_Create(send_to_proc, ctypes.py_object(self),
                                    ctypes.byref(sin), ctypes.sizeof(sin))
        self.set_socket(utp_socket, send_to_proc)

    def set_callbacks(self, callbacks):
        self.callbacks = callbacks
        f = UTPFunctionTable(UTPOnReadProc(wrap_callback(self.on_read)),
                             UTPOnWriteProc(wrap_callback(self.on_write)),
                             UTPGetRBSize(wrap_callback(callbacks.get_rb_size)),
                             UTPOnStateChangeProc(wrap_callback(callbacks.on_state)),
                             UTPOnErrorProc(wrap_callback(callbacks.on_error)),
                             UTPOnOverheadProc(wrap_callback(callbacks.on_overhead)))
        self.functable = f
        utp.UTP_SetCallbacks(self.utp_socket,
                             ctypes.byref(f), ctypes.py_object(self))

    def on_read(self, bytes, count):
        self.callbacks.on_read(ctypes.string_at(bytes, count))

    def on_write(self, bytes, count):
        d = self.callbacks.on_write(count)
        dst = ctypes.cast(bytes, ctypes.c_void_p).value
        ctypes.memmove(dst, d, count)

    def connect(self):
        if not hasattr(self, "callbacks"):
            raise ValueError("Callbacks must be set before connecting")
        utp.UTP_Connect(self.utp_socket)

    def getpeername(self):
        sa = SOCKADDR_STORAGE()
        salen = socklen_t(ctypes.sizeof(sa))
        utp.UTP_GetPeerName(self.utp_socket, ctypes.byref(sa), ctypes.byref(salen))
        return from_lpsockaddr(ctypes.pointer(sa), salen.value)

    def rbdrained(self):
        utp.UTP_RBDrained(self.utp_socket)

    def write(self, to_write):
        return utp.UTP_Write(self.utp_socket, to_write)

    def close(self):
        utp.UTP_Close(self.utp_socket)


# This is just an interface example. You do not have to subclass from it,
# but you do need to pass an object which has this interface.
class Callbacks(object):

    def on_read(self, data):
        pass

    def on_write(self, count):
        pass

    def get_rb_size(self):
        return 0

    def on_state(self, state):
        pass

    def on_error(self, errcode):
        pass

    def on_overhead(self, send, count, type):
        pass


def wrap_incoming(f, send_to_proc):
    def unwrap_incoming(userdata, utp_socket):
        us = Socket()
        us.set_socket(utp_socket, send_to_proc)
        f(us)
    return unwrap_incoming


def IsIncomingUTP(incoming_connection, send_to, d, addr):
    send_to_proc = SendToProc(wrap_send_to(send_to))
    if incoming_connection:
        incoming_proc = UTPGotIncomingConnection(wrap_incoming(incoming_connection, send_to_proc))
    else:
        incoming_proc = None
    sa = to_sockaddr(*addr)
    return utp.UTP_IsIncomingUTP(incoming_proc, send_to_proc, 1, d, len(d),
                                 ctypes.byref(sa), ctypes.sizeof(sa))
