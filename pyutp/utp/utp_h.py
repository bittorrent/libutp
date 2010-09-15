import ctypes
from utp.sockaddr_types import *

# hork
if not hasattr(ctypes, "c_bool"):
    ctypes.c_bool = ctypes.c_byte

# Lots of stuff which has to be kept in sync with utp.h...
# I wish ctypes had a C header parser.

UTP_STATE_CONNECT = 1
UTP_STATE_WRITABLE = 2
UTP_STATE_EOF = 3
UTP_STATE_DESTROYING = 4


# typedef void UTPOnReadProc(void *userdata, const byte *bytes, size_t count);
UTPOnReadProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_byte), ctypes.c_size_t)

# typedef void UTPOnWriteProc(void *userdata, byte *bytes, size_t count);
UTPOnWriteProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_byte), ctypes.c_size_t)

# typedef size_t UTPGetRBSize(void *userdata);
UTPGetRBSize = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)

# typedef void UTPOnStateChangeProc(void *userdata, int state);
UTPOnStateChangeProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)

# typedef void UTPOnErrorProc(void *userdata, int errcode);
UTPOnErrorProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)

# typedef void UTPOnOverheadProc(void *userdata, bool send, size_t count, int type);
UTPOnOverheadProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_bool, ctypes.c_size_t, ctypes.c_int)


class UTPFunctionTable(ctypes.Structure):
    _fields_ = (
        ("on_read", UTPOnReadProc),
        ("on_write", UTPOnWriteProc),
        ("get_rb_size", UTPGetRBSize),
        ("on_state", UTPOnStateChangeProc),
        ("on_error", UTPOnErrorProc),
        ("on_overhead", UTPOnOverheadProc),
    )


# typedef void UTPGotIncomingConnection(UTPSocket* s);
UTPGotIncomingConnection = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

# typedef void SendToProc(void *userdata, const byte *p, size_t len, const struct sockaddr *to, socklen_t tolen);
SendToProc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_byte), ctypes.c_size_t, LPSOCKADDR, socklen_t)
