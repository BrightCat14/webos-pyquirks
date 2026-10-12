# Copyright (c) 2026 by Georgii Kulikov <geokyll.14@gmail.com>
# SPDX-License-Identifier: MIT

import ctypes
import os

try:
    libc = ctypes.CDLL(None, use_errno=True)
except (OSError, TypeError):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

LOCK_SH = 1
LOCK_EX = 2
LOCK_NB = 4
LOCK_UN = 8

F_DUPFD = 0
F_GETFD = 1
F_SETFD = 2
F_GETFL = 3
F_SETFL = 4
F_GETLK = 5
F_SETLK = 6
F_SETLKW = 7
F_SETOWN = 8
F_GETOWN = 9

FD_CLOEXEC = 1

F_RDLCK = 0
F_WRLCK = 1
F_UNLCK = 2

# Kept for backward compatibility; new code uses _Flock below.
FLOCK_STRUCT_FORMAT = "hhqqi"


class _Flock(ctypes.Structure):
    # Native struct flock layout. c_long matches off_t on both
    # 32-bit ARM (4 bytes) and 64-bit (8 bytes); ctypes adds the
    # platform padding automatically. The old struct.pack("hhqqi")
    # hard-coded 64-bit sizes and silently corrupted non-zero
    # l_start/l_len on 32-bit ARM (it only worked for zeros).
    _fields_ = [("l_type", ctypes.c_short),
                ("l_whence", ctypes.c_short),
                ("l_start", ctypes.c_long),
                ("l_len", ctypes.c_long),
                ("l_pid", ctypes.c_int)]


def _make_flock(l_type, l_whence=0, l_start=0, l_len=0, l_pid=0):
    return _Flock(l_type, l_whence, l_start, l_len, l_pid)

# fcntl(fd, cmd, arg)
libc.fcntl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
libc.fcntl.restype = ctypes.c_int

# ioctl(fd, request, arg)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
libc.ioctl.restype = ctypes.c_int

# flock(fd, operation)
if hasattr(libc, "flock"):
    libc.flock.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.flock.restype = ctypes.c_int


def _get_fd(fd):
    return fd.fileno() if hasattr(fd, "fileno") else int(fd)


def _check_error(result):
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return result

def fcntl(fd, cmd, arg=0):
    f_id = _get_fd(fd)

    if isinstance(arg, int):
        res = libc.fcntl(f_id, cmd, ctypes.c_void_p(arg))
        return _check_error(res)

    if isinstance(arg, str):
        arg = arg.encode("utf-8")

    if isinstance(arg, (bytes, bytearray)):
        buf = ctypes.create_string_buffer(bytes(arg))
        res = libc.fcntl(f_id, cmd, buf)
        _check_error(res)
        return buf.raw[:len(arg)]

    raise TypeError("arg must be an int, bytes, or string")


def ioctl(fd, request, arg=0, mutate_flag=True):
    f_id = _get_fd(fd)

    if isinstance(arg, int):
        res = libc.ioctl(f_id, request, ctypes.c_void_p(arg))
        return _check_error(res)

    if isinstance(arg, str):
        arg = arg.encode("utf-8")

    if isinstance(arg, bytearray):
        if len(arg) == 0:
            res = libc.ioctl(f_id, request, ctypes.c_void_p(0))
        else:
            buf = (ctypes.c_char * len(arg)).from_buffer(arg)
            res = libc.ioctl(f_id, request, buf)
        _check_error(res)
        return res

    if isinstance(arg, bytes):
        buf = ctypes.create_string_buffer(arg)
        res = libc.ioctl(f_id, request, buf)
        _check_error(res)
        return buf.raw[:len(arg)]

    raise TypeError("arg must be an int, bytes, bytearray, or string")


def flock(fd, operation):
    f_id = _get_fd(fd)
    if hasattr(libc, "flock"):
        res = libc.flock(f_id, operation)
        _check_error(res)
    else:
        l_type = F_UNLCK
        if operation == LOCK_UN:
            l_type = F_UNLCK
        elif operation & LOCK_SH:
            l_type = F_RDLCK
        elif operation & LOCK_EX:
            l_type = F_WRLCK

        cmd = F_SETLK if (operation & LOCK_NB) else F_SETLKW
        fl = _make_flock(l_type)
        res = libc.fcntl(f_id, cmd, ctypes.byref(fl))
        _check_error(res)


def lockf(fd, cmd, lenobj=0, startobj=0, whence=0):
    f_id = _get_fd(fd)
    l_type = F_UNLCK
    if cmd == LOCK_UN:
        l_type = F_UNLCK
    elif cmd & LOCK_SH:
        l_type = F_RDLCK
    elif cmd & LOCK_EX:
        l_type = F_WRLCK
    else:
        raise ValueError("unrecognized lockf argument")

    fcntl_cmd = F_SETLK if (cmd & LOCK_NB) else F_SETLKW

    fl = _make_flock(l_type, whence, startobj, lenobj, 0)
    res = libc.fcntl(f_id, fcntl_cmd, ctypes.byref(fl))
    _check_error(res)
