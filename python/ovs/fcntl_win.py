import errno
import win32con
import win32file
import pywintypes
import msvcrt

LOCK_EX = win32con.LOCKFILE_EXCLUSIVE_LOCK
LOCK_SH = 0 # the default
LOCK_NB = win32con.LOCKFILE_FAIL_IMMEDIATELY
LOCK_UN = 0x80000000  # unlock - non-standard

def fcntl(fd, op, arg=0):
    # not implemented yet on Windows
    return 0

def ioctl(fd, op, arg=0, mutable_flag=True):
    # not implemented yet on Windows
    if mutable_flag:
        return 0
    else:
        return ""

def lockf(fd, flags, length=0xFFFF0000, start=0, whence=0):
    file_name = fd.name
    overlapped = pywintypes.OVERLAPPED()
    hfile = msvcrt.get_osfhandle(fd.fileno())
    if LOCK_UN & flags:
        ret = win32file.UnlockFileEx(hfile, 0, start, length, overlapped)
    else:
        try:
            ret = win32file.LockFileEx(hfile, flags, start, length, overlapped)
        except:
            raise IOError(errno.EAGAIN, "", "")

def flock(fd, flags):
    lockf(fd, flags, 0xFFFF0000, 0, 0)
