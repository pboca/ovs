# Copyright (c) 2010, 2011, 2012 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import os
import socket
import sys
import six

import ovs.poller
import ovs.socket_util
import ovs.vlog

import pywintypes
import winerror
import win32pipe
import win32con
import win32security
import win32file
import win32event

vlog = ovs.vlog.Vlog("stream")


def stream_or_pstream_needs_probes(name):
    """ 1 if the stream or pstream specified by 'name' needs periodic probes to
    verify connectivity.  For [p]streams which need probes, it can take a long
    time to notice the connection was dropped.  Returns 0 if probes aren't
    needed, and -1 if 'name' is invalid"""

    if PassiveStream.is_valid_name(name) or Stream.is_valid_name(name):
        # Only unix and punix are supported currently.
        return 0
    else:
        return -1


class Stream(object):
    """Bidirectional byte stream.  Currently only Unix domain sockets
    are implemented."""

    # States.
    __S_CONNECTING = 0
    __S_CONNECTED = 1
    __S_DISCONNECTED = 2

    # Kinds of events that one might wait for.
    W_CONNECT = 0               # Connect complete (success or failure).
    W_RECV = 1                  # Data received.
    W_SEND = 2                  # Send buffer room available.

    _SOCKET_METHODS = {}

    write = None                # overlapped for write operation
    read = None                 # overlapped for read operation
    write_pending = False
    read_pending = False
    retry_connect = False

    @staticmethod
    def register_method(method, cls):
        Stream._SOCKET_METHODS[method + ":"] = cls

    @staticmethod
    def _find_method(name):
        for method, cls in six.iteritems(Stream._SOCKET_METHODS):
            if name.startswith(method):
                return cls
        return None

    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a stream name in the form "TYPE:ARGS" and
        TYPE is a supported stream type (currently only "unix:" and "tcp:"),
        otherwise False."""
        return bool(Stream._find_method(name))

    def __init__(self, sock, name, status):
        if isinstance(sock, socket.socket):
            self.socket = sock
        else:
            self.pipe = sock
            self.read = pywintypes.OVERLAPPED()
            self.read.hEvent = win32event.CreateEvent(None, True, True, None)
            self.write = pywintypes.OVERLAPPED()
            self.write.hEvent = win32event.CreateEvent(None, True, True, None)

        self.name = name
        if status == errno.EAGAIN:
            self.state = Stream.__S_CONNECTING
        elif status == 0:
            self.state = Stream.__S_CONNECTED
        else:
            self.state = Stream.__S_DISCONNECTED

        self.error = 0

    # Default value of dscp bits for connection between controller and manager.
    # Value of IPTOS_PREC_INTERNETCONTROL = 0xc0 which is defined
    # in <netinet/ip.h> is used.
    IPTOS_PREC_INTERNETCONTROL = 0xc0
    DSCP_DEFAULT = IPTOS_PREC_INTERNETCONTROL >> 2

    @staticmethod
    def open(name, dscp=DSCP_DEFAULT):
        """Attempts to connect a stream to a remote peer.  'name' is a
        connection name in the form "TYPE:ARGS", where TYPE is an active stream
        class's name and ARGS are stream class-specific.  Currently the only
        supported TYPEs are "unix" and "tcp".

        Returns (error, stream): on success 'error' is 0 and 'stream' is the
        new Stream, on failure 'error' is a positive errno value and 'stream'
        is None.

        Never returns errno.EAGAIN or errno.EINPROGRESS.  Instead, returns 0
        and a new Stream.  The connect() method can be used to check for
        successful connection completion."""
        cls = Stream._find_method(name)
        if not cls:
            return errno.EAFNOSUPPORT, None

        suffix = name.split(":", 1)[1]
        if name.startswith("unix:"):
            suffix = ovs.util.abs_file_name(ovs.dirs.RUNDIR, suffix)
            suffix = suffix.replace('/', '')
            suffix = suffix.replace('\\', '')
            suffix = "\\\\.\\pipe\\" + suffix

            saAttr = win32security.SECURITY_ATTRIBUTES()
            saAttr.bInheritHandle = 1
            try:
                npipe = win32file.CreateFile(
                            suffix,
                            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                            0, None,
                            win32file.OPEN_EXISTING,
                            win32file.FILE_ATTRIBUTE_NORMAL |
                            win32file.FILE_FLAG_OVERLAPPED |
                            win32file.FILE_FLAG_NO_BUFFERING,
                            None)
            except pywintypes.error as e:
                return e.winerror, None

            return 0, Stream(npipe, suffix, 0)
        else:
            error, sock = cls._open(suffix, dscp)
            if error:
                return error, None
            else:
                status = ovs.socket_util.check_connection_completion(sock)
                return 0, Stream(sock, name, status)

    @staticmethod
    def _open(suffix, dscp):
        raise NotImplementedError("This method must be overrided by subclass")

    @staticmethod
    def open_block(error_stream):
        """Blocks until a Stream completes its connection attempt, either
        succeeding or failing.  (error, stream) should be the tuple returned by
        Stream.open().  Returns a tuple of the same form.

        Typical usage:
        error, stream = Stream.open_block(Stream.open("unix:/tmp/socket"))"""

        # Py3 doesn't support tuple parameter unpacking - PEP 3113
        error, stream = error_stream
        if not error:
            while True:
                error = stream.connect()
                if sys.platform == "win32" and error == errno.WSAEWOULDBLOCK:
                    error = errno.EAGAIN
                if error != errno.EAGAIN:
                    break
                stream.run()
                poller = ovs.poller.Poller()
                stream.run_wait(poller)
                stream.connect_wait(poller)
                poller.block()
            assert error != errno.EINPROGRESS

        if error and stream:
            stream.close()
            stream = None
        return error, stream

    def close(self):
        if hasattr(self, "socket"):
            self.socket.close()

    def __scs_connecting(self):
        if hasattr(self, "socket"):
            retval = ovs.socket_util.check_connection_completion(self.socket)
        elif self.retry_connect:
            saAttr = win32security.SECURITY_ATTRIBUTES()
            saAttr.bInheritHandle = 1

            try:
                self.pipe = win32file.CreateFile(
                            self.name,
                            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                            0, None,
                            win32file.OPEN_EXISTING,
                            win32file.FILE_ATTRIBUTE_NORMAL |
                            win32file.FILE_FLAG_OVERLAPPED |
                            win32file.FILE_FLAG_NO_BUFFERING,
                            None)
            except pywintypes.error:
                retval = errno.EAGAIN
                self.retry_connect = True

        assert retval != errno.EINPROGRESS
        if retval == 0:
            self.state = Stream.__S_CONNECTED
        elif retval != errno.EAGAIN:
            self.state = Stream.__S_DISCONNECTED
            self.error = retval

    def connect(self):
        """Tries to complete the connection on this stream.  If the connection
        is complete, returns 0 if the connection was successful or a positive
        errno value if it failed.  If the connection is still in progress,
        returns errno.EAGAIN."""

        if self.state == Stream.__S_CONNECTING:
            self.__scs_connecting()

        if self.state == Stream.__S_CONNECTING:
            return errno.EAGAIN
        elif self.state == Stream.__S_CONNECTED:
            return 0
        else:
            assert self.state == Stream.__S_DISCONNECTED
            return self.error

    def recv(self, n):
        """Tries to receive up to 'n' bytes from this stream.  Returns a
        (error, string) tuple:

            - If successful, 'error' is zero and 'string' contains between 1
              and 'n' bytes of data.

            - On error, 'error' is a positive errno value.

            - If the connection has been closed in the normal fashion or if 'n'
              is 0, the tuple is (0, "").

        The recv function will not block waiting for data to arrive.  If no
        data have been received, it returns (errno.EAGAIN, "") immediately."""

        retval = self.connect()
        if retval != 0:
            return (retval, "")
        elif n == 0:
            return (0, "")

        if hasattr(self, "socket"):
            try:
                return (0, self.socket.recv(n))
            except socket.error as e:
                return (ovs.socket_util.get_exception_errno(e), "")
        else:
            if self.read_pending:
                try:
                    nBytesRead = win32file.GetOverlappedResult(self.pipe,
                                                        self.read,
                                                        False)
                    self.read_pending = False
                    recvBuffer = self.read_buffer[:nBytesRead]
                    if six.PY3:
                        return (0, bytes(recvBuffer).decode("utf-8"))
                    else:
                        return (0, str(recvBuffer))
                except pywintypes.error as e:
                    return (errno.EAGAIN, "")

            try:
                (errCode, self.read_buffer) = win32file.ReadFile(self.pipe,
                                                             n,
                                                             self.read)

                if errCode == winerror.ERROR_IO_PENDING:
                    self.read_pending = True
                    return (errno.EAGAIN, "")

                nBytesRead = win32file.GetOverlappedResult(self.pipe,
                                                        self.read,
                                                        False)
                win32event.SetEvent(self.read.hEvent)
                recvBuffer = self.read_buffer[:nBytesRead]
                if six.PY3:
                    return (0, bytes(recvBuffer).decode("utf-8"))
                else:
                    return (0, str(recvBuffer))
            except pywintypes.error as e:
                return (0, None)

    def send(self, buf):
        """Tries to send 'buf' on this stream.

        If successful, returns the number of bytes sent, between 1 and
        len(buf).  0 is only a valid return value if len(buf) is 0.

        On error, returns a negative errno value.

        Will not block.  If no bytes can be immediately accepted for
        transmission, returns -errno.EAGAIN immediately."""

        retval = self.connect()
        if retval != 0:
            return -retval
        elif len(buf) == 0:
            return 0

        if hasattr(self, "socket"):
            try:
                # Python 3 has separate types for strings and bytes.  We must
                # have bytes here.
                if six.PY3 and not isinstance(buf, six.binary_type):
                    buf = six.binary_type(buf, 'utf-8')
                return self.socket.send(buf)
            except socket.error as e:
                return -ovs.socket_util.get_exception_errno(e)
        else:
            if self.write_pending:
                try:
                    nBytesWritten = win32file.GetOverlappedResult(self.pipe,
                                                            self.write,
                                                            False)
                    self.write_pending = False
                    return nBytesWritten
                except pywintypes.error as e:
                    return -errno.EAGAIN

            try:
                # Python 3 has separate types for strings and bytes.  We must
                # have bytes here.
                if not isinstance(buf, six.binary_type):
                    if six.PY3:
                        buf = six.binary_type(buf, 'utf-8')
                    else:
                        buf = six.binary_type(buf)

                self.write_pending = False
                (errCode, nBytesWritten) = win32file.WriteFile(self.pipe,
                                                            buf,
                                                            self.write)
                if errCode == winerror.ERROR_IO_PENDING:
                    self.write_pending = True
                    return -errno.EAGAIN

                nBytesWritten = win32file.GetOverlappedResult(self.pipe,
                                                            self.write,
                                                            False)
                win32event.SetEvent(self.write.hEvent)

                return nBytesWritten
            except pywintypes.error as e:
                return -e.winerror

    def run(self):
        pass

    def run_wait(self, poller):
        pass

    def wait(self, poller, wait):
        if hasattr(self, "socket"):
            import win32file
            import win32event

            assert wait in (Stream.W_CONNECT, Stream.W_RECV, Stream.W_SEND)

            if self.state == Stream.__S_DISCONNECTED:
                poller.immediate_wake()
                return

            if self.state == Stream.__S_CONNECTING:
                wait = Stream.W_CONNECT

            event = win32event.CreateEvent(None, True, True, None)

            if wait == Stream.W_RECV:
                win32file.WSAEventSelect(self.socket, event,
                                        win32file.FD_READ |
                                        win32file.FD_ACCEPT |
                                        win32file.FD_CLOSE)
                poller.fd_wait(event, ovs.poller.POLLIN)
            else:
                win32file.WSAEventSelect(self.socket, event,
                                        win32file.FD_WRITE |
                                        win32file.FD_CONNECT |
                                        win32file.FD_CLOSE)
                poller.fd_wait(event, ovs.poller.POLLOUT)
        else:
            if wait == Stream.W_RECV:
                if self.read:
                    poller.fd_wait(self.read.hEvent, ovs.poller.POLLIN)
            else:
                if self.write:
                    poller.fd_wait(self.write.hEvent, ovs.poller.POLLOUT)

    def connect_wait(self, poller):
        self.wait(poller, Stream.W_CONNECT)

    def recv_wait(self, poller):
        self.wait(poller, Stream.W_RECV)

    def send_wait(self, poller):
        poller.fd_wait(self.connect.hEvent, ovs.poller.POLLIN)
        self.wait(poller, Stream.W_SEND)

    def __del__(self):
        # Don't delete the file: we might have forked.
        if hasattr(self, "socket"):
            self.socket.close()


class PassiveStream(object):
    connect = None                  # overlapped for read operation
    connect_pending = False

    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a passive stream name in the form
        "TYPE:ARGS" and TYPE is a supported passive stream type (currently
        "punix:" or "ptcp"), otherwise False."""
        return name.startswith("punix:") | name.startswith("ptcp:")

    def __init__(self, sock, name, bind_path):
        self.name = name
        if isinstance(sock, socket.socket):
            self.socket = sock
        else:
            self.pipe = sock
        self.bind_path = bind_path

    @staticmethod
    def open(name):
        """Attempts to start listening for remote stream connections.  'name'
        is a connection name in the form "TYPE:ARGS", where TYPE is an passive
        stream class's name and ARGS are stream class-specific. Currently the
        supported values for TYPE are "punix" and "ptcp".

        Returns (error, pstream): on success 'error' is 0 and 'pstream' is the
        new PassiveStream, on failure 'error' is a positive errno value and
        'pstream' is None."""
        # raise OSError
        suffix = name.split(":", 1)[1]
        if name.startswith("punix:"):
            suffix = ovs.util.abs_file_name(ovs.dirs.RUNDIR, suffix)
            try:
                open(suffix, 'w').close()
            except:
                return errno.EAFNOSUPPORT, None

            pipename = suffix.replace('/', '')
            pipename = pipename.replace('\\', '')
            pipename = "\\\\.\\pipe\\" + pipename

            saAttr = win32security.SECURITY_ATTRIBUTES()
            saAttr.bInheritHandle = 1

            npipe = win32pipe.CreateNamedPipe(
                        pipename,
                        win32con.PIPE_ACCESS_DUPLEX |
                        win32con.FILE_FLAG_OVERLAPPED,
                        win32con.PIPE_TYPE_MESSAGE |
                        win32con.PIPE_READMODE_BYTE |
                        win32con.PIPE_WAIT,
                        64, 65000, 65000, 0, saAttr
                        )
            return 0, PassiveStream(npipe, pipename, suffix)
        elif name.startswith("ptcp:"):
            bind_path = name[6:]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote = name.split(':')
            sock.bind((remote[1], int(remote[2])))

            try:
                sock.listen(10)
            except socket.error as e:
                vlog.err("%s: listen: %s" % (name, os.strerror(e.error)))
                sock.close()
                return e.error, None

            return 0, PassiveStream(sock, name, bind_path)
        else:
            raise Exception('Unknown connection string')

    def close(self):
        """Closes this PassiveStream."""
        if hasattr(self, "socket"):
            self.socket.close()
        else:
            win32pipe.DisconnectNamedPipe(self.pipe)
        if self.bind_path is not None:
            ovs.fatal_signal.unlink_file_now(self.bind_path)
            self.bind_path = None

    def accept(self):
        """Tries to accept a new connection on this passive stream.  Returns
        (error, stream): if successful, 'error' is 0 and 'stream' is the new
        Stream object, and on failure 'error' is a positive errno value and
        'stream' is None.

        Will not block waiting for a connection.  If no connection is ready to
        be accepted, returns (errno.EAGAIN, None) immediately."""

        if hasattr(self, "socket"):
            while True:
                try:
                    sock, addr = self.socket.accept()
                    ovs.socket_util.set_nonblocking(sock)
                    if (sys.platform != "win32"
                       and sock.family == socket.AF_UNIX):
                        return 0, Stream(sock, "unix:%s" % addr, 0)
                    return 0, Stream(sock, 'ptcp:%s:%s' % (addr[0],
                                                           str(addr[1])), 0)
                except socket.error as e:
                    error = ovs.socket_util.get_exception_errno(e)
                    if (sys.platform == "win32" and
                        error == errno.WSAEWOULDBLOCK):
                        error = errno.EAGAIN
                    if error != errno.EAGAIN:
                        # XXX rate-limit
                        vlog.dbg("accept: %s" % os.strerror(error))
                    return error, None
        else:
            if self.connect_pending:
                try:
                    win32file.GetOverlappedResult(self.pipe,
                                                self.connect,
                                                False)
                    self.connect_pending = False
                except pywintypes.error as e:
                    return (errno.EAGAIN, "")
                return 0, Stream(self.pipe, "", 0)

            try:
                self.connect_pending = False
                self.connect = pywintypes.OVERLAPPED()
                self.connect.hEvent = win32event.CreateEvent(None, True,
                                                            True, None)
                error = win32pipe.ConnectNamedPipe(self.pipe, self.connect)
                if error == winerror.ERROR_IO_PENDING:
                    self.connect_pending = True
                    return errno.EAGAIN, None

                stream = Stream(self.pipe, "", 0)

                saAttr = win32security.SECURITY_ATTRIBUTES()
                saAttr.bInheritHandle = 1
                self.pipe = win32pipe.CreateNamedPipe(
                        self.name,
                        win32con.PIPE_ACCESS_DUPLEX |
                        win32con.FILE_FLAG_OVERLAPPED,
                        win32con.PIPE_TYPE_MESSAGE |
                        win32con.PIPE_READMODE_BYTE |
                        win32con.PIPE_WAIT,
                        64, 65000, 65000, 0, saAttr
                        )

                return 0, stream
            except pywintypes.error as e:
                return errno.EAGAIN, None

    def wait(self, poller):
        if hasattr(self, "socket"):
            poller.fd_wait(self.socket, ovs.poller.POLLIN)
        else:
            poller.fd_wait(self.connect.hEvent, ovs.poller.POLLIN)

    def __del__(self):
        # Don't delete the file: we might have forked.
        if hasattr(self, "socket"):
            self.socket.close()


def usage(name):
    return """
Active %s connection methods:
  unix:FILE               Unix domain socket named FILE
  tcp:IP:PORT             TCP socket to IP with port no of PORT

Passive %s connection methods:
  punix:FILE              Listen on Unix domain socket FILE""" % (name, name)


class UnixStream(Stream):
    @staticmethod
    def _open(suffix, dscp):
        connect_path = suffix
        return ovs.socket_util.make_unix_socket(socket.SOCK_STREAM,
                                                True, None, connect_path)
Stream.register_method("unix", UnixStream)


class TCPStream(Stream):
    @staticmethod
    def _open(suffix, dscp):
        error, sock = ovs.socket_util.inet_open_active(socket.SOCK_STREAM,
                                                       suffix, 0, dscp)
        if not error:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return error, sock
Stream.register_method("tcp", TCPStream)
