import sys
import utp.utp_socket as utp
import types
import socket

from cStringIO import StringIO
from zope.interface import implements
from twisted.python import failure, log
from twisted.python.util import unsignedID
from twisted.internet import abstract, main, interfaces, error, base, task
from twisted.internet import address, defer
from twisted.internet.tcp import ECONNRESET
from twisted.internet.defer import Deferred, maybeDeferred
from twisted.internet.protocol import DatagramProtocol


def makeAddr(addr):
    return address.IPv4Address('UDP', *(addr + ('INET',)))


def _disconnectSelectable(selectable, why, isRead, faildict={
    error.ConnectionDone: failure.Failure(error.ConnectionDone()),
    error.ConnectionLost: failure.Failure(error.ConnectionLost())
    }):
    """
    Utility function for disconnecting a selectable.

    Supports half-close notification, isRead should be boolean indicating
    whether error resulted from doRead().
    """
    f = faildict.get(why.__class__)
    if f:
        if (isRead and why.__class__ ==  error.ConnectionDone
            and interfaces.IHalfCloseableDescriptor.providedBy(selectable)):
            selectable.readConnectionLost(f)
        else:
            selectable.connectionLost(f)
    else:
        selectable.connectionLost(failure.Failure(why))


class Connection(abstract.FileDescriptor, utp.Callbacks):

    def __init__(self, adapter, utp_socket, reactor):
        abstract.FileDescriptor.__init__(self, reactor=reactor)
        self.reactor.addUTPConnection(self)
        self.adapter = adapter
        self.protocol = None
        self.utp_socket = utp_socket
        self.utp_socket.set_callbacks(self)
        self.writeTriggered = False
        self.writing = False
        self.reading = False

    logstr = "Uninitialized"

    def logPrefix(self):
        """Return the prefix to log with when I own the logging thread.
        """
        return self.logstr

    def on_read(self, data):
        if self.reading:
            assert not hasattr(self, "_readBuffer")
            self._readBuffer = data
            log.callWithLogger(self, self._doReadOrWrite, "doRead")

    def doRead(self):
        data = self._readBuffer
        del self._readBuffer
        self.protocol.dataReceived(data)

    def get_rb_size(self):
        # TODO: extend producer/consumer interfaces in Twisted to support
        # fetching the number of bytes before a pauseProducing would happen.
        # Then this number, x, would be used like this: rcvbuf - min(x, rcvbuf)
        # (so that: rcvbuf-(rcvbuf-x) == x)
        return 0

    def on_write(self, count):
        d = buffer(self._writeBuffer, 0, count)
        self._writeBuffer = buffer(self._writeBuffer, count)
        return str(d)

    def writeSomeData(self, data):
        """
        Write as much as possible of the given data to this UTP connection.

        The number of bytes successfully written is returned.
        """
        if not hasattr(self, "utp_socket"):
            return main.CONNECTION_LOST
        assert not hasattr(self, "_writeBuffer")
        self._writeBuffer = data
        self.utp_socket.write(len(data))
        sent = len(data) - len(self._writeBuffer)
        del self._writeBuffer
        return sent

    def on_state(self, state):
        if state == utp.CONNECT:
            self._connectDone()
        elif state == utp.WRITABLE:
            if self.writing:
                self.triggerWrite()
        elif state == utp.EOF:
            self.loseConnection()
        elif state == utp.DESTROYING:
            self.reactor.removeUTPConnection(self)
            df = maybeDeferred(self.adapter.removeSocket, self.dying_utp_socket)
            df.addCallback(self._finishConnectionLost)
            del self.dying_utp_socket

    def on_error(self, errcode):
        if errcode == ECONNRESET:
            err = main.CONNECTION_LOST
        else:
            err = error.errnoMapping.get(errcode, errcode)
        self.connectionLost(failure.Failure(err))

    def stopReading(self):
        self.reading = False

    def stopWriting(self):
        self.writing = False

    def startReading(self):
        self.reading = True

    def _doReadOrWrite(self, method):
        try:
            why = getattr(self, method)()
        except:
            why = sys.exc_info()[1]
            log.err()
        if why:
            _disconnectSelectable(self, why, method=="doRead")

    def triggerWrite(self):
        self.writeTriggered = False
        log.callWithLogger(self, self._doReadOrWrite, "doWrite")

    def startWriting(self):
        self.writing = True
        # UTP socket write state is edge triggered, so we may or may not be
        # writable right now. So, just try it. We use reactor.callLater so
        # functions like abstract.FileDescriptor.loseConnection don't start
        # doWrite before setting self.disconnecting to True.
        if not self.writeTriggered:
            self.writeTriggered = True
            self.reactor.callLater(0, self.triggerWrite)

    # These are here because abstract.FileDescriptor claims to implement
    # IHalfCloseableDescriptor, but we can not support IHalfCloseableProtocol
    def writeConnectionLost(self, reason):
        self.connectionLost(reason)

    # These are here because abstract.FileDescriptor claims to implement
    # IHalfCloseableDescriptor, but we can not support IHalfCloseableProtocol
    def readConnectionLost(self, reason):
        self.connectionLost(reason)

    def connectionLost(self, reason):
        abstract.FileDescriptor.connectionLost(self, reason)
        if hasattr(self, "utp_socket"):
            self.reason = reason
            self.utp_socket.close()
            self.dying_utp_socket = self.utp_socket
            del self.utp_socket
            self.closing_df = Deferred()
        if hasattr(self, "closing_df"):
            return self.closing_df

    def _finishConnectionLost(self, r):
        protocol = self.protocol
        reason = self.reason
        df = self.closing_df
        del self.protocol
        del self.reason
        del self.closing_df
        if protocol:
            protocol.connectionLost(reason)
        return df.callback(r)

    def getPeer(self):
        return makeAddr(self.utp_socket.getpeername())

    def getHost(self):
        return self.adapter.getHost()


class Client(Connection):

    def __init__(self, host, port, connector, adapter, reactor=None, soError=None):
        # Connection.__init__ is invoked later in doConnect
        self.connector = connector
        self.addr = (host, port)
        self.adapter = adapter
        self.reactor = reactor
        self.soError = soError
        # ack, twisted. what the heck.
        self.reactor.callLater(0, self.resolveAddress)

    def __repr__(self):
        s = '<%s to %s at %x>' % (self.__class__, self.addr, unsignedID(self))
        return s

    def stopConnecting(self):
        """Stop attempt to connect."""
        return self.failIfNotConnected(error.UserError())

    def failIfNotConnected(self, err):
        """
        Generic method called when the attemps to connect failed. It basically
        cleans everything it can: call connectionFailed, stop read and write,
        delete socket related members.
        """
        if (self.connected or self.disconnected or
            not hasattr(self, "connector")):
            return

        # HM: maybe call loseConnection, maybe make a new function
        self.disconnecting = 1
        reason = failure.Failure(err)
        # we might not have an adapter if there was a bind error
        # but we need to notify the adapter if we failed before connecting
        stop = (self.adapter and not hasattr(self, "utp_socket"))
        df = maybeDeferred(Connection.connectionLost, self, reason)
        if stop:
            df.addCallback(lambda r: self.adapter.maybeStopUDPPort())
        def more(r):
            self.connector.connectionFailed(reason)
            del self.connector
            self.disconnecting = 0
        df.addCallback(more)
        return df

    def resolveAddress(self):
        if abstract.isIPAddress(self.addr[0]):
            self._setRealAddress(self.addr[0])
        else:
            d = self.reactor.resolve(self.addr[0])
            d.addCallbacks(self._setRealAddress, self.failIfNotConnected)

    def _setRealAddress(self, address):
        self.realAddress = (address, self.addr[1])
        self.doConnect()

    def doConnect(self):
        """I connect the socket.

        Then, call the protocol's makeConnection, and start waiting for data.
        """
        if self.disconnecting or not hasattr(self, "connector"):
            # this happens when the connection was stopped but doConnect
            # was scheduled via the resolveAddress callLater
            return

        if self.soError:
            self.failIfNotConnected(self.soError)
            return

        utp_socket = utp.Socket()
        utp_socket.init_outgoing(self.adapter.udpPort.write, self.realAddress)
        self.adapter.addSocket(utp_socket)
        Connection.__init__(self, self.adapter, utp_socket, self.reactor)
        utp_socket.connect()

    def _connectDone(self):
        self.protocol = self.connector.buildProtocol(self.getPeer())
        self.connected = 1
        self.logstr = self.protocol.__class__.__name__ + ",client"
        self.startReading()
        self.protocol.makeConnection(self)

    def connectionLost(self, reason):
        if not self.connected:
            self.failIfNotConnected(error.ConnectError(string=reason))
        else:
            df = maybeDeferred(Connection.connectionLost, self, reason)
            def more(r):
                self.connector.connectionLost(reason)
            df.addCallback(more)


class Server(Connection):

    def __init__(self, utp_socket, protocol, adapter, sessionno, reactor):
        Connection.__init__(self, adapter, utp_socket, reactor)
        self.protocol = protocol
        self.sessionno = sessionno
        self.hostname = self.getPeer().host
        self.logstr = "%s,%s,%s" % (self.protocol.__class__.__name__,
                                    sessionno,
                                    self.hostname)
        self.repstr = "<%s #%s on %s>" % (self.protocol.__class__.__name__,
                                          self.sessionno,
                                          self.adapter.udpPort._realPortNumber)
        self.startReading()
        self.connected = 1

    def __repr__(self):
        """A string representation of this connection.
        """
        return self.repstr


class Connector(base.BaseConnector):

    def __init__(self, host, port, factory, adapter, timeout, reactor=None):
        self.host = host
        if isinstance(port, types.StringTypes):
            try:
                port = socket.getservbyname(port, 'tcp')
            except socket.error:
                e = sys.exc_info()[1]
                raise error.ServiceNameUnknownError(string="%s (%r)" % (e, port))
        self.port = port
        self.adapter = adapter
        self.soError = None
        base.BaseConnector.__init__(self, factory, timeout, reactor)

    def _makeTransport(self):
        return Client(self.host, self.port, self, self.adapter, self.reactor, self.soError)

    def getDestination(self):
        return address.IPv4Address('UDP', self.host, self.port, 'INET')


class Protocol(DatagramProtocol):

    BUFFERSIZE = 2 * 1024 * 1024

    def startProtocol(self):
        if interfaces.ISystemHandle.providedBy(self.transport):
            sock = self.transport.getHandle()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.BUFFERSIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.BUFFERSIZE)

    def datagramReceived(self, data, addr):
        if self.adapter.acceptIncoming and self.adapter.listening:
            cb = self.adapter.connectionReceived
        else:
            cb = None
        utp.IsIncomingUTP(cb, self.transport.write, data, addr)


class Adapter:

    def __init__(self, udpPort, acceptIncoming):
        self.udpPort = udpPort
        self.acceptIncoming = acceptIncoming
        # HORK
        udpPort.protocol.adapter = self
        self.sockets = set()

    def addSocket(self, utp_socket):
        if not self.udpPort.connected:
            assert not self.acceptIncoming
            self.udpPort.startListening()
        self.sockets.add(utp_socket)

    def removeSocket(self, utp_socket):
        self.sockets.remove(utp_socket)
        return self.maybeStopUDPPort()

    def maybeStopUDPPort(self):
        if len(self.sockets) == 0:
            assert self.udpPort.connected
            return self.udpPort.stopListening()

    def getHost(self):
        return self.udpPort.getHost()


class Port(Adapter, base.BasePort):

    implements(interfaces.IListeningPort)
    sessionno = 0

    def __init__(self, udpPort, factory, reactor):
        self.factory = factory
        self.reactor = reactor
        Adapter.__init__(self, udpPort, acceptIncoming=True)
        self.listening = False

    def __repr__(self):
        if self.udpPort._realPortNumber is not None:
            return "<%s of %s on %s>" % (self.__class__, self.factory.__class__,
                                         self.udpPort._realPortNumber)
        else:
            return "<%s of %s (not listening)>" % (self.__class__, self.factory.__class__)

    def maybeStopUDPPort(self):
        if not self.listening:
            return Adapter.maybeStopUDPPort(self)

    def startListening(self):
        if self.listening:
            return
        self.listening = True
        if not self.udpPort.connected:
            self.udpPort.startListening()
        self.factory.doStart()

    def stopListening(self):
        if not self.listening:
            return
        self.listening = False
        df = maybeDeferred(self.maybeStopUDPPort)
        df.addCallback(lambda r: self._connectionLost())
        return df

    # this one is for stopListening
    # the listening port has closed
    def _connectionLost(self, reason=None):
        assert not self.listening
        base.BasePort.connectionLost(self, reason)
        self.factory.doStop()

    # this one is for calling directly
    # the listening port has closed
    def connectionLost(self, reason=None):
        self.listening = False
        self.udpPort.connectionLost(reason)
        self._connectionLost(reason)

    # a new incoming connection has arrived
    def connectionReceived(self, utp_socket):
        self.addSocket(utp_socket)
        protocol = self.factory.buildProtocol(makeAddr(utp_socket.getpeername()))
        if protocol is None:
            # XXX: untested path
            Connection(self, utp_socket, self.reactor).loseConnection()
            return
        s = self.sessionno
        self.sessionno = s+1
        transport = Server(utp_socket, protocol, self, s, self.reactor)
        protocol.makeConnection(transport)


def listenUTP(self, port, factory, interface=''):
    udpPort = self.listenUDP(port, Protocol(), interface=interface)
    utpPort = Port(udpPort, factory, self)
    utpPort.startListening()
    return utpPort

def createUTPAdapter(self, port, protocol, interface=''):
    udpPort = self.listenUDP(port, protocol, interface=interface)
    return Adapter(udpPort, acceptIncoming=False)

def connectUTP(self, host, port, factory, timeout=30, bindAddress=None):
    if bindAddress is None:
        bindAddress = ['', 0]
    adapter = None
    try:
        adapter = self.createUTPAdapter(bindAddress[1], Protocol(), interface=bindAddress[0])
    except error.CannotListenError:
        e = sys.exc_info()[1]
        c = Connector(host, port, factory, None, timeout, self)
        se = e.socketError
        # We have to call connect to trigger the factory start and connection
        # start events, but we already know the connection failed because the
        # UDP socket couldn't bind. So we set soError, which causes the connect
        # call to fail.
        c.soError = error.ConnectBindError(se[0], se[1])
        c.connect()
        return c
    try:
        return self.connectUTPUsingAdapter(host, port, factory, adapter, timeout=timeout)
    except:
        adapter.maybeStopUDPPort()
        raise

def connectUTPUsingAdapter(self, host, port, factory, adapter, timeout=30):
    c = Connector(host, port, factory, adapter, timeout, self)
    c.connect()
    return c

# like addReader/addWriter, sort of
def addUTPConnection(self, connection):
    if not hasattr(self, "_utp_task"):
        self._utp_connections = set()
        self._utp_task = task.LoopingCall(utp.CheckTimeouts)
        self._utp_task.start(0.050)
    self._utp_connections.add(connection)

# like removeReader/removeWriter, sort of
def removeUTPConnection(self, connection):
    self._utp_connections.remove(connection)
    if len(self._utp_connections) == 0:
        self._utp_task.stop()
        del self._utp_task
        del self._utp_connections

# Ouch.
from twisted.internet.protocol import ClientCreator, _InstanceFactory
def clientCreatorConnectUTP(self, host, port, timeout=30, bindAddress=None):
    """Connect to remote host, return Deferred of resulting protocol instance."""
    d = defer.Deferred()
    f = _InstanceFactory(self.reactor, self.protocolClass(*self.args, **self.kwargs), d)
    self.reactor.connectUTP(host, port, f, timeout=timeout, bindAddress=bindAddress)
    return d
ClientCreator.connectUTP = clientCreatorConnectUTP

# Owwww.
from twisted.internet import reactor
reactor.__class__.listenUTP = listenUTP
reactor.__class__.connectUTP = connectUTP
reactor.__class__.createUTPAdapter = createUTPAdapter
reactor.__class__.connectUTPUsingAdapter = connectUTPUsingAdapter
reactor.__class__.addUTPConnection = addUTPConnection
reactor.__class__.removeUTPConnection = removeUTPConnection
del reactor
