__author__ = 'root'
import socket
import logging
import logging.handlers
from struct import *


class Connector:
    def __main__(self):
        pass

    def __init__(self, ):
        self.log = logging.getLogger('Thales')
        #self.TCP_IP = '10.125.3.30'
        self.TCP_IP = '203.213.124.34'
        self.TCP_PORT = 1500
        self.BUFFER_SIZE = 1024
        self.__Connect()

    def __Connect(self):
        self.log.debug("Connecting to Thales on address %s:%s" % (self.TCP_IP, self.TCP_PORT))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.sock.setdefaulttimeout(10000)
        self.sock.connect((self.TCP_IP, self.TCP_PORT))
        self.sock.settimeout(None)
        self.log.debug("Connected.")

    def SendMessage(self, Command):

        response = ''
        try:

            Header = 'HEAD'
            Command = Header + Command
            Size = pack('>h', len(Command))

            Message = Size + Command
            sent = self.sock.send(Message)
            response = self.sock.recv(1024)


        finally:
            return response




"""
class Database(object):
    _iInstance = None
    class Singleton:
        def __init__(self):
            # add singleton variables here
            self.connection = MySQLdb.connect("127.0.0.1", "switch", "Potatohair51!", "switch")'

    def __init__( self):
        if Database._iInstance is None:
            Database._iInstance = Database.Singleton()
        self._EventHandler_instance = Database._iInstance


    def __getattr__(self, aAttr):
        return getattr(self._iInstance, aAttr)

    def __setattr__(self, aAttr, aValue):
        return setattr(self._iInstance, aAttr, aValue)

class SwitchDatabase():
    def get_connection(self):
        try:
            return Database().connection
        except Exception as exe:
            raise
"""

