from collections import OrderedDict
from passlib.hash import hex_md5
from passlib.hash import hex_sha1
from passlib.hash import hex_sha256
from passlib.hash import mysql41
from passlib.hash import mysql323
from passlib.hash import cisco_type7
from passlib.hash import lmhash
from hashlib import sha224


class Encrypt(object):
    """
    >>> from encrypt import encrypt
    >>> for algo in encrypt.algos:
    ...     print algo, encrypt.algos[algo]('admin')
    """
    def __init__(self):
        self.algos = OrderedDict([
                      ('md5', self.md5),
                      ('sha1', self.sha1),
                      ('sha256', self.sha256),
                      ('sha224', self.sha224),
                      ('mysql5', self.mysql5),
                      ('mysql3', self.mysql3),
                      ('lmhash', self.lmhash),
                      ('type7', self.type7),
                      ('base64', self.base64),
                      ('ascii', self.ascii),
                      ('asciiHex', self.asciiHex),
                      ('hexEntity', self.hexEntity),
                      ('htmlEntity', self.htmlEntity),
                      ('u00', self.u00),
                      ('mysqlChar', self.mysqlChar),
                      ('mssqlChar', self.mssqlChar),
                      ('fullUrl', self.fullUrl),
                      ('binary', self.binary),
                      ])

    def md5(self, plain):
        return hex_md5.encrypt(plain)

    def sha256(self, plain):
        return hex_sha256.encrypt(plain)

    def sha1(self, plain):
        return hex_sha1.encrypt(plain)

    def sha224(self, plain):
        return sha224(plain).hexdigest()

    def type7(self, plain):
        return cisco_type7.encrypt(plain)

    def mysql5(self, plain):
        return mysql41.encrypt(plain)

    def mysql3(self, plain):
        return mysql323.encrypt(plain)

    def lmhash(self, plain):
        return lmhash.encrypt(plain)

    def base64(self, plain):
        return plain.encode('base64').rstrip()

    def ascii(self, plain):
        return ''.join(['{0},'.format(str(ord(i))) for i in plain]).rstrip(',')

    def asciiHex(self, plain):
        return '0x{0}'.format(plain.encode('hex'))

    def hexEntity(self, plain):
        return ''.join(['{0};'.format(hex(ord(i)).replace('0x', '&#x')) for i in plain])

    def htmlEntity(self, plain):
        return ''.join(['&#{0}'.format(ord(i)) for i in plain])

    def u00(self, plain):
        return ''.join(['{0}'.format(hex(ord(i)).replace('0x', '%u00')) for i in plain])

    def mysqlChar(self, plain):
        return 'CHAR({0})'.format(''.join(['{0}, '.format((str(ord(i)))) for i in plain]).rstrip(', '))

    def mssqlChar(self, plain):
        return ''.join(['CHAR(%s)+' % (str(ord(i))) for i in plain]).rstrip('+')

    def fullUrl(self, plain):
        return ''.join(['%s' % hex(ord(i)).replace('0x', '%') for i in plain])

    def binary(self, plain):
        return ''.join(['%08d' % int(bin(ord(i))[2:]) for i in plain])

encrypt = Encrypt()
