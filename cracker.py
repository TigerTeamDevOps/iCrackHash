#!/usr/bin/env python
#This script is a part of iCrackHash
#Written by Ahmed Shawky @lnxg33k

from encrypt import encrypt
from encrypt import cisco_type7
import binascii
import re
import urllib2
import urllib


class TwoWayHash:
    def __init__(self):
        self.algos = {
                      'base64': self.base64,
                      'asciiHex': self.asciiHex,
                      'ascii': self.ascii,
                      'u00': self.u00,
                      'fullUrl': self.fullUrl,
                      'binary': self.binary,
                      'type7': self.type7,
                      'htmlEntity': self.htmlEntity,
                      'hexEntity': self.hexEntity,
                      }

    def base64(self, hash):
        plain = hash.decode('base64')
        return plain

    def asciiHex(self, hash):
        plain = hash.lstrip('0x').decode('hex')
        return plain

    def ascii(self, hash):
        plain = ''.join(['%s' % chr(int(i)) for i in hash.lstrip('(').rstrip(')').split(',')])
        return plain

    def u00(self, hash):
        plain = hash.replace('%u00', '').decode('hex')
        return plain

    def fullUrl(self, hash):
        plain = hash.replace('%', '').decode('hex')
        return plain

    def binary(self, hash):
        plain = binascii.unhexlify('%x' % int(hash, 2))
        return plain

    def type7(self, hash):
        plain = cisco_type7.decode(hash)
        return plain

    def hexEntity(self, hash):
        plain = ''.join(['%s' % (i.replace(':w00t:x', '')).decode('hex') for i in hash.split(':deli:')])
        return plain

    def htmlEntity(self, hash):
        plain = ''.join(['%s' % chr(int(i)) for i in hash.replace(':deli:', '').lstrip(':w00t:').split(':w00t:')])
        return plain


class OneWayHash(object):
    def __init__(self):
        self.algos = ['md5', 'sha1', 'sha224', 'sha256']
        self.dbs = {
                'goog': self.goog,
                'tobtu': self.tobtu,
                'rednoize': self.rednoize,
                'sha1Lookup': self.sha1Lookup,
                'bigTrapeze': self.bigTrapeze,
                'hashCracking': self.hashCracking,
                'myaddr': self.myaddr,
                }

    def goog(self, hash, type):
        request = urllib2.Request('http://goog.li/?t={0}'.format(hash))
        request.add_header('User-Agent', 'iCrackHash (http://www.icrackhash.com/)')
        source = urllib2.urlopen(request).read()
        if 'found=true' in source:  # type=plaintext
            plainRex = re.search('plaintext=(?P<hash>.+)', source)
            if plainRex:
                plain = plainRex.group('hash')
                if hash == encrypt.algos[type](plain):
                    return plain

    def tobtu(self, hash, type):
        request = 'http://www.tobtu.com/md5.php?h={0}'.format(hash)
        source = urllib2.urlopen(request).read()
        plainRex = re.search(':\w.+:(?P<hash>\w+.\w+)', source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

    def rednoize(self, hash, type):
        url = 'http://md5.rednoize.com/'
        if type == 'md5':
            url += '?p&s=MD5&q={0}&_='.format(hash)
        elif type == 'sha1':
            url += '?p&s=sha1&q={0}&_='.format(hash)
        request = urllib2.Request(url)
        source = urllib2.urlopen(request).read()
        plainRex = re.search('(?P<hash>.+)', source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

    def sha1Lookup(self, hash, type):
        if type == 'md5':
            url = 'http://www.md5-lookup.com/'
        elif type == 'sha1':
            url = 'http://www.sha1-lookup.com/'
        elif type == 'sha256':
            url = 'http://sha-256.sha1-lookup.com/'
        url += 'index.php?q={0}'.format(hash)
        request = urllib2.Request(url)
        source = urllib2.urlopen(request).read()
        plainRex = re.search(r'<td width="250">(?P<hash>.+)</td>', source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

    def bigTrapeze(self, hash, type):
        url = 'http://www.bigtrapeze.com/'
        url += 'md5/index.php?query={0}'.format(hash)
        request = urllib2.Request(url)
        request.add_header('user-agent', 'Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0')
        source = urllib2.urlopen(request).read()
        plainRex = re.search('(=> <strong>)(?P<hash>\w+.\w+)', source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

    def hashCracking(self, hash, type):
        url = 'https://hashcracking.ru/'
        url += 'index.php'
        parameters = urllib.urlencode({'hash': hash.lstrip('*')})
        request = urllib2.Request(url)
        source = urllib2.urlopen(request, parameters).read()
        plainRex = re.search(r"<span class='green'>(?P<hash>.+)</span>'", source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

    def myaddr(self, hash, type):
        url = 'http://md5.my-addr.com/'
        url += 'md5_decrypt-md5_cracker_online/md5_decoder_tool.php'
        parameters = urllib.urlencode({'md5': hash})
        request = urllib2.Request(url)
        source = urllib2.urlopen(request, parameters).read()
        plainRex = re.search('(Hashed string</span>: )(?P<hash>\w+.\w+)', source)
        if plainRex:
            plain = plainRex.group('hash')
            if hash == encrypt.algos[type](plain):
                return plain

oneWay = OneWayHash()
twoWay = TwoWayHash()
