#!/usr/bin/python
# This script is a part of iCrackHash project
# Written by Ahmed Shawky @lnxg33k

from strop import lowercase as lcase
from strop import uppercase as ucase
try:
    from passlib import hash as ciscohash               # TODO you don't need the module comment it
except ImportError:
    print '[+] I need passlib module to identify cisco_type7 hashes'
    exit(1)


def hashType(hash):
    # python built-in 'methods'
    if hash.endswith('='):
        return 'base64'

    elif hash.startswith('0x') and hash.isalnum():
        return 'asciiHex'

    elif ',' in hash \
    and hash.split(',')[1].strip().isdigit() \
    and not hash.startswith('CHAR('):
        return 'ascii'

    elif hash.startswith('%u00') \
    and not hash.isalnum():
        return 'u00'

    elif hash.startswith('%') \
    and not hash.isalnum():
        return 'fullUrl'

    elif hash.startswith('0b1') \
    or hash.startswith('01') and hash.isalnum() and hash.isdigit() and all((c in ['0', '1']) for c in hash):
        return 'binary'

    # the following block is customized to fit icrackhas's JS output >>>   &#x61;  will be :w00t:x61:deli:
    elif hash.startswith(':w00t:x') \
    and (hash.endswith((tuple(':deli:%s' % i for i in range(10)))) \
    or hash.endswith(':deli:')):
        return 'hexEntity'

    elif hash.startswith(':w00t:') \
    and (hash.endswith(tuple('%s' % i for i in range(10))) \
    or hash.endswith(':deli:')):
        return 'htmlEntity'

    # algos depend on iCrackHash's DB 'Rainbow Tables'
    elif (hash.endswith(tuple('%s' % i for i in range(10))) \
    or hash.endswith(tuple(lcase[:6])) \
    or hash.endswith(tuple(ucase[:6]))):               # ^[A-Fa-f0-9]
        if len(hash) == 32:
            return 'md5'

        elif len(hash) == 41 \
        and hash.startswith('*'):
            return 'mysql5'

        elif len(hash) == 16:
            return 'mysql3'

        elif len(hash) == 40:
            return 'sha1'

        elif len(hash) == 64:
            return 'sha256'

        elif len(hash) == 56:
            return 'sha224'

        elif (hash.startswith('0') \
        or hash.startswith('1')) \
        and len(hash) == (len(ciscohash.cisco_type7.encrypt(hash)) - 2) / 2 \
        and hash[1] in (tuple('%s' % i for i in range(10))):
            return 'type7'

        else:
            return None

    else:
        return None
