iCrackHash
==========

iCrackHash is a search engine for hashes and passwords. First it detects the hash type in a simple way then it deals with the hash as the following.  
For two way hashes 'base64, ascii, asciihex and etc...' it uses some builtin methods in python to decrypt them 'e.g.) .encode()'.  
For one way hashes 'Md5, Sha-1, sha-224 and etc...' it  uses some online DBs to search for the hash "e.g.) goog, tobtu, rednoize and etc...".  
if iCrackHash couldn't figure out the hash type it will consider it a normal string and it will encode this string in different formats like 'hex, hexentity, fullurl and etc...'.