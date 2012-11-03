#!/usr/bin/env python
#This script is a part of iCrackhash
#Written by Ahmed Shawky @lnxg33k

from smasher import hashType
from cracker import twoWay, oneWay

hashes = [
        '0x74657374313233', '116,101,115,116,49,50,51',
        '01101101011010010110101101101111', '%64%69%64%6f',
        '%u0074%u0065%u0073%u0074%u0031%u0032%u0033',
        '110D181116', '71537dbb0f2d3e415e7a91ff6243e0d2',
        'a BS', 'd65a197664e1233729d709333bda1cdb',
        'd65a197664e1233729d709333bda1cd2', 'dGVzdA==',
        '21232f297a57a5a743894a0e4a801fc3',
        'd033e22ae348aeb5660fc2140aec35850c4da997',
        '9af2921d3fd57fe886c9022d1fcc055d53a79e4032fa6137e397583884e1a5de',
        '7c32fe8cc855fb7ddcc7a73346262ad10f46543643e7ae9490c8dae6'
        ]
cracked = {}
notCracked = {}
notDetected = []

x = 1
for hash in hashes:
    print '{0:2d}- Checking: {1}'.format(x, hash)
    x += 1
    if hashType(hash) in twoWay.algos:
        db = 'iCrackHash'
        cracked[hash] = (twoWay.algos[hashType(hash)](hash), hashType(hash), db)

    elif hashType(hash) in oneWay.algos:
        for db in oneWay.dbs:
            try:
                if oneWay.dbs[db](hash, hashType(hash)):
                    cracked[hash] = (oneWay.dbs[db](hash, hashType(hash)), hashType(hash), db)
                    break   # break the inner loop
                else:
                    notCracked[hash] = ('Unknown', hashType(hash), 'Unknown')
            except:
                pass
    else:
        notDetected.append(hash)

with open('result.html', 'w') as result:
        result.write('<html>')
        result.write('<head><link href="bootstrap.css" rel="stylesheet" type="text/css"></head>')
        result.write('<body>')
        result.write('<div class="row-fluid"><div class="span10 offset1">')
        #--- Cracked Table
        result.write('<legend>Cracked Hashes</legend>')
        result.write('<table class="table table-hover">')
        result.write('<thead><tr>')
        result.write('<th>#</th>')
        result.write('<th>Hash</th>')
        result.write('<th>Plain</th>')
        result.write('<th>Type</th>')
        result.write('<th>DB</th>')
        result.write('</tr></thead>')
        c = 1
        result.write('<tbody>')
        for hash, info in cracked.items():
                result.write('<tr>')
                result.write('<td>' + str(c) + '</td>')
                result.write('<td>' + hash + '</td>')
                result.write('<td>' + info[0] + '</td>')
                result.write('<td>' + info[1] + '</td>')
                result.write('<td>' + info[2] + '</td>')
                result.write('</tr>')
                c += 1
        result.write('</tbody></table>')
        #--- Not Cracked Table
        result.write('<legend>Not-Cracked Hashes</legend>')
        result.write('<table class="table table-hover">')
        result.write('<thead><tr>')
        result.write('<th>#</th>')
        result.write('<th>Hash</th>')
        result.write('<th>Type</th>')
        result.write('</tr></thead>')
        c = 1
        result.write('<tbody>')
        for hash, info in notCracked.items():
            result.write('<tr>')
            result.write('<td>' + str(c) + '</td>')
            result.write('<td>' + hash + '</td>')
            result.write('<td>' + info[1] + '</td>')
            result.write('</tr>')
            c += 1
        result.write('</tbody></table>')
        result.write('</div></div>')
        result.write('</body></html>')

print '\n[+] Successfully wrote a HTML report <result.html>'
