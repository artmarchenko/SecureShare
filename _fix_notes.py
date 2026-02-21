# -*- coding: utf-8 -*-
"""Bump version to 3.3.3."""
import sys
sys.stdout.reconfigure(errors='replace')

# config.py
c = open('app/config.py', 'r', encoding='utf-8').read()
c = c.replace('APP_VERSION = "3.3.2"', 'APP_VERSION = "3.3.3"')
open('app/config.py', 'w', encoding='utf-8').write(c)

# version_info.txt
v = open('version_info.txt', 'r', encoding='utf-8').read()
v = v.replace('(3, 3, 2, 0)', '(3, 3, 3, 0)')
v = v.replace("u'3.3.2.0'", "u'3.3.3.0'")
open('version_info.txt', 'w', encoding='utf-8').write(v)

# relay_server.py
r = open('server/relay_server.py', 'r', encoding='utf-8').read()
r = r.replace('"3.3.2"', '"3.3.3"')
open('server/relay_server.py', 'w', encoding='utf-8').write(r)

print("OK: bumped to 3.3.3")
