#!/usr/bin/env python3
#
# Mutt OAuth2 token management script, version 2020-08-07
# Written against python 3.7.3, not tried with earlier python versions.
#
#   Copyright (C) 2020 Alexander Perlis
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation; either version 2 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#   02110-1301, USA.
'''Mutt OAuth2 token management'''

import sys
import json
import argparse
import urllib.parse
import urllib.request
import imaplib
import poplib
import smtplib
import base64
import secrets
import hashlib
import time
from datetime import timedelta, datetime
from pathlib import Path
import socket
import http.server
import subprocess

registration = {
    'authorize_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'devicecode_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
    'token_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    'redirect_uri': 'https://login.microsoftonline.com/common/oauth2/nativeclient',
    'tenant': 'common',
    'imap_endpoint': 'outlook.office365.com',
    'pop_endpoint': 'outlook.office365.com',
    'smtp_endpoint': 'smtp.office365.com',
    'sasl_method': 'XOAUTH2',
    'scope': ('offline_access https://outlook.office.com/IMAP.AccessAsUser.All '
        'https://outlook.office.com/POP.AccessAsUser.All '
        'https://outlook.office.com/SMTP.Send'),
    'client_id': '08162f7c-0fd2-4200-a84a-f25a4db0b584',
    'client_secret': 'TxRBilcHdC6WGBee]fs?QR:SJ8nI[g82',
}

p = {'client_id': registration['client_id']}
p['scope'] = registration['scope']

verifier = secrets.token_urlsafe(90)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())[:-1]
redirect_uri = registration['redirect_uri']
listen_port = 0

# Find an available port to listen on
s = socket.socket()
s.bind(('127.0.0.1', 0))
listen_port = s.getsockname()[1]
s.close()
redirect_uri = 'http://localhost:'+str(listen_port)+'/'
# Probably should edit the port number into the actual redirect URL.

p.update({'login_hint': input('Account e-mail address: '),
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'})
print(registration["authorize_endpoint"] + '?' +
        urllib.parse.urlencode(p, quote_via=urllib.parse.quote))

authcode = ''
print('Visit displayed URL to authorize this application. Waiting...',
        end='', flush=True)

class MyHandler(http.server.BaseHTTPRequestHandler):
    '''Handles the browser query resulting from redirect to redirect_uri.'''

    # pylint: disable=C0103
    def do_HEAD(self):
        '''Response to a HEAD requests.'''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        '''For GET request, extract code parameter from URL.'''
        # pylint: disable=W0603
        global authcode
        querystring = urllib.parse.urlparse(self.path).query
        querydict = urllib.parse.parse_qs(querystring)
        if 'code' in querydict:
            authcode = querydict['code'][0]
        self.do_HEAD()
        self.wfile.write(b'<html><head><title>Authorizaton result</title></head>')
        self.wfile.write(b'<body><p>Authorization redirect completed. You may '
                            b'close this window.</p></body></html>')
with http.server.HTTPServer(('127.0.0.1', listen_port), MyHandler) as httpd:
    try:
        httpd.handle_request()
    except KeyboardInterrupt:
        pass

if not authcode:
    sys.exit('Did not obtain an authcode.')

print('')
print('Refresh code: ', authcode)
