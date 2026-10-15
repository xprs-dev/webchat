#!/usr/bin/env python3
"""A station that speaks just enough of spec/API-HTTP.md for the web chat.

    python3 contract/mock_station.py [port]

Serves dist/chat_page.html at / (gzipped, as both editions do), the
/api/services answer an app host gives (`page.tabs`, `page.app`), a history of
public rows, and POST /api/xprs/send, which it records. It exists so the page
can be tested without a board and without a phone.
"""
import gzip
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENT = []
ROWS = [{
    'ts': int(time.time()) - 60, 'bearer': 'lan', 'rssi': 0, 'from': 'X1ARKL',
    'to': '', 'type': 'message', 'sig': 'verified', 'own': False,
    'wire': 't:message f:X1ARKL ts:2026-10-15_09:00:00 scope:local m:hello from the mock',
}]
SERVICES = {'ok': True, 'features': {}, 'serve': [],
            'page': {'tabs': ['chat', 'traffic'], 'config': False, 'app': '/app'}}
if os.environ.get('MOCK_BOARD'):
    # What the boards answer today: no `page`, so the page shows everything.
    del SERVICES['page']


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json', extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/':
            raw = open(os.path.join(ROOT, 'dist', 'chat_page.html'), 'rb').read()
            self._send(200, gzip.compress(raw), 'text/html; charset=utf-8',
                       {'Content-Encoding': 'gzip'})
        elif u.path == '/app':
            self._send(200, b'<html><body>download page</body></html>', 'text/html')
        elif u.path == '/api/services':
            self._send(200, SERVICES)
        elif u.path == '/api/xprs/history':
            q = parse_qs(u.query)
            kinds = (q.get('kind') or [''])[0].split(',')
            rows = [r for r in ROWS if not kinds[0] or r['type'] in kinds]
            self._send(200, {'ok': True, 'count': len(rows), 'held': len(ROWS),
                             'time': 'synced', 'rows': rows})
        elif u.path == '/__sent':
            self._send(200, SENT)
        else:
            self._send(404, {'ok': False, 'error': 'not here'})

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode()
        if urlparse(self.path).path == '/api/xprs/send':
            try:
                wire = json.loads(body)['wire']
            except Exception:
                wire = body
            if not wire.startswith('t:') or ' f:' not in wire or len(wire) > 250:
                return self._send(400, {'ok': False, 'error': 'malformed'})
            SENT.append(wire)
            return self._send(200, {'ok': True, 'id': 'abc123', 'wire': wire})
        self._send(404, {'ok': False, 'error': 'not here'})


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8780
    ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
