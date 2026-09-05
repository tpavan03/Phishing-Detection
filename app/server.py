"""Dependency-free local demo server with a persistent SQLite audit history."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from app.workflow import analyze, VERSION

STATIC = Path(__file__).parent / 'static'
DB = Path(os.environ.get('DATA_DIR', 'data')) / 'cases.sqlite3'

def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB)
    db.execute('CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL)')
    return db

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log submitted URLs or review notes.

    def reply(self, code, value, mime='application/json; charset=utf-8'):
        payload = json.dumps(value).encode() if mime.startswith('application/json') else value
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/health':
            return self.reply(200, {'status': 'ok', 'mode': 'offline rules', 'version': VERSION})
        if path == '/api/cases':
            with connect() as db:
                rows = db.execute('SELECT payload FROM cases ORDER BY created_at DESC LIMIT 30').fetchall()
            return self.reply(200, {'cases': [json.loads(row[0]) for row in rows]})
        if path.startswith('/api/cases/'):
            with connect() as db:
                row = db.execute('SELECT payload FROM cases WHERE id=?', (path.rsplit('/', 1)[-1],)).fetchone()
            return self.reply(200, json.loads(row[0])) if row else self.reply(404, {'error': 'Case not found.'})
        files = {'/': ('index.html', 'text/html; charset=utf-8'), '/styles.css': ('styles.css', 'text/css; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8')}
        if path in files:
            name, mime = files[path]
            return self.reply(200, (STATIC / name).read_bytes(), mime)
        self.reply(404, {'error': 'Not found.'})

    def do_POST(self):
        # Browser writes must originate from this instance; no cross-origin state changes.
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://' + self.headers.get('Host', ''), 'https://' + self.headers.get('Host', '')):
            return self.reply(403, {'error': 'Cross-origin requests are not permitted.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 8192:
                return self.reply(413, {'error': 'Request must be between 1 and 8,192 bytes.'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self.reply(415, {'error': 'Use application/json.'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            path = urlsplit(self.path).path
            if path == '/api/analyze':
                result = analyze(data.get('url'))
                with connect() as db:
                    db.execute('INSERT INTO cases VALUES (?, ?, ?)', (result['id'], result['created_at'], json.dumps(result)))
                return self.reply(201, result)
            if path.startswith('/api/cases/') and path.endswith('/review'):
                case_id = path.split('/')[3]
                decision, note = data.get('decision'), data.get('note', '')
                if decision not in ('likely_legitimate', 'suspicious', 'needs_investigation'):
                    raise ValueError('Select a supported review decision.')
                if not isinstance(note, str) or not note.strip() or len(note) > 500:
                    raise ValueError('Add a review note between 1 and 500 characters.')
                with connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    row = db.execute('SELECT payload FROM cases WHERE id=?', (case_id,)).fetchone()
                    if not row:
                        return self.reply(404, {'error': 'Case not found.'})
                    result = json.loads(row[0])
                    if result['review']:
                        return self.reply(409, {'error': 'This case already has a review. Analyze again to create a new case.'})
                    result['review'] = {'decision': decision, 'note': note.strip(), 'reviewed_at': datetime.now(timezone.utc).isoformat(), 'reviewer': 'local demo operator'}
                    result['status'] = 'escalated' if decision == 'needs_investigation' else 'reviewed'
                    result['stages'][-1] = {'name': 'Human review', 'status': 'completed', 'detail': 'Operator recorded: ' + decision.replace('_', ' ') + '.'}
                    db.execute('UPDATE cases SET payload=? WHERE id=?', (json.dumps(result), case_id))
                return self.reply(200, result)
            self.reply(404, {'error': 'Not found.'})
        except (ValueError, UnicodeError) as exc:
            self.reply(400, {'error': str(exc)})
        except sqlite3.Error:
            self.reply(503, {'error': 'Case storage is temporarily unavailable.'})

if __name__ == '__main__':
    with connect():
        pass
    ThreadingHTTPServer((os.environ.get('HOST', '127.0.0.1'), int(os.environ.get('PORT', '3102'))), Handler).serve_forever()
