#!/usr/bin/env python3
"""
A quick check of the RUNNING service, with its real settings. Run as root on the server:

    python3 /srv/quote-pages/tests/smoke.py

It makes a throwaway business, signs in with its one-time link, saves settings, uploads a logo,
looks at the page the way the public would, then deletes the business again. It talks to the
service on its own loopback port. Nothing is emailed.
"""
import http.client
import json
import os
import re
import secrets
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'app', 'server.py')
ENV_FILE = os.environ.get('QP_ENV_FILE', '/etc/quote-pages/env')
PNG = bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944415408d763f8cfc000000301010018dd8db00000000049454e44ae426082')


def load_env():
    env = dict(os.environ)
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE, encoding='utf-8'):
            m = re.match(r'^([A-Z_]+)=(.*)$', line.rstrip('\n'))
            if m:
                v = m.group(2).strip()
                env[m.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
    return env


def main():
    env = load_env()
    port = int(env.get('QP_PORT', '7871'))
    base = env.get('QP_BASE_URL', f'http://127.0.0.1:{port}').rstrip('/')
    email = f'smoke-{secrets.token_hex(4)}@example.com'
    cli = lambda *a: subprocess.run([sys.executable, SERVER, *a], env=env, capture_output=True, text=True)
    done = []

    def check(name, ok, detail=''):
        done.append(ok)
        print(('PASS  ' if ok else 'FAIL  ') + name + (f'  [{detail}]' if detail and not ok else ''))

    def call(method, path, body=None, headers=None, cookie=''):
        h = {'X-Forwarded-For': '127.0.0.1', 'Origin': base}
        if cookie:
            h['Cookie'] = cookie
        h.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        conn.request(method, path, body=body if body is not None else (b'' if method == 'POST' else None), headers=h)
        res = conn.getresponse()
        res.text = res.read()
        conn.close()
        return res

    out = cli('add', email, '0400 000 000', 'Smoke', 'Test', 'Trees', secrets.token_hex(2))
    link = re.search(r'/auth#t=([A-Za-z0-9_-]+)', out.stdout)
    slug = re.search(r'Page made: \S+/([a-z0-9-]+)', out.stdout)
    check('make a throwaway business', bool(link and slug), out.stdout + out.stderr)
    if not (link and slug):
        return 1
    slug = slug.group(1)
    try:
        res = call('POST', '/auth', f't={link.group(1)}'.encode(), {'Content-Type': 'application/x-www-form-urlencoded'})
        setc = res.getheader('Set-Cookie') or ''
        cookie = setc.split(';')[0]
        secure = base.startswith('https://')
        check('one-time link signs in', res.status == 303 and bool(cookie), f'{res.status} {setc[:60]}')
        check('cookie is locked down', 'HttpOnly' in setc and 'SameSite=Lax' in setc and (not secure or (setc.startswith('__Host-qp=') and 'Secure' in setc)), setc[:40])
        res = call('POST', '/auth', f't={link.group(1)}'.encode(), {'Content-Type': 'application/x-www-form-urlencoded'})
        check('the link does not work twice', res.status == 400, res.status)
        check('account page opens', call('GET', '/my', cookie=cookie).status == 200)
        mine = call('GET', '/' + slug, cookie=cookie).text.decode()
        acc = re.search(r'window\.QUOTE_ACCOUNT = (\{.*?\});', mine)
        acc = json.loads(acc.group(1)) if acc else {}
        check('owner sees the edit controls', 'save' in acc and 'Edit my page' in mine)
        settings = json.loads(re.search(r'^window\.QUOTE_SETTINGS = (\{.*\});$', mine, re.M).group(1))
        settings.update(businessName='Smoke Test Renamed', colour='#224466', baseSuburb='Midland')
        res = call('POST', '/api/settings', json.dumps({'settings': settings}).encode(), {'Content-Type': 'application/json', 'X-CSRF': acc.get('csrf', '')}, cookie)
        check('save settings', res.status == 200, res.text[:120])
        res = call('POST', '/api/settings', json.dumps({'settings': settings}).encode(), {'Content-Type': 'application/json', 'X-CSRF': 'wrong'}, cookie)
        check('save is refused without the page token', res.status == 403, res.status)
        res = call('POST', '/api/logo', PNG, {'Content-Type': 'image/png', 'X-CSRF': acc.get('csrf', '')}, cookie)
        logo = json.loads(res.text).get('logo', '') if res.status == 200 else ''
        check('upload a logo', bool(logo), res.text[:120])
        public = call('GET', '/' + slug)
        text = public.text.decode()
        check('public page shows the saved name, colour and logo', 'Smoke Test Renamed' in text and '#224466' in text and logo in text and '"locked": true' in text)
        check('public page hides owner controls and sales parts', '"save"' not in text and 'class="sell-bar"' not in text and 'id="offer"' not in text)
        check('logo file is served', call('GET', logo).status == 200)
        check('strangers cannot open the account or owner pages', call('GET', '/my').status == 303 and call('GET', '/owner', cookie=cookie).status == 404)
        data = env.get('QP_DATA', '')
        if os.geteuid() == 0 and data and os.stat(data).st_uid != 0:  # on the server: the service has its own user
            files = [os.path.join(d, f) for d, _, fs in os.walk(data) for f in fs]
            check('nothing in the data folder is owned by root', all(os.stat(f).st_uid != 0 for f in files), [f for f in files if os.stat(f).st_uid == 0])
    finally:
        out = cli('remove', email)
        check('delete the throwaway business', 'Deleted' in out.stdout, out.stdout + out.stderr)
        check('its page is gone', call('GET', '/' + slug).status == 404)
    print(f'\n{sum(done)} of {len(done)} checks passed.')
    return 0 if all(done) else 1


if __name__ == '__main__':
    sys.exit(main())
