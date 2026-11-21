#!/usr/bin/env python3
"""
End-to-end checks of the accounts service over real HTTP, against a throwaway copy on this
machine. Standard library only:  python3 tests/test_app.py
"""
import http.client
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib
from urllib.parse import urlencode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'app', 'server.py')
OWNER = 'owner@example.com'


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def png(width=8, height=4, rgb=(27, 111, 99)):
    """A real, tiny PNG."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body) & 0xffffffff)
    row = b'\x00' + bytes(rgb) * width
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(row * height)) + chunk(b'IEND', b''))


class Site:
    """One running copy of the service with its own data folder."""

    def __init__(self, mail=True, extra=None):
        self.dir = tempfile.mkdtemp(prefix='qp-test-')
        self.port = free_port()
        self.base = f'http://127.0.0.1:{self.port}'
        self.outbox = os.path.join(self.dir, 'outbox.jsonl')
        self.env = dict(os.environ, QP_PORT=str(self.port), QP_BASE_URL=self.base, QP_DATA=os.path.join(self.dir, 'data'),
                        QP_ADMIN_EMAIL=OWNER, QP_SUPPORT_NAME='Sam', QP_SUPPORT_PHONE='0400 000 000', PYTHONDONTWRITEBYTECODE='1')
        for k in ('QP_SMTP_HOST', 'QP_DEV_OUTBOX', 'QP_MAIL_FROM'):
            self.env.pop(k, None)
        if mail:
            self.env['QP_DEV_OUTBOX'] = self.outbox
        self.env.update(extra or {})
        self.log = open(os.path.join(self.dir, 'server.log'), 'w')
        self.proc = subprocess.Popen([sys.executable, SERVER], env=self.env, stderr=self.log, stdout=self.log)
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError('server did not start: ' + open(self.log.name).read())

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)
        self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def db(self):
        c = sqlite3.connect(os.path.join(self.dir, 'data', 'accounts.db'), timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def mails(self):
        for _ in range(40):  # the mail worker runs just after the reply
            time.sleep(0.05)
            if os.path.exists(self.outbox):
                break
        time.sleep(0.1)
        if not os.path.exists(self.outbox):
            return []
        with open(self.outbox) as f:
            return [json.loads(line) for line in f if line.strip()]

    def last_link(self, to):
        found = [m for m in self.mails() if m['to'] == to]
        assert found, f'no email to {to}'
        return re.search(r'/auth#t=([A-Za-z0-9_-]+)', found[-1]['body']).group(1)


class Browser:
    """A very small web client: keeps cookies, never follows redirects on its own."""

    def __init__(self, site, ip='203.0.113.9'):
        self.site, self.ip, self.cookies = site, ip, {}

    def request(self, method, path, body=None, headers=None, origin=True):
        h = {'X-Forwarded-For': self.ip}
        if self.cookies:
            h['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        if method == 'POST':
            if origin:
                h['Origin'] = self.site.base if origin is True else origin
            if isinstance(body, dict):
                body = urlencode(body).encode()
                h['Content-Type'] = 'application/x-www-form-urlencoded'
            body = body if body is not None else b''
        h.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.site.port, timeout=10)
        conn.request(method, path, body=body, headers=h)
        res = conn.getresponse()
        data = res.read()
        for name, value in res.getheaders():
            if name.lower() == 'set-cookie':
                k, _, rest = value.partition('=')
                v = rest.split(';')[0]
                if v:
                    self.cookies[k] = v
                else:
                    self.cookies.pop(k, None)
        conn.close()
        res.text = data.decode('utf-8', 'replace')
        res.data = data
        return res

    def get(self, path, **kw):
        return self.request('GET', path, **kw)

    def post(self, path, body=None, **kw):
        return self.request('POST', path, body, **kw)

    def csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.get('/my').text).group(1)

    def sign_in_with(self, token):
        return self.post('/auth', {'t': token})

    def save(self, settings, **kw):
        headers = {'Content-Type': 'application/json', 'X-CSRF': kw.pop('csrf', None) or self.page_csrf()}
        return self.post('/api/settings', json.dumps({'settings': settings}).encode(), headers=headers, **kw)

    def page_csrf(self):
        slug = re.search(r'href="/([a-z0-9-]+)\?setup"', self.get('/my').text).group(1)
        return json.loads(re.search(r'window\.QUOTE_ACCOUNT = (\{.*?\});', self.get('/' + slug).text).group(1))['csrf']


def page_settings(html):
    return json.loads(re.search(r'^window\.QUOTE_SETTINGS = (\{.*\});$', html, re.M).group(1))


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site()
        b = Browser(cls.site)
        cls.stamp = re.search(r'name="stamp" value="([^"]+)"', b.get('/start').text).group(1)
        time.sleep(2.1)  # the sign-up form refuses anything sent back faster than a person could type
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.site.stop()

    def signup(self, business='Karri Tree Care', mobile='0412 345 678', email=None, extra=None, ip=None):
        Tests.n += 1
        email = email or f'biz{Tests.n}@example.com'
        b = Browser(self.site, ip or f'198.51.100.{Tests.n}')
        form = {'business': business, 'mobile': mobile, 'email': email, 'qp-zx-leave-empty': '', 'stamp': self.stamp, 'settings': ''}
        form.update(extra or {})
        res = b.post('/start', form)
        return b, email, res

    def member(self, business='Karri Tree Care', **kw):
        """Sign up, press the emailed link, and come back signed in."""
        b, email, res = self.signup(business, **kw)
        self.assertEqual(res.status, 200)
        self.assertIn('Check your email', res.text)
        res = b.sign_in_with(self.site.last_link(email))
        self.assertEqual(res.status, 303, res.text)
        slug = res.getheader('Location').split('?')[0].strip('/')
        return b, email, slug

    def owner(self):
        b = Browser(self.site, '192.0.2.200')
        b.post('/signin', {'email': OWNER})
        res = b.sign_in_with(self.site.last_link(OWNER))
        self.assertEqual(res.status, 303)
        return b, res

    # ---- basics

    def test_basics(self):
        b = Browser(self.site)
        self.assertEqual(b.get('/healthz').text, 'ok\n')
        demo = b.get('/')
        self.assertEqual(demo.status, 200)
        self.assertIn('Demo Tree Co', demo.text)
        self.assertIn('href="/start"', demo.text)
        self.assertEqual(json.loads(b.get('/api/open').text), {'signup': True})
        self.assertIn('Disallow: /owner', b.get('/robots.txt').text)
        self.assertEqual(b.get('/nobody-here').status, 404)
        self.assertEqual(b.get('/my').status, 303)
        self.assertEqual(b.get('/owner').status, 303)
        head = b.request('HEAD', '/start')
        self.assertEqual((head.status, head.data), (200, b''))
        self.assertEqual(b.request('PUT', '/start').status, 501)
        start = b.get('/start')
        self.assertIn("frame-ancestors 'none'", start.getheader('Content-Security-Policy'))
        self.assertEqual(start.getheader('X-Content-Type-Options'), 'nosniff')

    def test_signup_checks_what_is_typed(self):
        for form, message in (({'business': 'A'}, 'business name'), ({'mobile': '9388 1234'}, 'mobile number'),
                              ({'email': 'not-an-email'}, 'email address'), ({'email': 'a@b.com\r\nBcc: x@y.com'}, 'email address')):
            b, email, res = self.signup(**form)
            self.assertIn(message, res.text, form)
            self.assertIn('class="err"', res.text)
        before = len(self.site.mails())
        b, email, res = self.signup(extra={'qp-zx-leave-empty': 'http://spam.example'})  # the hidden trap field
        self.assertIn('Check your email', res.text)
        for junk in ('nonsense', '\u00b2.abc', '1.\u00e9', '9' * 40 + '.x', ''):
            b, email, res = self.signup(extra={'stamp': junk})
            self.assertEqual(res.status, 200, junk)
            self.assertIn('open a long time', res.text)
        # sent back within two seconds of being shown: not believed, but never told "check your email" either
        quick = re.search(r'name="stamp" value="([^"]+)"', Browser(self.site).get('/start').text).group(1)
        b, email, res = self.signup(extra={'stamp': quick})
        self.assertIn('Please press the button again', res.text)
        self.assertNotIn('Check your email', res.text)
        self.assertIn(f'value="{quick}"', res.text)  # the clock is not restarted, so the second press goes through
        self.assertEqual(len(self.site.mails()), before)
        # a correction keeps the first clock too, so fixing one field and pressing straight away works
        b, email, res = self.signup(mobile='12')
        self.assertIn(f'value="{self.stamp}"', res.text)
        self.assertEqual(Browser(self.site).post('/start', {'business': 'X Trees'}, origin='https://evil.example').status, 403)

    def test_one_connection_many_people(self):
        # The web server in front reuses one connection for many visitors. Who is signed in must be
        # worked out for each request, never remembered from the request before it.
        b, email, slug = self.member('Shared Line Trees')
        cookie = '; '.join(f'{k}={v}' for k, v in b.cookies.items())
        for order in (('in', 'out', 'in', 'out'), ('out', 'in', 'out', 'out', 'in')):
            conn = http.client.HTTPConnection('127.0.0.1', self.site.port, timeout=10)
            for who in order:
                conn.request('GET', '/' + slug, headers={'Cookie': cookie} if who == 'in' else {})
                res = conn.getresponse()
                text = res.read().decode()
                self.assertEqual('"save"' in text, who == 'in', order)
                self.assertEqual('"locked": true' in text, who == 'out', order)
                conn.request('GET', '/my', headers={'Cookie': cookie} if who == 'in' else {})
                res = conn.getresponse()
                res.read()
                self.assertEqual(res.status, 200 if who == 'in' else 303, order)
            conn.close()

    def test_where_a_form_came_from(self):
        # What real browsers send. A page with a strict referrer policy posts "Origin: null", so the
        # browser's own Sec-Fetch-Site header is what counts when it is there.
        form = {'business': 'Origin Test Trees', 'mobile': '0412 345 678', 'email': 'origin@example.com', 'stamp': self.stamp}
        post = lambda headers, origin: Browser(self.site, '192.0.2.90').post('/start', form, headers=headers, origin=origin).status
        self.assertEqual(post({'Sec-Fetch-Site': 'same-origin'}, 'null'), 200)
        self.assertEqual(post({'Sec-Fetch-Site': 'same-origin'}, False), 200)
        self.assertEqual(post({'Sec-Fetch-Site': 'cross-site'}, True), 403)
        self.assertEqual(post({'Sec-Fetch-Site': 'same-site'}, True), 403)
        self.assertEqual(post({'Sec-Fetch-Site': 'none'}, True), 403)
        self.assertEqual(post({}, 'null'), 403)
        self.assertEqual(post({}, False), 403)
        self.assertEqual(Browser(self.site).get('/start').getheader('Referrer-Policy'), 'same-origin')

    def test_signup_and_one_time_link(self):
        b, email, res = self.signup('Jarrah & Sons Tree Lopping')
        self.assertIn('Check your email', res.text)
        mail = [m for m in self.site.mails() if m['to'] == email][-1]
        self.assertIn('Jarrah & Sons Tree Lopping', mail['body'])
        token = self.site.last_link(email)
        with self.site.db() as db:  # nothing exists until the email address is proven
            self.assertIsNone(db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone())
            stored = [r['hash'] for r in db.execute('SELECT hash FROM tokens')]
            self.assertNotIn(token, stored)  # only a hash of the link is kept
        self.assertIn('Open my page', b.get('/auth').text)  # looking at the page uses nothing up
        self.assertEqual(b.post('/auth', {'t': token}, origin='https://evil.example').status, 403)
        res = b.sign_in_with(token)
        self.assertEqual(res.status, 303)
        self.assertEqual(res.getheader('Location'), '/jarrah-and-sons-tree-lopping?setup')
        self.assertIn('HttpOnly', res.getheader('Set-Cookie'))
        self.assertIn('SameSite=Lax', res.getheader('Set-Cookie'))
        again = Browser(self.site).sign_in_with(token)
        self.assertEqual(again.status, 400)
        self.assertIn('already used', again.text)
        self.assertEqual(Browser(self.site).sign_in_with('x' * 43).status, 400)
        my = b.get('/my')
        self.assertIn('/jarrah-and-sons-tree-lopping', my.text)
        self.assertIn('Free trial', my.text)
        self.assertIn('14 days left', my.text)
        self.assertNotIn('Owner page', my.text)

    def test_pages_for_public_and_owner(self):
        b, email, slug = self.member('Marri Tree Services', mobile='0498 765 432')
        public = Browser(self.site).get('/' + slug)
        self.assertEqual(public.status, 200)
        s = page_settings(public.text)
        self.assertEqual((s['businessName'], s['phone'], s['demo'], s['logo']), ('Marri Tree Services', '0498 765 432', False, ''))
        self.assertEqual(s['prices']['removal']['h10'], 1100)  # starts from the example prices
        self.assertEqual(s['trust'], [])  # and none of the demo's claims
        self.assertIn('window.QUOTE_ACCOUNT = {"locked": true};', public.text)
        self.assertIn('<title>Marri Tree Services: tree quote</title>', public.text)
        self.assertIn('Please call or text 0498 765 432 instead.', public.text)
        for gone in ('<section class="sell-offer"', 'id="offer"', 'class="sell-bar"', 'class="sell-cta"', 'href="/signin"', 'Demo Tree Co', '0491 570 156', 'matthew.carl', 'carl.hogan', '\x00'):
            self.assertNotIn(gone, public.text)
        self.assertIn("form-action 'self'", public.getheader('Content-Security-Policy'))
        self.assertEqual(public.getheader('Cache-Control'), 'no-cache')
        mine = b.get('/' + slug)
        acc = json.loads(re.search(r'window\.QUOTE_ACCOUNT = (\{.*?\});', mine.text).group(1))
        self.assertEqual((acc['save'], acc['logo'], acc['slug']), ('/api/settings', '/api/logo', slug))
        self.assertIn('Edit my page', mine.text)
        self.assertIn('Free trial: 14 days left', mine.text)
        self.assertEqual(mine.getheader('Cache-Control'), 'no-store')
        self.assertEqual(b.get(f'/{slug}/').getheader('Location'), '/' + slug)

    def test_saving_settings(self):
        b, email, slug = self.member('Tuart Trees')
        csrf = b.page_csrf()
        good = page_settings(b.get('/' + slug).text)
        anon = Browser(self.site)
        self.assertEqual(anon.save(good, csrf=csrf).status, 401)
        self.assertEqual(b.save(good, csrf='wrong').status, 403)
        self.assertEqual(b.post('/api/settings', b'{}', headers={'X-CSRF': 'caf\u00e9'.encode('utf-8').decode('latin-1')}).status, 403)
        self.assertEqual(b.save(good, csrf=csrf, origin='https://evil.example').status, 403)
        self.assertEqual(b.post('/api/settings', b'{"settings": 5}', headers={'X-CSRF': csrf}).status, 400)
        self.assertEqual(b.post('/api/settings', b'x' * 70000, headers={'X-CSRF': csrf}).status, 413)
        nasty = dict(good, businessName='</script><script>alert(1)</script>', colour='red; background:url(x)', phone='0412 345 678',
                     email='jobs@tuart.example', logo='https://evil.example/pixel.png', demo=True, extra={'a': 1},
                     trust=['One', '<b>Two</b>', '', 'Three', 'Four', 'Five'], promises={'insured': True, 'bogus': True, 'cleanUp': 'yes'})
        nasty['prices'] = dict(good['prices'], removal={'h4': '$1,250', 'h6': -5, 'h10': 1e12, 'h15': 'abc', 'zzz': 9}, range=99, minimumJob=None)
        res = b.save(nasty, csrf=csrf)
        self.assertEqual((res.status, json.loads(res.text)), (200, {'ok': True}))
        html = Browser(self.site).get('/' + slug).text
        self.assertNotIn('<script>alert(1)', html)
        self.assertIn('\\u003c/script\\u003e\\u003cscript\\u003ealert(1)', html)
        s = page_settings(html)
        self.assertEqual(s['businessName'], '</script><script>alert(1)</script>')
        self.assertEqual((s['colour'], s['logo'], s['demo'], s['email']), ('#1b6f63', '', False, 'jobs@tuart.example'))
        self.assertNotIn('extra', s)
        self.assertEqual(s['trust'], ['One', '<b>Two</b>', 'Three', 'Four'])
        self.assertEqual(s['promises'], {'freeQuote': False, 'cleanUp': False, 'freeSiteVisit': False, 'fixedPriceBeforeWork': False, 'insured': True, 'as4373': False})
        self.assertEqual(s['prices']['removal'], {'h4': 1250, 'h6': 0, 'h10': 100000, 'h15': 0, 'h20': 0, 'h20p': 0})
        self.assertEqual((s['prices']['range'], s['prices']['minimumJob']), (40, 0))
        self.assertIn('&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;: tree quote</title>', html)
        self.assertEqual(b.save(dict(good, businessName=''), csrf=csrf).status, 400)
        self.assertEqual(b.save(dict(good, email='nope'), csrf=csrf).status, 400)

    def test_one_business_cannot_touch_another(self):
        a, _, slug_a = self.member('Peppermint Tree Co')
        b, _, slug_b = self.member('Banksia Arbor')
        sa = page_settings(a.get('/' + slug_a).text)
        res = b.save(dict(sa, businessName='Hijacked'))  # b's own sign-in can only ever write b's page
        self.assertEqual(res.status, 200)
        self.assertEqual(page_settings(Browser(self.site).get('/' + slug_a).text)['businessName'], 'Peppermint Tree Co')
        self.assertEqual(page_settings(Browser(self.site).get('/' + slug_b).text)['businessName'], 'Hijacked')
        csrf_a = a.page_csrf()
        self.assertEqual(b.save(sa, csrf=csrf_a).status, 403)  # another person's token is no use
        self.assertNotIn('"save"', b.get('/' + slug_a).text)
        self.assertEqual(b.get('/owner').status, 404)
        self.assertEqual(b.post('/owner/act', {'id': '1', 'action': 'paid', 'csrf': b.csrf()}).status, 404)

    def test_logo(self):
        b, email, slug = self.member('Wandoo Tree Works')
        csrf = b.page_csrf()
        up = lambda data, **kw: b.post('/api/logo', data, headers={'Content-Type': 'image/png', 'X-CSRF': kw.pop('csrf', csrf)}, **kw)
        self.assertEqual(Browser(self.site).post('/api/logo', png(), headers={'X-CSRF': csrf}).status, 401)
        self.assertEqual(up(png(), csrf='bad').status, 403)
        self.assertEqual(up(b'<html><script>alert(1)</script></html>').status, 400)
        self.assertEqual(up(b'<svg xmlns="http://www.w3.org/2000/svg"/>').status, 400)
        self.assertEqual(up(png() + b'\x00' * 600000).status, 413)
        res = up(png())
        self.assertEqual(res.status, 200)
        first = json.loads(res.text)['logo']
        self.assertRegex(first, r'^/logo/[a-f0-9]{24}\.png$')
        got = Browser(self.site).get(first)
        self.assertEqual((got.status, got.getheader('Content-Type'), got.data), (200, 'image/png', png()))
        self.assertEqual(got.getheader('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(page_settings(Browser(self.site).get('/' + slug).text)['logo'], first)
        second = json.loads(up(b'\xff\xd8\xff\xe0' + b'0' * 64).text)['logo']
        self.assertTrue(second.endswith('.jpg'))
        self.assertEqual(Browser(self.site).get(first).status, 404)  # the old file is cleaned up
        self.assertEqual(Browser(self.site).get('/logo/../accounts.db').status, 404)
        self.assertEqual(Browser(self.site).get('/logo/' + 'a' * 24 + '.png').status, 404)
        res = b.post('/api/logo/remove', b'', headers={'X-CSRF': csrf})
        self.assertEqual(json.loads(res.text), {'ok': True, 'logo': ''})
        self.assertEqual(Browser(self.site).get(second).status, 404)
        self.assertEqual(page_settings(Browser(self.site).get('/' + slug).text)['logo'], '')

    def test_signin_again_and_limits(self):
        b, email, slug = self.member('Sheoak Stump Grinding')
        fresh = Browser(self.site, '192.0.2.50')
        before = len(self.site.mails())
        plain = lambda t: re.sub(r'nonce="[^"]+"', '', t)
        res = fresh.post('/signin', {'email': 'stranger@example.com'})
        same = plain(res.text)
        self.assertIn('Check your email', same)
        self.assertEqual(len(self.site.mails()), before)  # no email, but the same answer
        res = fresh.post('/signin', {'email': email.upper()})
        self.assertEqual(plain(res.text).replace(email, 'stranger@example.com'), same)
        self.assertEqual(fresh.sign_in_with(self.site.last_link(email)).getheader('Location'), '/my')
        self.assertIn(slug, fresh.get('/my').text)
        self.assertEqual(fresh.get('/signin').getheader('Location'), '/my')
        count = lambda: len([m for m in self.site.mails() if m['to'] == email])
        for _ in range(5):
            Browser(self.site, '192.0.2.51').post('/signin', {'email': email})
        self.assertEqual(count(), 3)  # sign-up, one sign-in, one more: then the 15-minute cap on one inbox
        # signing up again with an address that already has a page just sends a sign-in link
        with self.site.db() as db:
            db.execute('DELETE FROM hits')
        _, _, res = self.signup('Someone Else', email=email)
        self.assertIn('Check your email', res.text)
        self.assertIn('sign in', [m for m in self.site.mails() if m['to'] == email][-1]['body'])
        # one address can only start so many sign-ups an hour
        statuses = [self.signup(ip='192.0.2.77')[2].status for _ in range(8)]
        self.assertEqual(statuses[:6], [200] * 6)
        self.assertEqual(statuses[6:], [429, 429])

    def test_sign_out_and_delete(self):
        b, email, slug = self.member('Zamia Tree Fellers')
        csrf = b.csrf()
        self.assertEqual(b.post('/signout', {'csrf': 'wrong'}).status, 403)
        cookie = dict(b.cookies)
        out = b.post('/signout', {'csrf': csrf})
        self.assertEqual((out.status, out.getheader('Location')), (303, '/signin'))
        self.assertEqual(b.cookies, {})
        b.cookies = cookie
        self.assertEqual(b.get('/my').status, 303)  # the old cookie is dead on the server too
        b.post('/signin', {'email': email})
        b.sign_in_with(self.site.last_link(email))
        self.assertIn('can\'t be undone', b.get('/my/delete').text)
        self.assertEqual(b.post('/my/delete', {'csrf': 'wrong'}).status, 403)
        self.assertEqual(Browser(self.site).get('/' + slug).status, 200)
        res = b.post('/my/delete', {'csrf': b.csrf()})
        self.assertIn('Your page is deleted', res.text)
        self.assertEqual(Browser(self.site).get('/' + slug).status, 404)
        with self.site.db() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone())
            self.assertIsNone(db.execute('SELECT 1 FROM sessions WHERE email=?', (email,)).fetchone())

    def test_names_and_carried_settings(self):
        _, _, one = self.member('Coastal Trees')
        _, _, two = self.member('Coastal Trees')
        _, _, three = self.member('Start')
        _, _, four = self.member('Öl & Ästhetik 99!')
        self.assertEqual((one, two, three, four), ('coastal-trees', 'coastal-trees-2', 'tree-page', 'l-and-sthetik-99'))
        demo = page_settings(Browser(self.site).get('/').text.replace('window.QUOTE_SETTINGS_BACKUP', 'window.QUOTE_SETTINGS'))
        typed = dict(demo, showPrices=False)
        typed['prices'] = dict(demo['prices'], minimumJob=333)
        b, email, slug = self.member('Carried Over Trees', extra={'settings': json.dumps(typed)})
        s = page_settings(Browser(self.site).get('/' + slug).text)
        self.assertEqual((s['businessName'], s['showPrices'], s['prices']['minimumJob']), ('Carried Over Trees', False, 333))
        self.assertEqual((s['trust'], s['baseSuburb'], s['demo']), ([], '', False))  # the demo's own claims and suburb stay behind
        _, _, slug = self.member('Broken Carry', extra={'settings': '{not json'})
        self.assertEqual(page_settings(Browser(self.site).get('/' + slug).text)['prices']['minimumJob'], 280)

    def test_owner_page(self):
        b, email, slug = self.member('Yate Tree Surgeons', mobile='0455 111 222')
        logo = json.loads(b.post('/api/logo', png(), headers={'X-CSRF': b.page_csrf()}).text)['logo']
        o, res = self.owner()
        self.assertEqual(res.getheader('Location'), '/owner')
        page = o.get('/owner')
        self.assertIn('Yate Tree Surgeons', page.text)
        self.assertIn(email, page.text)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        acc_id = re.search(r'/owner/delete\?id=(\d+)', page.text[page.text.index('Yate Tree Surgeons'):]).group(1)
        act = lambda action, **kw: o.post('/owner/act' + kw.pop('q', ''), dict({'csrf': csrf, 'id': acc_id, 'action': action}, **kw))
        public = lambda: Browser(self.site).get('/' + slug)
        self.assertEqual(o.post('/owner/act', {'csrf': 'wrong', 'id': acc_id, 'action': 'off'}).status, 403)
        self.assertEqual(act('off').status, 303)
        off = public()
        self.assertEqual(off.status, 200)
        self.assertIn('Online quotes are not available here right now', off.text)
        self.assertIn('href="tel:0455111222"', off.text)
        self.assertNotIn('QUOTE_SETTINGS', off.text)
        self.assertIn('Only you see this', b.get('/' + slug).text)
        self.assertIn('Not active', b.get('/my').text)
        act('paid')
        self.assertTrue(page_settings(public().text)['showPrices'])
        self.assertIn('This is your live page', b.get('/' + slug).text)
        act('plan-catcher')
        self.assertFalse(page_settings(public().text)['showPrices'])  # Job catcher never shows prices
        self.assertIn('Job catcher', b.get('/my').text)
        act('plan-instant')
        act('trial')
        self.assertIn('Free trial', b.get('/my').text)
        with self.site.db() as db:  # a trial that has run out
            db.execute('UPDATE accounts SET trial_ends=? WHERE id=?', (int(time.time()) - 60, acc_id))
        self.assertIn('Online quotes are not available', public().text)
        self.assertIn('Your free trial has ended', b.get('/' + slug).text)
        self.assertIn('Trial ended', o.get('/owner').text)
        act('extend')
        self.assertIn('QUOTE_SETTINGS', public().text)
        self.assertIn('14 days left', b.get('/my').text)
        res = act('link')
        token = re.search(r'/auth#t=([A-Za-z0-9_-]+)', res.text).group(1)
        helper = Browser(self.site)
        self.assertEqual(helper.sign_in_with(token).getheader('Location'), '/my')
        self.assertIn(slug, helper.get('/my').text)
        # the owner makes a page for someone who texted instead of signing up
        add = lambda **kw: o.post('/owner/add', dict({'csrf': csrf, 'business': 'Texted In Trees', 'mobile': '0477 000 111', 'email': 'texted@example.com'}, **kw))
        self.assertIn('not an Australian mobile', add(mobile='12345').text)
        self.assertIn('already has a page', add(email=email).text)
        self.assertEqual(add(csrf='wrong').status, 403)
        self.assertEqual(b.post('/owner/add', {'csrf': b.csrf(), 'business': 'X Trees', 'mobile': '0477 000 111', 'email': 'x@example.com'}).status, 404)
        made = add()
        self.assertIn('Page made: /texted-in-trees', made.text)
        newcomer = Browser(self.site)
        res = newcomer.sign_in_with(re.search(r'/auth#t=([A-Za-z0-9_-]+)', made.text).group(1))
        self.assertEqual(res.getheader('Location'), '/my')
        self.assertIn('texted-in-trees', newcomer.get('/my').text)
        self.assertEqual(page_settings(Browser(self.site).get('/texted-in-trees').text)['phone'], '0477 000 111')
        self.assertIn("can't be undone", o.get('/owner/delete?id=' + acc_id).text)
        self.assertEqual(act('', q='?do=delete').status, 303)
        self.assertEqual(public().status, 404)
        self.assertEqual(Browser(self.site).get(logo).status, 404)
        self.assertEqual(helper.get('/my').status, 303)

    def test_command_line_link(self):
        b, email, slug = self.member('Command Line Trees')
        out = subprocess.run([sys.executable, SERVER, 'link', email], env=self.site.env, capture_output=True, text=True)
        token = re.search(r'/auth#t=([A-Za-z0-9_-]+)', out.stdout).group(1)
        self.assertEqual(Browser(self.site).sign_in_with(token).getheader('Location'), '/my')
        out = subprocess.run([sys.executable, SERVER, 'link', 'nobody@example.com'], env=self.site.env, capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)
        run = lambda *a: subprocess.run([sys.executable, SERVER, *a], env=self.site.env, capture_output=True, text=True)
        out = run('add', 'cli@example.com', '0411 222 333', 'Command', 'Made', 'Trees')
        self.assertIn('/command-made-trees', out.stdout)
        token = re.search(r'/auth#t=([A-Za-z0-9_-]+)', out.stdout).group(1)
        self.assertEqual(Browser(self.site).sign_in_with(token).getheader('Location'), '/my')
        self.assertNotEqual(run('add', 'cli@example.com', '0411 222 333', 'Twice').returncode, 0)
        self.assertNotEqual(run('add', 'bad@example.com', '555', 'Bad Mobile').returncode, 0)
        self.assertIn('Deleted /command-made-trees', run('remove', 'cli@example.com').stdout)
        self.assertEqual(Browser(self.site).get('/command-made-trees').status, 404)


class MailOff(unittest.TestCase):
    def test_no_mail_means_no_dead_ends(self):
        site = Site(mail=False)
        try:
            b = Browser(site)
            start = b.get('/start').text
            self.assertEqual(json.loads(b.get('/api/open').text), {'signup': False})
            self.assertIn('Online sign-up opens soon', start)
            self.assertIn('0400 000 000', start)
            self.assertNotIn('<form', start)
            self.assertIn('not switched on yet', b.get('/signin').text)
            self.assertIn('opens soon', b.post('/start', {'business': 'A Trees', 'mobile': '0412345678', 'email': 'a@example.com'}).text)
            self.assertIn('not switched on yet', b.post('/signin', {'email': 'a@example.com'}).text)
            with site.db() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM tokens').fetchone()[0], 0)
            # the owner can still get in from the server's command line
            out = subprocess.run([sys.executable, SERVER, 'link', OWNER], env=site.env, capture_output=True, text=True)
            token = re.search(r'/auth#t=([A-Za-z0-9_-]+)', out.stdout).group(1)
            self.assertEqual(b.sign_in_with(token).getheader('Location'), '/owner')
            self.assertIn('Sign-up and sign-in emails can', b.get('/owner').text)
        finally:
            site.stop()


if __name__ == '__main__':
    unittest.main(verbosity=2)
