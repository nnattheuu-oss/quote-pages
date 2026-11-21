#!/usr/bin/env python3
"""
Accounts for the tree quote page.

Each business signs up with an email address, gets a one-time sign-in link by email (no
passwords), and owns one page at <site>/<their-name> with its own logo, colour and prices.
The page itself is ../index.html: this program fills in that business's settings and serves it.

Python standard library only. Runs behind a web server (Caddy) on a loopback port.

  server.py                 run the service
  server.py link EMAIL      print a one-time sign-in link for an existing account or the owner
  server.py add EMAIL MOBILE BUSINESS NAME   make a page for a business and print its sign-in link
  server.py remove EMAIL    delete that business's page, settings and logo
  server.py testmail EMAIL  send a test email with the mail settings in the environment
"""
import hashlib
import hmac
import html
import json
import math
import os
import queue
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))


def env(name, default=''):
    return os.environ.get(name, default).strip()


HOST = env('QP_HOST', '127.0.0.1')
PORT = int(env('QP_PORT', '7871'))
BASE_URL = env('QP_BASE_URL', f'http://127.0.0.1:{PORT}').rstrip('/')
DATA = env('QP_DATA', os.path.join(HERE, '..', 'data'))
TEMPLATE = env('QP_TEMPLATE', os.path.join(HERE, '..', 'index.html'))
SITE_NAME = env('QP_SITE_NAME', 'Tree Job Quote')
ADMIN_EMAIL = env('QP_ADMIN_EMAIL').lower()
SUPPORT_NAME = env('QP_SUPPORT_NAME')
SUPPORT_PHONE = env('QP_SUPPORT_PHONE')
TRIAL_DAYS = int(env('QP_TRIAL_DAYS', '14'))
SMTP_HOST = env('QP_SMTP_HOST')
SMTP_PORT = int(env('QP_SMTP_PORT', '465'))
SMTP_USER = env('QP_SMTP_USER')
SMTP_PASS = os.environ.get('QP_SMTP_PASS', '')
SMTP_SECURITY = env('QP_SMTP_SECURITY', 'ssl').lower()  # ssl | starttls
MAIL_FROM = env('QP_MAIL_FROM')
DEV_OUTBOX = env('QP_DEV_OUTBOX')  # tests only: write emails to this file instead of sending them

SECURE = BASE_URL.startswith('https://')
COOKIE = '__Host-qp' if SECURE else 'qp'
LOGOS = os.path.join(DATA, 'logos')
DB_PATH = os.path.join(DATA, 'accounts.db')

TOKEN_MINUTES = 30
HANDED_LINK_HOURS = 72  # a link the owner makes to text to someone lasts longer than an emailed one
SESSION_DAYS = 60
MAX_FORM = 64 * 1024
MAX_LOGO = 500 * 1024

RESERVED = {
    'start', 'signin', 'signout', 'signup', 'login', 'logout', 'auth', 'my', 'me', 'owner', 'admin', 'api',
    'logo', 'logos', 'static', 'assets', 'healthz', 'www', 'app', 'deploy', 'tests', 'data', 'index',
    'robots', 'favicon', 'demo', 'help', 'support', 'about', 'terms', 'privacy', 'pricing', 'new', 'edit',
}

now = lambda: int(time.time())
e = lambda s: html.escape(str(s), quote=True)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()


def log(*parts):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *parts, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  settings TEXT NOT NULL,
  logo TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'trial',
  plan TEXT NOT NULL DEFAULT 'instant',
  created INTEGER NOT NULL,
  trial_ends INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens(
  hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '',
  expires INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  csrf TEXT NOT NULL,
  expires INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hits(key TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS hits_key ON hits(key, ts);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class DB:
    """One short-lived connection per use. `with DB() as db:` commits on success."""

    def __enter__(self):
        self.c = sqlite3.connect(DB_PATH, timeout=15)
        self.c.row_factory = sqlite3.Row
        self.c.execute('PRAGMA foreign_keys=ON')
        return self.c

    def __exit__(self, kind, value, tb):
        try:
            if kind is None:
                self.c.commit()
            else:
                self.c.rollback()
        finally:
            self.c.close()


def init_db():
    os.makedirs(LOGOS, mode=0o750, exist_ok=True)
    with DB() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        if not db.execute("SELECT 1 FROM meta WHERE key='secret'").fetchone():
            db.execute("INSERT INTO meta(key, value) VALUES('secret', ?)", (secrets.token_hex(32),))
    try:
        os.chmod(DB_PATH, 0o640)
    except OSError:
        pass


_secret = None


def secret():
    global _secret
    if _secret is None:
        with DB() as db:
            _secret = db.execute("SELECT value FROM meta WHERE key='secret'").fetchone()[0].encode()
    return _secret


def sign(text):
    return hmac.new(secret(), text.encode(), hashlib.sha256).hexdigest()[:32]


def same(a, b):
    """Compare two secrets without leaking, by timing, how much of a guess was right."""
    return hmac.compare_digest(str(a).encode('utf-8', 'replace'), str(b).encode('utf-8', 'replace'))


def limited(db, key, window, most):
    """Count one try against `key`. True if that is more than `most` in the last `window` seconds."""
    t = now()
    n = db.execute('SELECT COUNT(*) FROM hits WHERE key=? AND ts>?', (key, t - window)).fetchone()[0]
    if n >= most:
        return True
    db.execute('INSERT INTO hits(key, ts) VALUES(?, ?)', (key, t))
    return False


def tidy():
    t = now()
    with DB() as db:
        db.execute('DELETE FROM tokens WHERE expires<?', (t,))
        db.execute('DELETE FROM sessions WHERE expires<?', (t,))
        db.execute('DELETE FROM hits WHERE ts<?', (t - 2 * 86400,))


# ---------------------------------------------------------------- settings

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,180}\.[A-Za-z]{2,24}$')
COLOUR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f  ]+')


def text(v, most=200):
    if v is None or isinstance(v, (dict, list, bool)):
        return ''
    return CONTROL_RE.sub(' ', str(v)).strip()[:most]


def number(v, fallback, low, high):
    if isinstance(v, bool):
        return fallback
    if isinstance(v, (int, float)):
        n = float(v)
    else:
        try:
            n = float(re.sub(r'[$,\s%]', '', str(v if v is not None else '')))
        except ValueError:
            return fallback
    if not math.isfinite(n):
        return fallback
    n = min(high, max(low, n))
    return int(n) if n == int(n) else round(n, 2)


def mobile(v):
    n = re.sub(r'[^\d+]', '', str(v or '').replace('(0)', ''))
    return n if re.match(r'^(\+?61|0)4\d{8}$', n) else ''


def valid_email(v):
    v = str(v or '').strip().lower()
    return v if len(v) <= 120 and EMAIL_RE.match(v) and '..' not in v else ''


def normalise(raw, defaults):
    """The same cleaning the page does (normalise in quote-core.js), so nothing odd is ever stored."""
    raw = raw if isinstance(raw, dict) else {}
    p = raw.get('prices') if isinstance(raw.get('prices'), dict) else {}
    t = p.get('travel') if isinstance(p.get('travel'), dict) else {}
    d = defaults['prices']

    def table(src, keys, low, high):
        src = src if isinstance(src, dict) else {}
        return {k: number(src.get(k), 0, low, high) for k in keys}

    colour = text(raw.get('colour'))
    promises = raw.get('promises') if isinstance(raw.get('promises'), dict) else {}
    trust = raw.get('trust') if isinstance(raw.get('trust'), list) else []
    return {
        'businessName': text(raw.get('businessName'), 60),
        'phone': text(raw.get('phone'), 24),
        'email': text(raw.get('email'), 120),
        'baseSuburb': text(raw.get('baseSuburb'), 60),
        'logo': '',  # set from the account's uploaded logo when the page is served
        'colour': colour.lower() if COLOUR_RE.match(colour) else '#1b6f63',
        'textJobsTo': text(raw.get('textJobsTo'), 24),
        'emailKey': text(raw.get('emailKey'), 80),
        'showPrices': raw.get('showPrices') is not False,
        'prices': {
            'removal': table(p.get('removal'), d['removal'].keys(), 0, 100000),
            'stump': table(p.get('stump'), d['stump'].keys(), 0, 100000),
            'pruneStandard': number(p.get('pruneStandard'), 0, 0, 100000),
            'hedgePerMetre': table(p.get('hedgePerMetre'), d['hedgePerMetre'].keys(), 0, 5000),
            'cablePerLimb': number(p.get('cablePerLimb'), 0, 0, 100000),
            'minimumJob': number(p.get('minimumJob'), 0, 0, 100000),
            'range': number(p.get('range'), 12, 0, 40),
            'includesGst': p.get('includesGst') is not False,
            'travel': {
                'freeKm': number(t.get('freeKm'), 0, 0, 2000),
                'perKm': number(t.get('perKm'), 0, 0, 100),
                'maxKm': number(t.get('maxKm'), 120, 1, 5000),
            },
            'adjust': table(p.get('adjust'), d['adjust'].keys(), -90, 500),
        },
        'promises': {k: promises.get(k) is True for k in defaults['promises'].keys()},
        'trust': [x for x in (text(x, 40) for x in trust) if x][:4],
        'demo': False,
    }


def script_json(obj):
    """JSON that is safe to place inside a <script> block."""
    return json.dumps(obj, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')


def slugify(name):
    s = re.sub(r'[^a-z0-9]+', '-', str(name).lower().replace('&', ' and ').replace("'", '')).strip('-')[:40].strip('-')
    if len(s) < 3 or s in RESERVED or s.isdigit():
        s = (s + '-trees').strip('-') if s and not s.isdigit() and s not in RESERVED else 'tree-page'
    return s


def free_slug(db, name):
    base = slugify(name)
    slug, n = base, 1
    while slug in RESERVED or db.execute('SELECT 1 FROM accounts WHERE slug=?', (slug,)).fetchone():
        n += 1
        slug = f'{base[:36]}-{n}'
    return slug


# ---------------------------------------------------------------- the page template

class Template:
    """index.html, cut up once so a business's settings can be dropped in."""

    def __init__(self, path):
        with open(path, encoding='utf-8') as f:
            src = f.read()
        self.demo = src.encode()
        m = re.search(r'^window\.QUOTE_SETTINGS_BACKUP = (\{.*\});$', src, re.M)
        if not m:
            raise SystemExit('index.html: the settings backup line is missing')
        self.defaults = json.loads(m.group(1))

        def cut(pattern, key, flags=re.S):
            nonlocal src
            src, n = re.subn(pattern, lambda _m: f'\x00{key}\x00', src, count=1, flags=flags)
            if n != 1:
                raise SystemExit(f'index.html: could not find the {key} part')

        cut(r'<title>[^<]*</title>', 'HEAD')
        cut(r'<aside class="sell-bar".*?</aside>\n?', 'TOPBAR')
        cut(r'<noscript>.*?</noscript>', 'NOSCRIPT')
        cut(r'<script>\s*/\* settings\.js \*/.*?</script>', 'SETTINGS')
        cut(r'^window\.QUOTE_SETTINGS_BACKUP = \{.*\};$', 'BACKUP', re.M)
        cut(r'<section class="sell-offer".*?</section>\n?', 'OFFER')
        self.parts = src

    def render(self, values):
        return re.sub('\x00([A-Z]+)\x00', lambda m: values[m.group(1)], self.parts).encode()


TPL = None

PAGE_CSP = ("default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https://api.web3forms.com; "
            "base-uri 'none'; form-action 'self'; object-src 'none'")


def page_settings(acc):
    s = json.loads(acc['settings'])
    s['logo'] = f"/logo/{acc['logo']}" if acc['logo'] else ''
    s['demo'] = False
    if acc['status'] == 'paid' and acc['plan'] == 'catcher':
        s['showPrices'] = False
    return s


def is_active(acc):
    return acc['status'] == 'paid' or (acc['status'] == 'trial' and now() < acc['trial_ends'])


def days_left(acc):
    return max(0, math.ceil((acc['trial_ends'] - now()) / 86400))


def support_line(lead='call or text'):
    if SUPPORT_PHONE:
        who = f'{e(SUPPORT_NAME)} on ' if SUPPORT_NAME else ''
        return f'{lead} {who}<a href="tel:{e(re.sub(r"[^0-9+]", "", SUPPORT_PHONE))}">{e(SUPPORT_PHONE)}</a>'
    return f'{lead} us'


def render_business_page(acc, session):
    s = page_settings(acc)
    mine = bool(session and session['email'] == acc['email'])
    name = s['businessName'] or 'Tree quote'
    if mine:
        account = {'save': '/api/settings', 'logo': '/api/logo', 'csrf': session['csrf'], 'slug': acc['slug'],
                   'url': f"{BASE_URL.split('//')[-1]}/{acc['slug']}"}
        if acc['status'] == 'paid':
            note = 'This is your live page. Only you see this bar.'
        else:
            n = days_left(acc)
            note = f"Free trial: {n} day{'' if n == 1 else 's'} left. To keep your page, {support_line()}."
        topbar = ('<aside class="sell-bar" aria-label="Your page"><div class="sell-bar-inner">'
                  f'<p><b>Your page</b>{note}</p><div class="sell-bar-btns">'
                  '<button type="button" id="sell-prices">Edit my page</button>'
                  '<button type="button" class="sell-quiet" onclick="location.href=\'/my\'">My account</button>'
                  '</div></div></aside>\n')
    else:
        account = {'locked': True}
        topbar = ''
    phone = s['phone']
    noscript = ('<noscript><div class="qw-fallback"><strong>This page needs JavaScript.</strong> '
                + (f'Please call or text {e(phone)} instead.' if phone else 'Please call us instead.') + '</div></noscript>')
    blob = script_json(s)
    return TPL.render({
        'HEAD': f'<title>{e(name)}: tree quote</title>',
        'TOPBAR': topbar,
        'NOSCRIPT': noscript,
        'SETTINGS': f'<script>\nwindow.QUOTE_SETTINGS = {blob};\nwindow.QUOTE_ACCOUNT = {script_json(account)};\n</script>',
        'BACKUP': f'window.QUOTE_SETTINGS_BACKUP = {blob};',
        'OFFER': '',
    }), mine


# ---------------------------------------------------------------- small pages

SHELL_CSS = """
:root{--green:#1b6f63;--deep:#145449;--ink:#1f2a2e;--muted:#5a676b;--line:#c3cfcb;--cream:#f6f8f7;--bad:#b3261e;--gold:#f0c98a}
*{box-sizing:border-box}
body{margin:0;font:17px/1.5 'Nunito Sans','Avenir','Segoe UI',system-ui,-apple-system,sans-serif;color:var(--ink);background:var(--cream)}
.top{background:var(--ink);padding:14px 16px}
.top a{color:#fff;text-decoration:none;font-weight:700;letter-spacing:.04em}
main{max-width:640px;margin:0 auto;padding:22px 16px 48px;display:grid;gap:16px}
.wide main{max-width:1100px}
h1{font-size:1.7rem;line-height:1.15;margin:6px 0 0}
h2{font-size:1.15rem;margin:0}
p{margin:0}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:18px;display:grid;gap:12px}
label{display:grid;gap:4px;font-weight:700;font-size:.95rem}
label small{font-weight:400;color:var(--muted)}
input[type=text],input[type=email],input[type=tel]{font:inherit;padding:12px;border:2px solid var(--line);border-radius:6px;background:var(--cream);width:100%}
input:focus-visible,button:focus-visible,a:focus-visible,select:focus-visible{outline:3px solid #1f6feb;outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:50px;padding:10px 20px;border-radius:6px;border:2px solid var(--deep);background:var(--deep);color:#fff;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}
.btn.quiet{background:#fff;color:var(--deep)}
.btn.bad{background:#fff;color:var(--bad);border-color:var(--bad)}
.btn.small{min-height:36px;padding:4px 10px;font-size:.85rem}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.note{color:var(--muted);font-size:.94rem}
.err{color:var(--bad);font-weight:700}
.ok{color:var(--deep);font-weight:700}
.link{font-weight:700;overflow-wrap:anywhere;color:var(--deep)}
.hp{position:absolute;left:-6000px;width:1px;height:1px;overflow:hidden}
code{background:var(--cream);padding:2px 6px;border-radius:4px;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.biz{display:grid;gap:6px;padding:14px 0;border-top:1px solid var(--line)}
.biz:first-of-type{border-top:0;padding-top:0}
.biz-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.biz .row{gap:6px;margin-top:4px}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-weight:700;font-size:.8rem;background:#e1f0ed;color:var(--deep)}
.pill.off{background:#f6dedc;color:var(--bad)}
.pill.trial{background:#fbefd9;color:#8a4b12}
form.inline{display:inline}
"""


def shell(title, body, nonce, wide=False, bare=False):
    top = '' if bare else f'<header class="top"><a href="/">{e(SITE_NAME)}</a></header>'
    return (f'<!DOCTYPE html>\n<html lang="en-AU"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex"><title>{e(title)}</title>'
            f'<style nonce="{nonce}">{SHELL_CSS}</style></head>'
            f'<body class="{"wide" if wide else ""}">{top}'
            f'<main>{body}</main></body></html>').encode()


def mail_on():
    return bool(DEV_OUTBOX or (SMTP_HOST and MAIL_FROM))


def no_mail_card():
    return (f'<div class="card"><h2>Online sign-up opens soon</h2>'
            f'<p>For now, {support_line("text")} with your business name and mobile number, and you will be sent your own page to try.</p></div>')


def start_page(nonce, values=None, error='', stamp=''):
    v = values or {}
    if not stamp:  # when the form was first shown; kept through any corrections
        t = str(now())
        stamp = f"{t}.{sign('start.' + t)}"
    if not mail_on():
        form = no_mail_card()
    else:
        form = f"""<form class="card" method="post" action="/start" id="f" novalidate>
{f'<p class="err" role="alert">{e(error)}</p>' if error else ''}
<label>Business name<input type="text" name="business" id="business" maxlength="60" autocomplete="organization" required value="{e(v.get('business', ''))}"></label>
<label>Mobile number <small>jobs are texted here</small><input type="tel" name="mobile" id="mobile" maxlength="24" inputmode="tel" autocomplete="tel" placeholder="0412 345 678" required value="{e(v.get('mobile', ''))}"></label>
<label>Email <small>your sign-in link is sent here. No password needed</small><input type="email" name="email" maxlength="120" autocomplete="email" autocapitalize="off" required value="{e(v.get('email', ''))}"></label>
<div class="hp" aria-hidden="true"><label>Leave this empty<input type="text" name="qp-zx-leave-empty" tabindex="-1" autocomplete="off"></label></div>
<input type="hidden" name="stamp" value="{e(stamp)}">
<input type="hidden" name="settings" id="settings" value="{e(v.get('settings', ''))}">
<p class="note" id="carry" hidden>The prices you put in on the demo come with you.</p>
<button class="btn" type="submit">Make my page</button>
<p class="note">Free to try for {TRIAL_DAYS} days. No card needed. Keep it and pay, or walk away and owe nothing. <a href="/#offer">What it costs</a>.</p>
<p class="note">Your email is only used to sign you in and to contact you about your page.</p>
</form>
<script nonce="{nonce}">
(function () {{
  try {{
    var raw = sessionStorage.getItem('qp-start') || document.getElementById('settings').value;
    if (!raw) return;
    var s = JSON.parse(raw);
    document.getElementById('settings').value = raw;
    document.getElementById('carry').hidden = false;
    var b = document.getElementById('business'), m = document.getElementById('mobile');
    if (!b.value && s.businessName && s.businessName !== 'Demo Tree Co') b.value = s.businessName;
    if (!m.value && s.phone && s.phone !== '0491 570 156') m.value = s.phone;
  }} catch (err) {{}}
}})();
</script>"""
    body = f"""<h1>Make your own quote page</h1>
<p>Your own page with your name, logo, colour and prices, at <span class="link">{e(BASE_URL.split('//')[-1])}/your-business</span>.</p>
{form}
<p class="note">Already have a page? <a href="/signin">Sign in</a>.</p>"""
    return shell(f'Make your page: {SITE_NAME}', body, nonce)


def signin_page(nonce, error='', value=''):
    if not mail_on():
        form = (f'<div class="card"><h2>Sign-in emails are not switched on yet</h2>'
                f'<p>To get into your page, {support_line("text")}.</p></div>')
    else:
        form = f"""<form class="card" method="post" action="/signin" novalidate>
{f'<p class="err" role="alert">{e(error)}</p>' if error else ''}
<label>Email <small>the one you signed up with</small><input type="email" name="email" maxlength="120" autocomplete="email" autocapitalize="off" required value="{e(value)}"></label>
<button class="btn" type="submit">Email me a sign-in link</button>
<p class="note">No password. The link works once and lasts {TOKEN_MINUTES} minutes.</p>
</form>"""
    body = f"""<h1>Sign in</h1>{form}<p class="note">No page yet? <a href="/start">Make one</a>.</p>"""
    return shell(f'Sign in: {SITE_NAME}', body, nonce)


def sent_page(nonce, email, new=False):
    if new:
        lead = f'<p>A link is on its way to <strong>{e(email)}</strong> now.</p>'
        help_ = ('Nothing after a few minutes? Look in your spam or junk folder, and check the address above is spelled right. '
                 'Then <a href="/start">fill in the form again</a>.')
    else:
        lead = f'<p>If <strong>{e(email)}</strong> has a page here, a link is on its way to it now.</p>'
        help_ = ('Nothing after a few minutes? Look in your spam or junk folder. No email is sent to an address that has no page: '
                 '<a href="/signin">try the address you signed up with</a>, or <a href="/start">make a page</a>.')
    body = f"""<h1>Check your email</h1>
<div class="card">{lead}
<p>Open the email and press the link. It works once and lasts {TOKEN_MINUTES} minutes.</p>
<p class="note">{help_}</p></div>"""
    return shell(f'Check your email: {SITE_NAME}', body, nonce)


def auth_page(nonce, error=''):
    if error:
        body = f"""<h1>That link didn't work</h1>
<div class="card"><p class="err" role="alert">{e(error)}</p><div class="row"><a class="btn" href="/signin">Get a new link</a></div></div>"""
    else:
        body = f"""<h1>Sign in</h1>
<form class="card" method="post" action="/auth" id="f">
<p id="msg">Press the button to open your page.</p>
<input type="hidden" name="t" id="t">
<button class="btn" type="submit" id="go">Open my page</button>
</form>
<script nonce="{nonce}">
(function () {{
  var m = /[#?&]t=([A-Za-z0-9_-]{{20,}})/.exec(location.hash + location.search);
  if (m) {{
    document.getElementById('t').value = m[1];
    try {{ history.replaceState(null, '', location.pathname); }} catch (err) {{}}
  }} else {{
    document.getElementById('msg').textContent = 'This link is missing its code. Ask for a new one.';
    document.getElementById('go').hidden = true;
  }}
}})();
</script>
<p class="note"><a href="/signin">Get a new link</a></p>"""
    return shell(f'Sign in: {SITE_NAME}', body, nonce)


def message_page(nonce, title, text_html, status_note=''):
    body = f'<h1>{e(title)}</h1><div class="card">{text_html}</div>{status_note}'
    return shell(f'{title}: {SITE_NAME}', body, nonce)


def my_page(nonce, acc, session, is_admin):
    url = f"{BASE_URL}/{acc['slug']}"
    if acc['status'] == 'paid':
        plan = 'Instant quote' if acc['plan'] == 'instant' else 'Job catcher (no prices shown)'
        state = f'<p><span class="pill">Paid</span> {e(plan)}</p>'
    elif acc['status'] == 'trial' and is_active(acc):
        n = days_left(acc)
        state = (f'<p><span class="pill trial">Free trial</span> {n} day{"" if n == 1 else "s"} left.</p>'
                 f'<p>To keep your page, {support_line()}. <a href="/#offer">What it costs</a>.</p>'
                 f'<p class="note">If you do nothing, the quote form switches off when the trial ends. You are never charged automatically.</p>')
    else:
        state = (f'<p><span class="pill off">Not active</span> Customers see your name and a Call button, but not the quote form.</p>'
                 f'<p>To switch it back on, {support_line()}.</p>')
    body = f"""<h1>{e(json.loads(acc['settings']).get('businessName') or 'Your page')}</h1>
<div class="card"><h2>Your page</h2>
<p><a class="link" id="url" href="/{e(acc['slug'])}">{e(url)}</a></p>
<div class="row"><a class="btn" href="/{e(acc['slug'])}?setup">Edit my page</a><button class="btn quiet" type="button" id="copy">Copy link</button></div>
<p class="note">Put this link in your voicemail, your auto-reply text and your Facebook page.</p>
<p class="note">For a missed-call auto-reply, use <code>{e(url)}?callback</code>. It opens with "Sorry we missed your call".</p></div>
<div class="card"><h2>Your plan</h2>{state}</div>
<div class="card"><h2>Your account</h2><p>Signed in as <strong>{e(session['email'])}</strong>.</p>
<div class="row"><form class="inline" method="post" action="/signout"><input type="hidden" name="csrf" value="{e(session['csrf'])}"><button class="btn quiet" type="submit">Sign out</button></form>
{'<a class="btn quiet" href="/owner">Owner page</a>' if is_admin else ''}<a class="btn bad" href="/my/delete">Delete my page</a></div></div>
<script nonce="{nonce}">
document.getElementById('copy').addEventListener('click', function () {{
  var b = this, done = function (ok) {{ b.textContent = ok ? 'Copied' : 'Press and hold the link to copy'; }};
  try {{ navigator.clipboard.writeText(document.getElementById('url').textContent).then(function () {{ done(true); }}, function () {{ done(false); }}); }}
  catch (err) {{ done(false); }}
}});
</script>"""
    return shell(f'My page: {SITE_NAME}', body, nonce)


def delete_page(nonce, session, acc, action, back, who):
    body = f"""<h1>Delete {e(who)}?</h1>
<form class="card" method="post" action="{e(action)}">
<p>This removes the page <strong>/{e(acc['slug'])}</strong>, its settings and its logo. The link stops working straight away. It can't be undone.</p>
<input type="hidden" name="csrf" value="{e(session['csrf'])}"><input type="hidden" name="id" value="{acc['id']}">
<div class="row"><button class="btn bad" type="submit">Yes, delete it</button><a class="btn quiet" href="{e(back)}">No, keep it</a></div>
</form>"""
    return shell(f'Delete page: {SITE_NAME}', body, nonce)


def owner_page(nonce, session, rows, flash=''):
    def act(acc_id, action, label, cls='quiet'):
        return (f'<form class="inline" method="post" action="/owner/act"><input type="hidden" name="csrf" value="{e(session["csrf"])}">'
                f'<input type="hidden" name="id" value="{acc_id}"><input type="hidden" name="action" value="{action}">'
                f'<button class="btn small {cls}" type="submit">{label}</button></form>')

    lines = []
    for a in rows:
        st = json.loads(a['settings'])
        if a['status'] == 'paid':
            state = '<span class="pill">Paid</span>'
        elif a['status'] == 'trial' and is_active(a):
            state = f'<span class="pill trial">Trial, {days_left(a)}d left</span>'
        elif a['status'] == 'trial':
            state = '<span class="pill off">Trial ended</span>'
        else:
            state = '<span class="pill off">Off</span>'
        plan = 'Instant quote' if a['plan'] == 'instant' else 'Job catcher'
        seen = time.strftime('%d %b %Y', time.localtime(a['last_seen'])) if a['last_seen'] else 'never'
        buttons = ' '.join(x for x in [
            act(a['id'], 'paid', 'Mark paid') if a['status'] != 'paid' else act(a['id'], 'trial', 'Back to trial'),
            act(a['id'], 'off', 'Turn off') if a['status'] != 'off' else '',
            act(a['id'], 'extend', '+14 days') if a['status'] == 'trial' else '',
            act(a['id'], 'plan-catcher', 'Set Job catcher') if a['plan'] == 'instant' else act(a['id'], 'plan-instant', 'Set Instant quote'),
            act(a['id'], 'link', 'Sign-in link'),
            f'<a class="btn small bad" href="/owner/delete?id={a["id"]}">Delete</a>',
        ] if x)
        lines.append(f'<div class="biz"><div class="biz-head"><a class="link" href="/{e(a["slug"])}">{e(st.get("businessName") or a["slug"])}</a> {state}</div>'
                     f'<p class="note">/{e(a["slug"])} · {plan}</p>'
                     f'<p>{e(a["email"])} · {e(st.get("phone", ""))}</p>'
                     f'<p class="note">Joined {time.strftime("%d %b %Y", time.localtime(a["created"]))} · last seen {seen}</p>'
                     f'<div class="row">{buttons}</div></div>')
    table = ''.join(lines) if lines else '<p class="note">No businesses have signed up yet.</p>'
    mail = '<span class="pill">On</span>' if mail_on() else '<span class="pill off">Off</span> Sign-up and sign-in emails can\'t be sent until mail is set up.'
    body = f"""<h1>Owner page</h1>
{f'<div class="card">{flash}</div>' if flash else ''}
<div class="card"><h2>Businesses ({len(rows)})</h2>{table}</div>
<form class="card" method="post" action="/owner/add"><h2>Add a business yourself</h2>
<p class="note">For someone who texts you instead of signing up. It makes their page and gives you a sign-in link to text them.</p>
<input type="hidden" name="csrf" value="{e(session['csrf'])}">
<label>Business name<input type="text" name="business" maxlength="60" required></label>
<label>Their mobile <small>jobs are texted here</small><input type="tel" name="mobile" maxlength="24" inputmode="tel" required></label>
<label>Their email <small>they sign in with it later</small><input type="email" name="email" maxlength="120" autocapitalize="off" required></label>
<div class="row"><button class="btn" type="submit">Make their page</button></div></form>
<div class="card"><h2>How it works</h2>
<p class="note">A new page is a free trial for {TRIAL_DAYS} days. When they pay you, press <strong>Mark paid</strong>. A trial that runs out, or a page you turn off, shows the business name and a Call button but not the quote form.
<strong>Job catcher</strong> hides prices on a paid page. <strong>Sign-in link</strong> makes a one-time link you can text to someone who can't find their email. It lasts {HANDED_LINK_HOURS} hours.</p>
<p>Sign-in emails: {mail}</p>
<div class="row"><form class="inline" method="post" action="/signout"><input type="hidden" name="csrf" value="{e(session['csrf'])}"><button class="btn quiet small" type="submit">Sign out</button></form><a class="btn quiet small" href="/my">My own page</a></div></div>
<script nonce="{nonce}">
document.querySelectorAll('[data-copy]').forEach(function (b) {{
  b.addEventListener('click', function () {{
    var done = function (ok) {{ b.textContent = ok ? 'Copied' : 'Press and hold the link to copy'; }};
    try {{ navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function () {{ done(true); }}, function () {{ done(false); }}); }}
    catch (err) {{ done(false); }}
  }});
}});
</script>"""
    return shell(f'Owner: {SITE_NAME}', body, nonce, wide=True)


def inactive_page(nonce, acc, mine):
    s = json.loads(acc['settings'])
    name = s.get('businessName') or 'This business'
    phone = s.get('phone', '')
    call = (f'<div class="row"><a class="btn" href="tel:{e(re.sub(r"[^0-9+]", "", phone))}">Call {e(phone)}</a></div>' if phone else '')
    owner = ''
    if mine:
        why = 'Your free trial has ended.' if acc['status'] == 'trial' else 'Your page is switched off.'
        owner = f'<div class="card"><h2>Only you see this</h2><p>{why} To switch your page back on, {support_line()}.</p><div class="row"><a class="btn quiet" href="/my">My account</a></div></div>'
    body = f"""<h1>{e(name)}</h1>
<div class="card"><p>Online quotes are not available here right now. Please call for a quote.</p>{call}</div>{owner}"""
    return shell(f'{name}: tree quote', body, nonce, bare=True)


# ---------------------------------------------------------------- email

mail_queue = queue.Queue(maxsize=200)


def build_message(to, subject, body):
    msg = EmailMessage()
    msg['From'] = MAIL_FROM or f'{SITE_NAME} <noreply@localhost>'
    msg['To'] = to
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=False)
    domain = (MAIL_FROM.rsplit('@', 1)[-1].strip('> ') if '@' in MAIL_FROM else 'localhost')
    msg['Message-ID'] = make_msgid(domain=domain)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(body)
    return msg


def deliver(to, subject, body):
    if DEV_OUTBOX:
        with open(DEV_OUTBOX, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'to': to, 'subject': subject, 'body': body}) + '\n')
        return
    msg = build_message(to, subject, body)
    ctx = ssl.create_default_context()
    if SMTP_SECURITY == 'starttls':
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls(context=ctx)
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20, context=ctx) as s:
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)


def mail_worker():
    while True:
        to, subject, body = mail_queue.get()
        for attempt in (1, 2):
            try:
                deliver(to, subject, body)
                break
            except Exception as err:  # the reason goes to the service log; the link never does
                log(f'mail: attempt {attempt} to {to.split("@")[-1]} failed: {type(err).__name__}: {str(err)[:200]}')
                time.sleep(3)


def make_link(db, email, purpose='signin', payload=None, seconds=TOKEN_MINUTES * 60):
    raw = secrets.token_urlsafe(32)
    t = now()
    db.execute('INSERT INTO tokens(hash, email, purpose, payload, expires, created) VALUES(?,?,?,?,?,?)',
               (sha(raw), email, purpose, json.dumps(payload or {}), t + seconds, t))
    return f'{BASE_URL}/auth#t={raw}'


def send_link(db, email, purpose, payload=None, business=''):
    url = make_link(db, email, purpose, payload)
    if purpose == 'signup':
        subject = f'Finish making your page: {SITE_NAME}'
        lead = f'Press this link to make the quote page for {business}:' if business else 'Press this link to make your quote page:'
    else:
        subject = f'Your sign-in link: {SITE_NAME}'
        lead = 'Press this link to sign in:'
    body = (f'Hi,\n\n{lead}\n\n{url}\n\nIt works once and runs out in {TOKEN_MINUTES} minutes. '
            f"If you didn't ask for this, ignore this email and nothing happens.\n\n{SITE_NAME}\n{BASE_URL}\n")
    try:
        mail_queue.put_nowait((email, subject, body))
    except queue.Full:
        log('mail: queue full, dropped a message')
    return url


# ---------------------------------------------------------------- web

LOGO_TYPES = {'png': 'image/png', 'jpg': 'image/jpeg', 'webp': 'image/webp'}


def sniff_image(data):
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'webp'
    return ''


UNKNOWN = object()  # "not looked up yet", as distinct from None, "nobody is signed in"


class Halt(Exception):
    """Stop handling the request and send this response."""

    def __init__(self, status, body=b'', ctype='text/html; charset=utf-8', headers=None):
        self.status, self.body, self.ctype, self.headers = status, body, ctype, headers or {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'quote-pages'
    sys_version = ''
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    # ---- plumbing

    def reply(self, status, body=b'', ctype='text/html; charset=utf-8', headers=None, csp=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        h = {'Cache-Control': 'no-store'}
        h.update(headers or {})
        if csp is None and ctype.startswith('text/html'):
            csp = (f"default-src 'none'; style-src 'nonce-{self.nonce}'; script-src 'nonce-{self.nonce}'; img-src 'self'; "
                   "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'")
        if csp:
            self.send_header('Content-Security-Policy', csp)
        for k, v in h.items():
            if isinstance(v, list):
                for item in v:
                    self.send_header(k, item)
            else:
                self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def redirect(self, to, headers=None):
        h = {'Location': to}
        h.update(headers or {})
        self.reply(303, b'', 'text/plain; charset=utf-8', h)

    def json(self, status, obj):
        self.reply(status, json.dumps(obj), 'application/json; charset=utf-8')

    def client_ip(self):
        fwd = self.headers.get('X-Forwarded-For', '')
        ip = fwd.split(',')[-1].strip() if fwd else self.client_address[0]
        return ip[:64]

    def read_body(self, most):
        try:
            n = int(self.headers.get('Content-Length', ''))
        except ValueError:
            raise Halt(411, 'Length required', 'text/plain; charset=utf-8')
        if n < 0 or n > most:
            self.close_connection = True
            raise Halt(413, json.dumps({'ok': False, 'error': 'That is too big.'}), 'application/json; charset=utf-8')
        return self.rfile.read(n) if n else b''

    def form(self):
        raw = self.read_body(MAX_FORM).decode('utf-8', 'replace')
        try:
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True, max_num_fields=20).items()}
        except ValueError:
            raise Halt(400, 'Bad request', 'text/plain; charset=utf-8')

    def same_origin(self):
        """True only for a form or save sent from one of this site's own pages."""
        # Browsers say where a request came from in Sec-Fetch-Site, and a page cannot fake it.
        site = self.headers.get('Sec-Fetch-Site')
        if site is not None:
            return site == 'same-origin'
        origin = self.headers.get('Origin')  # older browsers
        return origin is not None and origin.rstrip('/') == BASE_URL

    def session(self):
        """Who is signed in on THIS request. Worked out afresh for every request: one connection
        from the web server in front carries many people's requests, one after another."""
        if self._session is not UNKNOWN:
            return self._session
        self._session = None
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == COOKIE and re.fullmatch(r'[A-Za-z0-9_-]{20,80}', v):
                with DB() as db:
                    row = db.execute('SELECT * FROM sessions WHERE hash=? AND expires>?', (sha(v), now())).fetchone()
                if row:
                    self._session = dict(row)
                break
        return self._session

    def need_session(self, api=False):
        s = self.session()
        if not s:
            if api:
                raise Halt(401, json.dumps({'ok': False, 'error': 'You are signed out. Sign in again, then save.'}), 'application/json; charset=utf-8')
            raise Halt(303, b'', 'text/plain; charset=utf-8', {'Location': '/signin'})
        return s

    def check_csrf(self, s, given, api=False):
        if not self.same_origin() or not given or not same(given, s['csrf']):
            if api:
                raise Halt(403, json.dumps({'ok': False, 'error': 'This screen is out of date. Reload the page and try again.'}), 'application/json; charset=utf-8')
            raise Halt(403, message_page(self.nonce, 'That didn\'t go through', '<p>This screen was out of date. Go back, reload the page and try again.</p>'))

    def account_for(self, s, db=None):
        def get(d):
            return d.execute('SELECT * FROM accounts WHERE email=?', (s['email'],)).fetchone()
        if db is not None:
            return get(db)
        with DB() as d:
            return get(d)

    def is_admin(self, s):
        return bool(s and ADMIN_EMAIL and s['email'] == ADMIN_EMAIL)

    def cookie(self, value, age):
        return f'{COOKIE}={value}; Path=/; Max-Age={age}; HttpOnly; SameSite=Lax' + ('; Secure' if SECURE else '')

    # ---- dispatch

    def handle_one(self, method):
        self.nonce = secrets.token_urlsafe(16)
        self._session = UNKNOWN
        try:
            parts = urlsplit(self.path)
            path = parts.path
            if len(self.path) > 2000 or '\x00' in path:
                raise Halt(400, 'Bad request', 'text/plain; charset=utf-8')
            try:
                query = {k: v[0] for k, v in parse_qs(parts.query, max_num_fields=20).items()}
            except ValueError:
                raise Halt(400, 'Bad request', 'text/plain; charset=utf-8')
            if method == 'GET':
                self.get(path, query)
            else:
                self.post(path, query)
        except Halt as h:
            self.reply(h.status, h.body, h.ctype, h.headers)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as err:
            log(f'error on {method} {urlsplit(self.path).path}: {type(err).__name__}: {str(err)[:300]}')
            try:
                self.reply(500, message_page(self.nonce, 'Something went wrong', '<p>That didn\'t work. Please try again in a minute.</p>'))
            except Exception:
                self.close_connection = True

    def do_GET(self):
        self.handle_one('GET')

    def do_HEAD(self):
        self.handle_one('GET')

    def do_POST(self):
        self.handle_one('POST')

    # ---- GET

    def get(self, path, query):
        if path == '/healthz':
            return self.reply(200, 'ok\n', 'text/plain; charset=utf-8')
        if path == '/api/open':  # the demo asks this before it offers "Make my page"
            return self.json(200, {'signup': mail_on()})
        if path in ('/', '/index.html'):
            return self.reply(200, TPL.demo, headers={'Cache-Control': 'no-cache'}, csp='')
        if path == '/robots.txt':
            return self.reply(200, 'User-agent: *\nDisallow: /my\nDisallow: /owner\nDisallow: /auth\nDisallow: /api/\n', 'text/plain; charset=utf-8',
                              {'Cache-Control': 'public, max-age=3600'})
        if path == '/favicon.ico':
            return self.reply(204, b'', 'image/x-icon', {'Cache-Control': 'public, max-age=86400'})
        if path == '/start':
            s = self.session()
            if s and self.account_for(s):
                return self.redirect('/my')
            return self.reply(200, start_page(self.nonce))
        if path == '/signin':
            s = self.session()
            if s:
                return self.redirect('/my' if self.account_for(s) else ('/owner' if self.is_admin(s) else '/start'))
            return self.reply(200, signin_page(self.nonce))
        if path == '/auth':
            return self.reply(200, auth_page(self.nonce))
        if path == '/my':
            s = self.need_session()
            acc = self.account_for(s)
            if not acc:
                return self.redirect('/owner' if self.is_admin(s) else '/start')
            return self.reply(200, my_page(self.nonce, acc, s, self.is_admin(s)))
        if path == '/my/delete':
            s = self.need_session()
            acc = self.account_for(s)
            if not acc:
                return self.redirect('/start')
            return self.reply(200, delete_page(self.nonce, s, acc, '/my/delete', '/my', 'your page'))
        if path == '/owner':
            s = self.need_session()
            if not self.is_admin(s):
                raise Halt(404, message_page(self.nonce, 'Page not found', '<p>There is nothing at this address.</p>'))
            with DB() as db:
                rows = db.execute('SELECT * FROM accounts ORDER BY created DESC LIMIT 500').fetchall()
            return self.reply(200, owner_page(self.nonce, s, rows))
        if path == '/owner/delete':
            s = self.need_session()
            if not self.is_admin(s):
                raise Halt(404, message_page(self.nonce, 'Page not found', '<p>There is nothing at this address.</p>'))
            with DB() as db:
                acc = db.execute('SELECT * FROM accounts WHERE id=?', (query.get('id', ''),)).fetchone()
            if not acc:
                return self.redirect('/owner')
            return self.reply(200, delete_page(self.nonce, s, acc, '/owner/act?do=delete', '/owner', f"/{acc['slug']}"))
        m = re.fullmatch(r'/logo/([a-f0-9]{24}\.(png|jpg|webp))', path)
        if m:
            try:
                with open(os.path.join(LOGOS, m.group(1)), 'rb') as f:
                    data = f.read()
            except OSError:
                raise Halt(404, 'Not found', 'text/plain; charset=utf-8')
            return self.reply(200, data, LOGO_TYPES[m.group(2)], {'Cache-Control': 'public, max-age=31536000, immutable'},
                              csp="default-src 'none'")
        m = re.fullmatch(r'/([a-z0-9][a-z0-9-]{1,39})/?', path)
        if m and m.group(1) not in RESERVED:
            if path.endswith('/'):
                return self.redirect('/' + m.group(1))
            with DB() as db:
                acc = db.execute('SELECT * FROM accounts WHERE slug=?', (m.group(1),)).fetchone()
            if acc:
                s = self.session()
                mine = bool(s and s['email'] == acc['email'])
                if not is_active(acc):
                    return self.reply(200, inactive_page(self.nonce, acc, mine))
                body, mine = render_business_page(acc, s)
                return self.reply(200, body, headers={'Cache-Control': 'no-store' if mine else 'no-cache'}, csp=PAGE_CSP)
        raise Halt(404, message_page(self.nonce, 'Page not found', '<p>There is no quote page at this address. Check the link, or <a href="/">see the demo</a>.</p>'))

    # ---- POST

    def post(self, path, query):
        if path == '/start':
            return self.post_start()
        if path == '/signin':
            return self.post_signin()
        if path == '/auth':
            return self.post_auth()
        if path == '/signout':
            f = self.form()
            s = self.session()
            if s:
                self.check_csrf(s, f.get('csrf'))
                with DB() as db:
                    db.execute('DELETE FROM sessions WHERE hash=?', (s['hash'],))
            return self.redirect('/signin', {'Set-Cookie': self.cookie('', 0)})
        if path == '/api/settings':
            return self.post_settings()
        if path == '/api/logo':
            return self.post_logo()
        if path == '/api/logo/remove':
            s = self.need_session(api=True)
            self.read_body(MAX_FORM)
            self.check_csrf(s, self.headers.get('X-CSRF'), api=True)
            with DB() as db:
                acc = self.account_for(s, db)
                if not acc:
                    return self.json(404, {'ok': False, 'error': 'No page found for this sign-in.'})
                self.drop_logo(acc)
                db.execute("UPDATE accounts SET logo='' WHERE id=?", (acc['id'],))
            return self.json(200, {'ok': True, 'logo': ''})
        if path == '/my/delete':
            s = self.need_session()
            f = self.form()
            self.check_csrf(s, f.get('csrf'))
            with DB() as db:
                acc = self.account_for(s, db)
                if acc:
                    self.delete_account(db, acc)
            return self.reply(200, message_page(self.nonce, 'Your page is deleted', '<p>The page, its settings and its logo are gone.</p><div class="row"><a class="btn quiet" href="/">Back to the demo</a></div>'),
                              headers={'Set-Cookie': self.cookie('', 0)})
        if path == '/owner/act':
            return self.post_owner(query)
        if path == '/owner/add':
            s = self.need_session()
            if not self.is_admin(s):
                raise Halt(404, 'Not found', 'text/plain; charset=utf-8')
            f = self.form()
            self.check_csrf(s, f.get('csrf'))
            with DB() as db:
                acc, problem = new_account(db, f.get('email'), f.get('business'), f.get('mobile'))
                if acc:
                    url = make_link(db, acc['email'], seconds=HANDED_LINK_HOURS * 3600)
                    flash = (f'<h2>Page made: /{e(acc["slug"])}</h2><p>Text them this sign-in link. It works once and lasts {HANDED_LINK_HOURS} hours. '
                             f'It opens their account, where they press Edit my page.</p><p><code>{e(url)}</code></p>'
                             f'<div class="row"><button class="btn small quiet" type="button" data-copy="{e(url)}">Copy link</button></div>')
                else:
                    flash = f'<p class="err" role="alert">{e(problem)}</p>'
                rows = db.execute('SELECT * FROM accounts ORDER BY created DESC LIMIT 500').fetchall()
            return self.reply(200, owner_page(self.nonce, s, rows, flash))
        raise Halt(404, 'Not found', 'text/plain; charset=utf-8')

    @staticmethod
    def drop_logo(acc):
        if acc['logo'] and re.fullmatch(r'[a-f0-9]{24}\.(png|jpg|webp)', acc['logo']):
            try:
                os.remove(os.path.join(LOGOS, acc['logo']))
            except OSError:
                pass

    def delete_account(self, db, acc):
        Handler.drop_logo(acc)
        db.execute('DELETE FROM sessions WHERE email=? AND email<>?', (acc['email'], ADMIN_EMAIL or '-'))
        db.execute('DELETE FROM tokens WHERE email=?', (acc['email'],))
        db.execute('DELETE FROM accounts WHERE id=?', (acc['id'],))
        log(f"account deleted: /{acc['slug']}")

    def post_start(self):
        f = self.form()
        if not self.same_origin():
            raise Halt(403, message_page(self.nonce, 'That didn\'t go through', '<p>Please try again.</p><div class="row"><a class="btn" href="/start">Back to the form</a></div>'))
        if not mail_on():
            return self.reply(200, start_page(self.nonce))
        email = valid_email(f.get('email'))
        business = text(f.get('business'), 60)
        phone = text(f.get('mobile'), 24)
        raw = f.get('settings', '')
        raw = raw if len(raw) < 20000 else ''
        values = {'business': business, 'mobile': phone, 'email': text(f.get('email'), 120), 'settings': raw}
        given = f.get('stamp', '')
        stamp, _, sig = given.partition('.')
        fresh = stamp.isascii() and stamp.isdigit() and len(stamp) < 12 and same(sig, sign('start.' + stamp)) and now() - int(stamp) <= 6 * 3600
        again = lambda message: self.reply(200, start_page(self.nonce, values, message, given if fresh else ''))
        # Bots fill the hidden trap field. Nothing a person types can: tell the bot it worked.
        if f.get('qp-zx-leave-empty'):
            return self.reply(200, sent_page(self.nonce, values['email'] or 'that address', new=True))
        if not fresh:
            return again('That page was open a long time. Please press the button again.')
        # Bots also send the form back within a second or two of getting it. A person who somehow did
        # (a password manager, say) is asked to press again, and is never told a link was sent when it was not.
        if now() - int(stamp) < 2:
            return again('Please press the button again.')
        if len(business) < 2:
            return again('Type your business name.')
        if not mobile(phone):
            return again('Type an Australian mobile number, like 0412 345 678. Jobs are texted to it.')
        if not email:
            return again('Type your email address. Your sign-in link is sent to it.')
        carried = None
        if raw:
            try:
                carried = json.loads(raw)
            except ValueError:
                carried = None
        ip = self.client_ip()
        with DB() as db:
            if (limited(db, f'start-ip:{ip}', 3600, 6) or limited(db, f'mail-to:{email}', 900, 3)
                    or limited(db, f'mail-to-day:{email}', 86400, 8) or limited(db, 'mail-all', 86400, 400)):
                raise Halt(429, message_page(self.nonce, 'Too many tries', '<p>Please wait a few minutes, then try again.</p>'))
            if db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone():
                send_link(db, email, 'signin')
            else:
                send_link(db, email, 'signup', {'business': business, 'mobile': phone, 'settings': carried if isinstance(carried, dict) else None}, business)
        return self.reply(200, sent_page(self.nonce, email, new=True))

    def post_signin(self):
        f = self.form()
        if not self.same_origin():
            raise Halt(403, message_page(self.nonce, 'That didn\'t go through', '<p>Please try again.</p><div class="row"><a class="btn" href="/signin">Back to sign in</a></div>'))
        if not mail_on():
            return self.reply(200, signin_page(self.nonce))
        email = valid_email(f.get('email'))
        if not email:
            return self.reply(200, signin_page(self.nonce, 'Type your email address.', text(f.get('email'), 120)))
        ip = self.client_ip()
        with DB() as db:
            if limited(db, f'signin-ip:{ip}', 3600, 12):
                raise Halt(429, message_page(self.nonce, 'Too many tries', '<p>Please wait a few minutes, then try again.</p>'))
            known = db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone() or (ADMIN_EMAIL and email == ADMIN_EMAIL)
            if known and not (limited(db, f'mail-to:{email}', 900, 3) or limited(db, f'mail-to-day:{email}', 86400, 8)
                              or limited(db, 'mail-all', 86400, 400)):
                send_link(db, email, 'signin')
        # The same answer whether or not the address has a page, so nobody can fish for customers' emails.
        return self.reply(200, sent_page(self.nonce, email))

    def post_auth(self):
        f = self.form()
        if not self.same_origin():
            raise Halt(403, auth_page(self.nonce, 'Please open the link from your email again.'))
        raw = f.get('t', '')
        ip = self.client_ip()
        bad = 'That link has run out or was already used. Links work once and last %d minutes.' % TOKEN_MINUTES
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,80}', raw):
            return self.reply(400, auth_page(self.nonce, bad))
        with DB() as db:
            if limited(db, f'auth-ip:{ip}', 900, 40):
                raise Halt(429, message_page(self.nonce, 'Too many tries', '<p>Please wait a few minutes, then try again.</p>'))
            tok = db.execute('SELECT * FROM tokens WHERE hash=? AND expires>?', (sha(raw), now())).fetchone()
            if not tok:
                return self.reply(400, auth_page(self.nonce, bad))
            db.execute('DELETE FROM tokens WHERE hash=?', (tok['hash'],))
            email = tok['email']
            acc = db.execute('SELECT * FROM accounts WHERE email=?', (email,)).fetchone()
            to = '/my'
            if not acc and tok['purpose'] == 'signup':
                acc = self.create_account(db, email, json.loads(tok['payload'] or '{}'))
                to = f"/{acc['slug']}?setup"
            elif not acc:
                to = '/owner' if (ADMIN_EMAIL and email == ADMIN_EMAIL) else '/start'
            if acc:
                db.execute('UPDATE accounts SET last_seen=? WHERE id=?', (now(), acc['id']))
            value = secrets.token_urlsafe(32)
            db.execute('INSERT INTO sessions(hash, email, csrf, expires, created) VALUES(?,?,?,?,?)',
                       (sha(value), email, secrets.token_urlsafe(24), now() + SESSION_DAYS * 86400, now()))
        self.redirect(to, {'Set-Cookie': self.cookie(value, SESSION_DAYS * 86400)})

    def create_account(self, db, email, payload):
        d = TPL.defaults
        carried = payload.get('settings') if isinstance(payload.get('settings'), dict) else None
        if carried:
            # Prices and choices made on the demo come across. The demo's own name, number and claims do not.
            base = normalise(carried, d)
            if base['businessName'] == d['businessName'] and base['baseSuburb'] == d['baseSuburb']:
                base['baseSuburb'] = ''
            if base['trust'] == d['trust']:
                base['trust'] = []
            base['email'] = ''
        else:
            base = normalise({'prices': d['prices'], 'promises': {'freeQuote': True}}, d)
        base['businessName'] = text(payload.get('business'), 60)
        base['phone'] = text(payload.get('mobile'), 24)
        base['textJobsTo'] = ''
        base['emailKey'] = ''
        slug = free_slug(db, base['businessName'])
        t = now()
        db.execute('INSERT INTO accounts(email, slug, settings, created, trial_ends) VALUES(?,?,?,?,?)',
                   (email, slug, json.dumps(base), t, t + TRIAL_DAYS * 86400))
        log(f'account created: /{slug}')
        return db.execute('SELECT * FROM accounts WHERE email=?', (email,)).fetchone()

    def post_settings(self):
        s = self.need_session(api=True)
        raw = self.read_body(MAX_FORM)
        self.check_csrf(s, self.headers.get('X-CSRF'), api=True)
        try:
            data = json.loads(raw.decode('utf-8'))
            incoming = data['settings']
            if not isinstance(incoming, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self.json(400, {'ok': False, 'error': "Those settings couldn't be read. Reload the page and try again."})
        clean = normalise(incoming, TPL.defaults)
        if len(clean['businessName']) < 2:
            return self.json(400, {'ok': False, 'error': 'Type your business name before saving.'})
        if clean['email'] and not valid_email(clean['email']):
            return self.json(400, {'ok': False, 'error': "The email shown on your page doesn't look right. Fix it or clear it, then save."})
        with DB() as db:
            acc = self.account_for(s, db)
            if not acc:
                return self.json(404, {'ok': False, 'error': 'No page found for this sign-in.'})
            if limited(db, f'save:{acc["id"]}', 3600, 200):
                return self.json(429, {'ok': False, 'error': 'Too many saves in a row. Wait a few minutes.'})
            db.execute('UPDATE accounts SET settings=?, last_seen=? WHERE id=?', (json.dumps(clean), now(), acc['id']))
        return self.json(200, {'ok': True})

    def post_logo(self):
        s = self.need_session(api=True)
        data = self.read_body(MAX_LOGO)
        self.check_csrf(s, self.headers.get('X-CSRF'), api=True)
        kind = sniff_image(data)
        if not kind:
            return self.json(400, {'ok': False, 'error': 'That file is not a PNG, JPG or WebP picture.'})
        with DB() as db:
            acc = self.account_for(s, db)
            if not acc:
                return self.json(404, {'ok': False, 'error': 'No page found for this sign-in.'})
            if limited(db, f'logo:{acc["id"]}', 3600, 30):
                return self.json(429, {'ok': False, 'error': 'Too many uploads in a row. Wait a few minutes.'})
            name = f'{secrets.token_hex(12)}.{kind}'
            tmp = os.path.join(LOGOS, name + '.part')
            with open(tmp, 'wb') as out:
                out.write(data)
            os.chmod(tmp, 0o640)
            os.replace(tmp, os.path.join(LOGOS, name))
            self.drop_logo(acc)
            db.execute('UPDATE accounts SET logo=?, last_seen=? WHERE id=?', (name, now(), acc['id']))
        return self.json(200, {'ok': True, 'logo': f'/logo/{name}'})

    def post_owner(self, query):
        s = self.need_session()
        if not self.is_admin(s):
            raise Halt(404, 'Not found', 'text/plain; charset=utf-8')
        f = self.form()
        self.check_csrf(s, f.get('csrf'))
        action = 'delete' if query.get('do') == 'delete' else f.get('action', '')
        flash, rows = '', None
        with DB() as db:  # answer only after this block: the change must be saved before the next page is asked for
            acc = db.execute('SELECT * FROM accounts WHERE id=?', (f.get('id', ''),)).fetchone()
            if not acc:
                pass
            elif action == 'paid':
                db.execute("UPDATE accounts SET status='paid' WHERE id=?", (acc['id'],))
            elif action == 'off':
                db.execute("UPDATE accounts SET status='off' WHERE id=?", (acc['id'],))
            elif action == 'trial':
                db.execute("UPDATE accounts SET status='trial', trial_ends=MAX(trial_ends, ?) WHERE id=?", (now() + TRIAL_DAYS * 86400, acc['id']))
            elif action == 'extend':
                db.execute("UPDATE accounts SET status='trial', trial_ends=MAX(trial_ends, ?) + ? WHERE id=?", (now(), 14 * 86400, acc['id']))
            elif action in ('plan-instant', 'plan-catcher'):
                db.execute('UPDATE accounts SET plan=? WHERE id=?', (action.split('-')[1], acc['id']))
            elif action == 'delete':
                self.delete_account(db, acc)
            elif action == 'link':
                url = make_link(db, acc['email'], seconds=HANDED_LINK_HOURS * 3600)
                flash = (f'<h2>Sign-in link for /{e(acc["slug"])}</h2><p>Text or email this to them. It works once and lasts {HANDED_LINK_HOURS} hours.</p>'
                         f'<p><code>{e(url)}</code></p><div class="row"><button class="btn small quiet" type="button" data-copy="{e(url)}">Copy link</button></div>')
                rows = db.execute('SELECT * FROM accounts ORDER BY created DESC LIMIT 500').fetchall()
        if flash:
            return self.reply(200, owner_page(self.nonce, s, rows, flash))
        return self.redirect('/owner')


# ---------------------------------------------------------------- start-up

def setup():
    global TPL
    TPL = Template(TEMPLATE)
    init_db()


def serve():
    setup()
    threading.Thread(target=mail_worker, daemon=True).start()

    def housekeeping():
        while True:
            try:
                tidy()
            except Exception as err:
                log(f'tidy failed: {err}')
            time.sleep(3600)

    threading.Thread(target=housekeeping, daemon=True).start()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.daemon_threads = True
    log(f'listening on {HOST}:{PORT}, site {BASE_URL}, mail {"on" if mail_on() else "off"}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def cli_link(email):
    setup()
    email = valid_email(email)
    with DB() as db:
        known = email and (db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone() or email == ADMIN_EMAIL)
        if not known:
            raise SystemExit('No page uses that email address, and it is not the owner address.')
        url = make_link(db, email, seconds=HANDED_LINK_HOURS * 3600)
    print(url)
    print(f'Works once. Runs out in {HANDED_LINK_HOURS} hours.')


def new_account(db, email, business, phone):
    """Make a page without the emailed link. For the owner only: owner page and command line."""
    email, business, phone = valid_email(email), text(business, 60), text(phone, 24)
    if len(business) < 2:
        return None, 'Type the business name.'
    if not mobile(phone):
        return None, 'That is not an Australian mobile number. Jobs are texted to it.'
    if not email:
        return None, 'That is not an email address.'
    if db.execute('SELECT 1 FROM accounts WHERE email=?', (email,)).fetchone():
        return None, 'That email address already has a page.'
    acc = Handler.create_account(None, db, email, {'business': business, 'mobile': phone})
    return acc, ''


def cli_add(email, phone, business):
    setup()
    with DB() as db:
        acc, problem = new_account(db, email, business, phone)
        if not acc:
            raise SystemExit(problem)
        url = make_link(db, acc['email'], seconds=HANDED_LINK_HOURS * 3600)
    print(f"Page made: {BASE_URL}/{acc['slug']}")
    print(f'Sign-in link (works once, lasts {HANDED_LINK_HOURS} hours):')
    print(url)


def cli_remove(email):
    setup()
    with DB() as db:
        acc = db.execute('SELECT * FROM accounts WHERE email=?', (valid_email(email),)).fetchone()
        if not acc:
            raise SystemExit('No page uses that email address.')
        Handler.delete_account(Handler, db, acc)
    print(f"Deleted /{acc['slug']}.")


def cli_testmail(to):
    to = valid_email(to)
    if not to:
        raise SystemExit('That is not an email address.')
    if not mail_on():
        raise SystemExit('Mail is not set up: QP_SMTP_HOST and QP_MAIL_FROM are empty.')
    deliver(to, f'Test email: {SITE_NAME}', f'This is a test from {SITE_NAME} ({BASE_URL}).\nIf you can read it, sign-in emails will work.\n')
    print(f'Sent a test email to {to}.')


if __name__ == '__main__':
    args = sys.argv[1:]
    if args[:1] == ['link'] and len(args) == 2:
        cli_link(args[1])
    elif args[:1] == ['add'] and len(args) >= 4:
        cli_add(args[1], args[2], ' '.join(args[3:]))
    elif args[:1] == ['remove'] and len(args) == 2:
        cli_remove(args[1])
    elif args[:1] == ['testmail'] and len(args) == 2:
        cli_testmail(args[1])
    elif not args or args == ['serve']:
        serve()
    else:
        raise SystemExit(__doc__)
