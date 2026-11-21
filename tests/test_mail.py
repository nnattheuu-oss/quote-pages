#!/usr/bin/env python3
"""
The server delivering its own, signed email: python3 tests/test_mail.py

A pretend mail server on this machine stands in for Gmail and the rest. Each message it is
handed is checked with an independent DKIM verifier (dkimpy) when that is installed.
"""
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_app import SERVER, Browser, Site, free_port  # noqa: E402

try:
    import dkim
except ImportError:  # pragma: no cover
    dkim = None


class Inbox(socketserver.ThreadingTCPServer):
    """A tiny mail server that keeps what it is given. `script` lists the answers to give to
    each RCPT in turn (default: accept)."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port):
        self.messages, self.script, self.helos = [], [], []
        super().__init__(('127.0.0.1', port), Session)
        threading.Thread(target=self.serve_forever, daemon=True).start()


class Session(socketserver.StreamRequestHandler):
    def handle(self):
        say = lambda line: self.wfile.write(line.encode() + b'\r\n')
        say('220 pretend ESMTP')
        sender = rcpt = None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            word = line.strip().upper()
            if word.startswith(b'EHLO') or word.startswith(b'HELO'):
                self.server.helos.append(line.split()[1].decode())
                say('250-pretend')
                say('250 SIZE 1000000')
            elif word.startswith(b'MAIL FROM'):
                sender = re.search(rb'<([^>]*)>', line).group(1).decode()
                say('250 ok')
            elif word.startswith(b'RCPT TO'):
                answer = self.server.script.pop(0) if self.server.script else '250 ok'
                rcpt = re.search(rb'<([^>]*)>', line).group(1).decode()
                say(answer)
            elif word == b'DATA':
                say('354 go on')
                data = b''
                while not data.endswith(b'\r\n.\r\n'):
                    chunk = self.rfile.readline()
                    if not chunk:
                        return
                    data += chunk
                body = re.sub(rb'(?m)^\.\.', b'.', data[:-3])
                self.server.messages.append({'from': sender, 'to': rcpt, 'raw': body})
                say('250 queued')
            elif word == b'QUIT':
                say('221 bye')
                return
            elif word == b'RSET':
                say('250 ok')
            else:
                say('502 what')


class DirectMail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inbox = Inbox(free_port())
        cls.site = Site(mail=False, extra={
            'QP_DIRECT_MAIL': '1', 'QP_TEST_MX': f'127.0.0.1:{cls.inbox.server_address[1]}', 'QP_TEST_RETRY': '0.5,0.5,0.5',
            'QP_MAIL_FROM': 'Tree Job Quote <signin@treejobquote.test>', 'QP_REPLY_TO': 'owner@example.com',
            'QP_HELO': 'mail.treejobquote.test', 'QP_MAIL_IP': '192.0.2.10'})
        cls.cli = staticmethod(lambda *a: subprocess.run([sys.executable, SERVER, *a], env=cls.site.env, capture_output=True, text=True))
        # No key yet: mail is off and nothing is promised
        assert json.loads(Browser(cls.site).get('/api/open').text) == {'signup': False}
        assert Browser(cls.site).get('/api/dkim').status == 404
        out = cls.cli('mailkey')
        assert 'Made a new mail-signing key' in out.stdout, out.stdout + out.stderr
        cls.records = dict(re.findall(r'name:\s+(\S+)\n\s+value: (.+)', out.stdout))
        b = Browser(cls.site)
        cls.stamp = re.search(r'name="stamp" value="([^"]+)"', b.get('/start').text).group(1)
        time.sleep(2.1)

    @classmethod
    def tearDownClass(cls):
        cls.site.stop()
        cls.inbox.shutdown()

    def wait_for(self, count, seconds=8):
        end = time.time() + seconds
        while time.time() < end and len(self.inbox.messages) < count:
            time.sleep(0.05)
        self.assertEqual(len(self.inbox.messages), count)
        return self.inbox.messages[-1]

    def verified(self, raw):
        key = self.records['qp1._domainkey'].encode()
        asked = []

        def dns(name, timeout=5):
            asked.append(name)
            return key
        ok = dkim.verify(raw, dnsfunc=dns)
        return ok, asked

    def signup(self, business, email, ip):
        b = Browser(self.site, ip)
        return b.post('/start', {'business': business, 'mobile': '0412 345 678', 'email': email, 'stamp': self.stamp})

    def test_1_records_to_publish(self):
        self.assertEqual(self.records['@'], 'v=spf1 ip4:192.0.2.10 ~all')
        self.assertEqual(self.records['_dmarc'], 'v=DMARC1; p=none')
        self.assertRegex(self.records['qp1._domainkey'], r'^v=DKIM1; k=rsa; p=[A-Za-z0-9+/]{300,}={0,2}$')
        self.assertEqual(json.loads(Browser(self.site).get('/api/dkim').text), {'name': 'qp1._domainkey', 'value': self.records['qp1._domainkey']})
        self.assertEqual(json.loads(Browser(self.site).get('/api/open').text), {'signup': True})
        self.assertNotIn('Made a new', self.cli('mailkey').stdout)  # a second run keeps the key it has
        self.assertEqual(oct(os.stat(os.path.join(self.site.env['QP_DATA'], 'dkim.pem')).st_mode & 0o777), '0o600')

    def test_2_a_signed_email_arrives(self):
        before = len(self.inbox.messages)
        self.assertIn('Check your email', self.signup('Signed Mail Trees', 'buyer@example.com', '198.51.100.1').text)
        got = self.wait_for(before + 1)
        raw = got['raw']
        self.assertEqual((got['from'], got['to']), ('signin@treejobquote.test', 'buyer@example.com'))
        self.assertIn('mail.treejobquote.test', self.inbox.helos)
        head = raw.split(b'\r\n\r\n')[0].decode()
        unfolded = re.sub(r'\r\n[ \t]+', ' ', head)
        self.assertTrue(unfolded.startswith('DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=treejobquote.test; s=qp1;'), unfolded[:120])
        self.assertIn('h=from:to:subject:date:message-id:reply-to:mime-version:content-type:content-transfer-encoding;', unfolded)
        for line in ('From: Tree Job Quote <signin@treejobquote.test>', 'To: buyer@example.com', 'Reply-To: owner@example.com',
                     'Subject: Finish making your page: Tree Job Quote', 'Auto-Submitted: auto-generated'):
            self.assertIn(line, head)
        self.assertRegex(head, r'Message-ID: <[^@>]+@treejobquote\.test>')
        self.assertTrue(all(len(line) <= 998 for line in raw.split(b'\r\n')))
        self.assertRegex(raw.decode(), r'/auth#t=[A-Za-z0-9_-]{40,}\r\n')
        if dkim:
            ok, asked = self.verified(raw)
            self.assertTrue(ok)
            self.assertEqual(asked, [b'qp1._domainkey.treejobquote.test.'])
            self.assertFalse(self.verified(raw.replace(b'/auth#t=', b'/auth#T='))[0])  # a changed body no longer checks out
            self.assertFalse(self.verified(raw.replace(b'To: buyer@example.com', b'To: thief@example.com'))[0])
        # the link in it really signs in
        token = re.search(r'/auth#t=([A-Za-z0-9_-]+)', raw.decode()).group(1)
        self.assertEqual(Browser(self.site).sign_in_with(token).getheader('Location'), '/signed-mail-trees?setup')

    def test_3_accents_and_odd_names_still_verify(self):
        before = len(self.inbox.messages)
        self.signup('Żółć & Søn  Træfældning — “best”', 'accents@example.com', '198.51.100.2')
        raw = self.wait_for(before + 1)['raw']
        self.assertIn(b'Content-Transfer-Encoding: quoted-printable', raw)
        self.assertTrue(all(byte < 128 for byte in raw))  # nothing a strict mail server would choke on
        if dkim:
            self.assertTrue(self.verified(raw)[0])

    def test_4_busy_server_is_tried_again_and_a_dead_address_is_not(self):
        before = len(self.inbox.messages)
        self.inbox.script[:] = ['451 4.7.1 try again later', '250 ok']
        self.signup('Greylisted Trees', 'grey@example.com', '198.51.100.3')
        self.assertEqual(self.wait_for(before + 1)['to'], 'grey@example.com')
        self.inbox.script[:] = ['550 5.1.1 no such user']
        self.signup('Nobody Home Trees', 'nobody@example.com', '198.51.100.4')
        time.sleep(2.5)
        self.assertEqual(len(self.inbox.messages), before + 1)  # refused for good: not sent again
        self.assertEqual(self.inbox.script, [])
        with open(self.site.log.name) as f:
            log = f.read()
        self.assertIn('will try again', log)
        self.assertIn('refused it: 550', log)
        self.assertNotIn('/auth#t=', log)  # links never reach the log
        self.assertNotIn('grey@example.com', log)

    def test_5_test_email_command(self):
        before = len(self.inbox.messages)
        out = self.cli('testmail', 'me@example.com')
        self.assertIn('Sent a test email to me@example.com through 127.0.0.1', out.stdout)
        self.wait_for(before + 1)
        self.inbox.script[:] = ['550 5.7.1 blocked']
        out = self.cli('testmail', 'me@example.com')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('Not sent: 550', out.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
