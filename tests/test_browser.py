#!/usr/bin/env python3
"""
The whole customer journey in a real browser, on a phone-sized screen: the demo, sign-up, the
emailed link, editing and saving the page, then a member of the public getting a quote from it.

The plain HTTP tests in test_app.py cannot see what a browser really sends or does. This file
exists because three faults only showed up here: a refused sign-up form, a sign-in that did not
stick on a reused connection, and a logo that uploaded twice.

Needs Playwright and Chrome or Chromium:  python3 tests/test_browser.py
(set QP_CHROME to the browser's path if it is not found)
"""
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_app import Site  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

CHROME = os.environ.get('QP_CHROME') or next((p for p in ('/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser') if os.path.exists(p)), None)
PHONE = dict(viewport={'width': 390, 'height': 780}, device_scale_factor=2, is_mobile=True, has_touch=True)


def logo_file(folder, w=900, h=360):
    """A big see-through PNG with an orange oval, like a real logo file off someone's phone."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body) & 0xffffffff)
    rows = bytearray()
    for y in range(h):
        rows.append(0)
        for x in range(w):
            inside = (x - w / 2) ** 2 / (w * 0.42) ** 2 + (y - h / 2) ** 2 / (h * 0.42) ** 2 < 1
            rows += bytes((200, 80, 30, 255)) if inside else bytes((0, 0, 0, 0))
    path = os.path.join(folder, 'logo.png')
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
                + chunk(b'IDAT', zlib.compress(bytes(rows), 6)) + chunk(b'IEND', b''))
    return path


@unittest.skipUnless(sync_playwright and CHROME, 'needs Playwright and Chrome')
class Journey(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='qp-browser-')
        self.pw = sync_playwright().start()
        self.browser = self.pw.chromium.launch(executable_path=CHROME, args=['--no-sandbox'])
        self.faults = []

    def tearDown(self):
        self.browser.close()
        self.pw.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def page(self, who, **kw):
        page = self.browser.new_context(**dict(PHONE, **kw)).new_page()
        own_warning = 'Quote page settings:'  # the page tells an owner, in the console, what their settings lack
        page.on('console', lambda m: self.faults.append((who, m.type, m.text[:200])) if m.type == 'error' or (m.type == 'warning' and own_warning not in m.text) else None)
        page.on('pageerror', lambda err: self.faults.append((who, 'pageerror', str(err)[:200])))
        page.on('requestfailed', lambda r: self.faults.append((who, 'failed', r.url[:120])) if 'fonts.g' not in r.url else None)
        page.on('response', lambda r: self.faults.append((who, r.status, r.url[:120])) if r.status >= 400 else None)
        return page

    def fits(self, page, where):
        over = page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
        self.assertLessEqual(over, 1, f'{where}: the page is wider than the screen')

    def emailed_link(self, site, to):
        mail = [m for m in site.mails() if m['to'] == to][-1]
        return re.search(r'(http\S+/auth#t=\S+)', mail['body']).group(1)

    def test_from_demo_to_a_quote(self):
        site = Site()
        try:
            # ---- a tree business owner finds the demo, tries prices, and decides to make a page
            dave = self.page('dave')
            dave.goto(site.base + '/')
            dave.locator('.sell-cta').wait_for(state='attached')
            dave.click('#sell-jump')
            dave.locator('.sell-cta').wait_for(state='visible')  # sign-up is open, so the demo offers it
            self.assertFalse(dave.locator('.sell-how.when-closed').is_visible())
            self.fits(dave, 'demo')
            dave.click('#sell-prices')
            dave.fill('[data-path="prices.minimumJob"]', '350')
            dave.click('#qs-make')
            dave.wait_for_url('**/start')
            self.assertTrue(dave.locator('#carry').is_visible())
            self.fits(dave, 'sign-up form')

            # ---- he mistypes, and is told what to fix without losing what he typed
            dave.fill('#business', "Dave's Tree & Stump")
            dave.fill('#mobile', '9388 1234')
            dave.fill('[name=email]', 'dave@davestrees.example')
            dave.wait_for_timeout(2200)  # the form ignores anything sent back faster than a person types
            dave.click('button[type=submit]')
            dave.locator('.err').wait_for()
            self.assertIn('mobile number', dave.locator('.err').inner_text())
            self.assertEqual(dave.input_value('#business'), "Dave's Tree & Stump")
            self.assertGreater(len(dave.input_value('#settings')), 100)  # the demo prices are still attached
            dave.fill('#mobile', '0412 345 678')
            dave.click('button[type=submit]')
            dave.wait_for_selector('text=Check your email')

            # ---- the email, and the link in it
            link = self.emailed_link(site, 'dave@davestrees.example')
            dave.goto(link)
            self.assertNotIn('t=', dave.url)  # the code is taken out of the address bar straight away
            dave.click('#go')
            dave.wait_for_selector('#qs-save')  # signed in, on his own page, with the edit screen open
            self.assertTrue(dave.url.endswith('/daves-tree-and-stump?setup'))
            self.assertIn('/daves-tree-and-stump', dave.locator('.qs-head').inner_text())
            self.assertEqual(dave.evaluate('window.QuotePage.settings().prices.minimumJob'), 350)
            self.fits(dave, 'edit screen')

            # ---- logo (one upload per pick), colour, suburb
            uploads = []
            dave.on('request', lambda r: uploads.append(r.url) if r.url.endswith('/api/logo') else None)
            dave.set_input_files('#qs-logo-file', logo_file(self.tmp))
            dave.locator('#qs-logo-status').filter(has_text='Logo saved').wait_for(timeout=8000)
            self.assertEqual(len(uploads), 1)
            dave.wait_for_timeout(300)
            self.assertTrue(dave.evaluate("(() => { const i = document.querySelector('#qw-logo img'); return !!i && i.complete && i.naturalWidth > 0 && i.naturalWidth <= 640; })()"))
            dave.fill('[data-path="baseSuburb"]', 'Midland')
            dave.evaluate("""() => { const c = document.querySelector('[data-path="colour"]'); c.value = '#8a2be2'; c.dispatchEvent(new Event('input', { bubbles: true })); }""")

            # ---- Close with nothing saved: warned once, and the Save button is on screen without scrolling
            dave.click('#qs-close')
            self.assertIn('Not saved yet', dave.locator('#qs-status').inner_text())
            self.assertTrue(dave.locator('#qs-save').is_visible())
            box = dave.locator('#qs-save').bounding_box()
            self.assertLess(box['y'] + box['height'], 781)
            dave.click('#qs-save')
            dave.locator('#qs-status').filter(has_text='Saved').wait_for(timeout=8000)
            dave.click('#qs-close')
            self.assertFalse(dave.locator('#qw-setup').is_visible())
            self.assertTrue(dave.locator('.sell-bar').is_visible())  # his own bar: Edit my page, My account
            self.fits(dave, 'own page')

            # ---- a member of the public, on another phone
            jo = self.page('jo')
            jo.goto(site.base + '/daves-tree-and-stump?setup')
            jo.wait_for_selector('#qw-logo img')
            self.assertFalse(jo.locator('#qw-setup').is_visible())  # the owner's screen never opens for anyone else
            self.assertEqual(jo.locator('.sell-bar').count(), 0)
            self.assertEqual(jo.title(), "Dave's Tree & Stump: tree quote")
            self.assertEqual(jo.evaluate('window.QuotePage.settings().colour'), '#8a2be2')
            jo.click('text=Remove a tree')
            for _ in range(8):
                step = jo.evaluate("[...document.querySelectorAll('.qw-step')].find(s => !s.hidden).dataset.step")
                self.fits(jo, 'quote step ' + step)
                if step == 'result':
                    break
                if step == 'details':
                    jo.fill('#qw-street', '14 Smith Street')
                    jo.fill('#qw-suburb', 'Guildford')
                    jo.locator('#qw-list [role=option]').first.click()
                    jo.fill('#qw-name', 'Jo Customer')
                    jo.fill('#qw-phone', '0433 222 111')
                jo.click('#qw-next')
                jo.wait_for_timeout(300)
            self.assertEqual(step, 'result')
            links = jo.evaluate("[...document.querySelectorAll('#qw-result a')].map(a => a.getAttribute('href'))")
            self.assertTrue(any(h.startswith('sms:0412345678') for h in links), links)  # the job goes to Dave's phone
            self.assertIn('tel:0412345678', links)

            # ---- Dave signs out, and gets back in another day with just his email
            dave.goto(site.base + '/my')
            self.fits(dave, 'account page')
            dave.click('text=Sign out')
            dave.wait_for_url('**/signin')
            dave.goto(site.base + '/daves-tree-and-stump')
            self.assertEqual(dave.locator('.sell-bar').count(), 0)
            dave.goto(site.base + '/signin')
            dave.fill('[name=email]', ' Dave@DavesTrees.example')
            dave.click('button[type=submit]')
            dave.wait_for_selector('text=Check your email')
            again = self.emailed_link(site, 'dave@davestrees.example')
            self.assertNotEqual(again, link)
            dave.goto(again)
            dave.click('#go')
            dave.wait_for_url('**/my')
            self.assertEqual(self.faults, [])

            # ---- the same link a second time
            late = self.page('late')
            late.goto(again)
            late.click('#go')
            late.wait_for_selector('text=already used')
        finally:
            site.stop()

    def test_demo_does_not_offer_sign_up_until_it_works(self):
        site = Site(mail=False)
        try:
            page = self.page('visitor')
            page.goto(site.base + '/')
            page.click('#sell-jump')
            page.wait_for_timeout(600)
            self.assertTrue(page.locator('.sell-how.when-closed').is_visible())
            self.assertFalse(page.locator('.sell-cta').is_visible())
            self.assertIn('Text Matt', page.locator('.sell-how.when-closed').inner_text())
            page.click('#sell-prices')
            self.assertEqual(page.locator('#qs-make').count(), 0)
            self.assertEqual(self.faults, [])
        finally:
            site.stop()


if __name__ == '__main__':
    unittest.main(verbosity=2)
