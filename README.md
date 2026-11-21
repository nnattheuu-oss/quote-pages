# quote-pages

Instant quote page for tree businesses, with a page for each business that buys it.

- `index.html` is the whole quote page in one file. On its own it is the sales demo.
- `app/server.py` gives each business its own page at `/<their-name>`, with their logo,
  colour and prices. They sign in with a one-time link sent to their email. No passwords.
- The owner (the seller) gets an owner page at `/owner`: who has signed up, mark paid, turn
  off, make a sign-in link to text to someone, add a business by hand.

Python standard library only. Nothing to install.

## How a business gets a page

1. On the demo they press **Make my page** and give a business name, mobile and email.
2. They press the link in the email. Their page opens with the edit screen showing.
3. They add a logo, pick a colour, set prices and press **Save my page**.

A new page is a free trial (14 days by default). After that, or if the owner turns it off,
the page shows the business name and a Call button but not the quote form. The owner presses
**Mark paid** when they pay. Nothing is ever charged automatically: there is no payment system.

The demo only offers **Make my page** when sign-in emails are switched on. Until then it says
"text Matt", as before.

## Run it on your own computer

    QP_DEV_OUTBOX=/tmp/outbox.jsonl QP_ADMIN_EMAIL=you@example.com python3 app/server.py

Then open http://127.0.0.1:7871. Emails are written to `/tmp/outbox.jsonl` instead of sent.

## Tests

    python3 tests/test_app.py        # the service, over real HTTP
    python3 tests/test_browser.py    # the whole customer journey in a real browser (needs Playwright and Chrome)
    python3 tests/test_mail.py       # the server's own signed email, against a pretend mail server

## On the server

- Code: `/srv/quote-pages` (this repo). Update with `git -C /srv/quote-pages pull`, then
  `systemctl restart quote-pages` if anything under `app/` or `index.html` changed.
- Service: `quote-pages` (`deploy/quote-pages.service`), its own user, loopback port 7871.
- Settings: `/etc/quote-pages/env` (see `deploy/env.example`). Root only. Never in this repo.
- Data: `/var/lib/quote-pages` (accounts database and logos). Back this folder up.
- Web server: Caddy serves `/` from `index.html` and passes everything else to the service.
  The block it uses is `deploy/Caddyfile.treejobquote`.

Handy commands, as root:

    python3 /srv/quote-pages/deploy/set-mail.py     # set up or change the email-sending service
    cd /srv/quote-pages && set -a && . /etc/quote-pages/env && set +a
    python3 app/server.py link someone@example.com  # a one-time sign-in link, to text to them
    python3 app/server.py add someone@example.com "0412 345 678" Their Business Name
    python3 app/server.py remove someone@example.com
    python3 app/server.py testmail you@example.com
    python3 tests/smoke.py                          # check the running service end to end (makes and deletes a throwaway page)

## Sign-in emails

The server sends them itself, straight to the other person's mail server, signed for the
domain (DKIM). No outside service or password is involved. Three DNS records make other mail
servers trust them: SPF, DKIM and DMARC.

    python3 app/server.py mailkey     # makes the signing key once, prints the three records
    python3 app/server.py mailcheck   # checks the records are in the DNS and right
    python3 app/server.py testmail you@example.com

If mail to some provider keeps going to spam or being refused, switch to a sending service
with `python3 deploy/set-mail.py`. Once that is set, it is used instead. Meanwhile the owner
page's **Sign-in link** button makes a link you can text to anyone whose email does not arrive.

## What is kept, and where

For each business: email address, the settings on their page (name, mobile, prices and so on)
and their logo file. Sign-in links and sessions are stored only as hashes. Jobs sent by
customers never touch this server: they go by text from the customer's own phone, or by email
through Web3Forms if the business sets a key.
