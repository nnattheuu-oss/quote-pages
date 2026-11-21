#!/usr/bin/env python3
"""
Set up the service that sends sign-in emails. Run as root on the server:

    python3 /srv/quote-pages/deploy/set-mail.py

It asks a few questions, saves the answers in /etc/quote-pages/env, restarts the service and
offers to send a test email. The password or key is never shown on screen.
"""
import getpass
import os
import re
import subprocess
import sys

ENV = '/etc/quote-pages/env'
SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'app', 'server.py')


def read_env():
    values = {}
    with open(ENV, encoding='utf-8') as f:
        for line in f:
            m = re.match(r'^([A-Z_]+)=(.*)$', line.rstrip('\n'))
            if m:
                v = m.group(2).strip()
                if len(v) >= 2 and v[0] == v[-1] == '"':
                    v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                values[m.group(1)] = v
    return values


def write_env(changes):
    quote = lambda v: '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
    with open(ENV, encoding='utf-8') as f:
        lines = f.read().splitlines()
    seen = set()
    for i, line in enumerate(lines):
        m = re.match(r'^([A-Z_]+)=', line)
        if m and m.group(1) in changes:
            lines[i] = f'{m.group(1)}={quote(changes[m.group(1)])}'
            seen.add(m.group(1))
    lines += [f'{k}={quote(v)}' for k, v in changes.items() if k not in seen]
    tmp = ENV + '.new'
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    st = os.stat(ENV)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, ENV)


def ask(label, default=''):
    answer = input(f'{label}{f" [{default}]" if default else ""}: ').strip()
    return answer or default


def main():
    if os.geteuid() != 0:
        sys.exit('Run this as root.')
    now = read_env()
    print('\nSign-in emails need a sending service. This saves its details.\n')
    print('  1  Resend (smtp.resend.com). You only need the API key.')
    print('  2  Another service. You need its server name, port, user name and password.\n')
    choice = ask('Which one', '1')
    if choice == '1':
        new = {'QP_SMTP_HOST': 'smtp.resend.com', 'QP_SMTP_PORT': '465', 'QP_SMTP_SECURITY': 'ssl', 'QP_SMTP_USER': 'resend'}
        secret_label = 'Resend API key (starts with re_). It will not show as you type or paste'
    else:
        new = {
            'QP_SMTP_HOST': ask('Server name', now.get('QP_SMTP_HOST', '')),
            'QP_SMTP_PORT': ask('Port (465 or 587)', now.get('QP_SMTP_PORT', '465')),
            'QP_SMTP_USER': ask('User name', now.get('QP_SMTP_USER', '')),
        }
        new['QP_SMTP_SECURITY'] = 'starttls' if new['QP_SMTP_PORT'] in ('587', '25', '2587') else 'ssl'
        secret_label = 'Password or key. It will not show as you type or paste'
    new['QP_MAIL_FROM'] = ask('Send from', now.get('QP_MAIL_FROM', 'Tree Job Quote <signin@treejobquote.tech>'))
    secret = getpass.getpass(secret_label + ': ').strip()
    if not secret:
        sys.exit('Nothing typed. Nothing was changed.')
    new['QP_SMTP_PASS'] = secret
    if not new['QP_SMTP_HOST'] or not new['QP_SMTP_PORT'].isdigit():
        sys.exit('The server name or port is missing. Nothing was changed.')
    write_env(new)
    print('\nSaved. Restarting the service...')
    subprocess.run(['systemctl', 'restart', 'quote-pages'], check=False)
    to = ask('\nSend a test email to (leave empty to skip)')
    if to:
        env = dict(os.environ)
        env.update(read_env())
        done = subprocess.run([sys.executable, SERVER, 'testmail', to], env=env)
        if done.returncode != 0:
            print('\nThe test email did not send. The message above says why. Run this again to fix the details.')
            sys.exit(1)
        print('Check that inbox (and its spam folder).')
    print('\nDone. Sign-up and sign-in emails are switched on.')


if __name__ == '__main__':
    main()
