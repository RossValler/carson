#!/usr/bin/python2
import rtorrent
import sys
import os
import sha
import os.path
import shutil
import datetime
import subprocess
import glob
import sqlite3
from flaskext.bcrypt import generate_password_hash
from dateutil import parser
from configobj import ConfigObj

def get_conf():
    pre = os.path.dirname(os.path.abspath(__file__))
    return ConfigObj(os.path.join(pre, 'carson.conf'))

# simple/naive validation
def validate_path(path):
    base = get_conf()['rtorrent']['downloads']
    return os.path.exists(path) and path.startswith(base) and len(path.replace(base, '')) > 0

def add(args):
    path = args[0]
    file = open(path, 'rb')
    rtorrent.load_raw(file, 'system')

def erase(args):
    name = args[0]
    base = get_conf()['rtorrent']['downloads']
    path = os.path.join(base, name)

    if not validate_path(path):
        return

    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.remove(path)

def extract(args):
    name = args[0]
    base = get_conf()['rtorrent']['downloads']
    path = os.path.join(base, name)

    if not validate_path(path) and not os.path.isdir(path):
        return

    os.chdir(path)
    open('.extracting', 'a').close()

    for root, dirs, files in os.walk('.'):
        for name in [f for f in files if f.endswith('.rar')]:
            file = os.path.join(root, name)[2:]
            dir = file[:-4]
            cmd = ['7z', 'x', file, '-oextract/' + dir, '-y']
            subprocess.call(cmd)

    os.remove('.extracting')

def prune():
    ts = rtorrent.torrents('main', 'get_hash', 'get_custom=metadata')
    expired = []

    for t in ts:
        metadata = rtorrent.decode_metadata(t['metadata'])

        if metadata['locks']: continue

        date = parser.parse(metadata['date']).replace(tzinfo=None)
        # TODO: conf expiration
        expires_at = date + datetime.timedelta(weeks=2)
        now = datetime.datetime.utcnow()

        if now > expires_at and not metadata['locks']:
            expired.append(t['hash'])

    rtorrent.erase(expired)

def stale():
    base = get_conf()['rtorrent']['downloads']
    resident = set(glob.glob(os.path.join(base, '*')))
    current = set([os.path.join(base, res['name'])
                   for res in rtorrent.torrents('main', 'get_name')])
    stale = resident - current

    for path in stale:
        # should never happen
        if path == base: continue

        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

def init():
    db = sqlite3.connect('carson.db')
    cursor = db.cursor()

    with open('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())

    email = raw_input("email: ")
    name = raw_input("name: ")
    password = raw_input("password: ")
    pw = generate_password_hash(password)
    token = token = sha.new(os.urandom(64)).hexdigest()

    cursor.execute('INSERT INTO users(email, name, password, token, role)'
                   'VALUES (?, ?, ?, ?, ?)',
                   (email, name, pw, token, 'admin'))

    db.commit()

    secret_key = os.urandom(24)
    conf = get_conf()
    conf['carson']['secret_key'] = secret_key
    conf.write()

if __name__ == "__main__":
    action = sys.argv[1]
    args = sys.argv[2:]

    if action == 'add':
        add(args)
    elif action == 'erase':
        erase(args)
    elif action == 'extract':
        extract(args)
    elif action == 'prune':
        prune()
    elif action == 'stale':
        stale()
    elif action == 'init':
        init()
    else:
        print "invalid parameter"

