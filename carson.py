from flask import Flask, request, make_response, send_file, send_from_directory, session, abort, g
from flaskext.bcrypt import Bcrypt

from datetime import timedelta, datetime
import sqlite3
import json
import os
import sha
import os.path
import time

import rtorrent
import util

import uwsgi
import gevent

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.permanent_session_lifetime = timedelta(weeks=4)

bcrypt = Bcrypt(app)

app.secret_key = util.get_conf()['carson']['secret_key']

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('carson.db')
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_request
def before_request():
    token = session.get('token')
    exempt = ['auth', 'root']
    invitation_check = request.endpoint == 'invitation' and request.method == 'GET'
    new_account = request.endpoint == 'users' and request.method == 'POST'

    if token is None and request.endpoint not in exempt and not invitation_check and not new_account:
        abort(401)

    user = get_current_user(token)

    if user is None and request.endpoint not in exempt and not invitation_check and not new_account:
        abort(401)

# TODO: stop sending updates once all files are 100% and done extracting?
@app.route('/ws/download/<hash>')
def ws_download(hash):
    uwsgi.websocket_handshake()
    while True:
        uwsgi.websocket_recv_nb() # for close()
        gevent.sleep(2)

        try:
            payload = json.dumps(rtorrent.download(hash))
        except:
            payload = json.dumps({'error': "can't connect to rtorrent"})

        uwsgi.websocket_send(payload)

@app.route('/ws/downloads')
def ws_downloads():
    uwsgi.websocket_handshake()
    while True:
        uwsgi.websocket_recv_nb() # for close()
        gevent.sleep(2)

        try:
            payload = json.dumps(rtorrent.downloads())
        except:
            payload = json.dumps({'error': "can't connect to rtorrent"})

        uwsgi.websocket_send(payload)

def token_for_user(name):
    c = get_db().cursor()
    c.execute('SELECT token FROM users WHERE name = ?', (name,))

    res = c.fetchone()

    if res is None:
        return None
    else:
        return res['token']

# upload: upload, magnet
#   member+
# lock: /lock/<hash>.json GET
#   member+
# view_trackers: /browse.json GET
#   member+
# admin_tracker: /browse.json POST, PUT, DELETE
#   admin
# admin_invitations: /inviations.json POST, PUT, DELETE
#   admin
# admin_users: /users.json GET, POST, PUT, DELETE
#   admin

def is_member(user):
    return user['role'] == 'member'

def is_admin(user):
    return user['role'] == 'admin'

def authorize(user, to):
    if to == 'upload':
        return is_member(user) or is_admin(user)
    elif to == 'lock':
        return is_member(user) or is_admin(user)
    elif to == 'view_trackers':
        return is_member(user) or is_admin(user)
    elif to == 'admin_trackers':
        return is_admin(user)
    elif to == 'admin_invitations':
        return is_admin(user)
    elif to == 'admin_users':
        return is_admin(user)
    else:
        return false

def get_current_user(token):
    c = get_db().cursor()
    c.execute('SELECT id, name, role FROM users WHERE token = ?', (token,))

    res = c.fetchone()

    if res is None:
        return None
    else:
        user = dict()
        user['id'], user['name'], user['role'] = res
        return user

@app.route('/auth', methods=['POST'])
def auth():
    name = request.json.get('name')
    password = request.json.get('password')

    c = get_db().cursor()
    c.execute('SELECT password FROM users WHERE name = ?', (name,))

    digest = c.fetchone()

    if digest is None:
        abort(401)

    if bcrypt.check_password_hash(digest['password'], password):
        token = token_for_user(name)
        session.permanent = True
        session['token'] = token
        return json.dumps(get_current_user(token))
    else:
        abort(401)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('token', None)
    return json.dumps({'logged_out': True})

@app.route('/current_user', methods=['GET'])
def current_user():
    token = session.get('token')

    if token is None:
        abort(401)

    user = get_current_user(token)

    if user is None:
        abort(401)
    else:
        return json.dumps(user)

@app.route('/file/<path:file>')
def file(file):
    base = os.path.basename(file)
    downloadsDir = util.get_conf()['rtorrent']['downloads']
    absPath = os.path.join(downloadsDir, file)
    sendfilePath = os.path.join('/sendfile', file)

    response = make_response()
    response.headers['Content-Disposition'] = 'filename="' + base + '"'
    response.headers['Content-Type'] = ''
    response.headers['X-Accel-Redirect'] = sendfilePath
    return response

@app.route('/magnet', methods=['POST'])
def magnet():
    user = get_current_user(session['token'])

    if not authorize(user, 'upload'):
        abort(401)

    hash = rtorrent.load_magnet(request.json['magnet'], user['name'])
    tdata = rtorrent.torrent(hash,
                             'get_name',
                             'get_ratio',
                             'get_complete',
                             'get_directory',
                             'is_hash_checking',
                             'is_active',
                             'is_open',
                             'get_size_bytes',
                             'get_size_chunks',
                             'get_completed_chunks',
                             'get_message',
                             'get_custom=metadata')

    tdata['hash'] = hash
    download = rtorrent.create_download(tdata)
    return json.dumps(download, sort_keys=True)

@app.route('/upload', methods=['POST'])
def upload():
    user = get_current_user(session['token'])

    if not authorize(user, 'upload'):
        abort(401)

    hash = rtorrent.load_raw(request.files['file'], user['name'])

    if hash is None:
        abort(422)

    tdata = rtorrent.torrent(hash,
                             'get_name',
                             'get_ratio',
                             'get_complete',
                             'get_directory',
                             'is_hash_checking',
                             'is_active',
                             'is_open',
                             'get_size_bytes',
                             'get_size_chunks',
                             'get_completed_chunks',
                             'get_message',
                             'get_custom=metadata')

    tdata['hash'] = hash
    download = rtorrent.create_download(tdata)
    return json.dumps(download, sort_keys=True)

@app.route('/browse.json', methods=['GET', 'POST'])
def browse():
    c = get_db().cursor()
    user = get_current_user(session['token'])

    if request.method == 'POST':
        if not authorize(user, 'admin_trackers'):
            abort(401)

        # TODO: validate
        name = request.json.get('name')
        url = request.json.get('url')
        user = request.json.get('user')
        password = request.json.get('password')
        category = request.json.get('category')

        c.execute('INSERT INTO trackers(name, url, user, password, category)'
                  'VALUES (?, ?, ?, ?, ?)', (name, url, user, password, category))
        get_db().commit()
        request.json['id'] = c.lastrowid
        return json.dumps(request.json)
    elif request.method == 'GET':
        if not authorize(user, 'view_trackers'):
            abort(401)

        c.execute('SELECT id, name, url, user, password, category FROM trackers ORDER BY name')
        trackers = []

        for row in c:
            tracker = dict()
            tracker['id'] = row['id']
            tracker['name'] = row['name']
            tracker['url'] = row['url']
            tracker['user'] = row['user']
            tracker['password'] = row['password']
            tracker['category'] = row['category']
            trackers.append(tracker)

    return json.dumps(trackers)

@app.route('/browse/<int:id>.json', methods=['PUT', 'DELETE'])
def browse_id(id):
    c = get_db().cursor()
    user = get_current_user(session['token'])

    if request.method == 'PUT':
        if not authorize(user, 'admin_trackers'):
            abort(401)

        name = request.json.get('name')
        url = request.json.get('url')
        user = request.json.get('user')
        password = request.json.get('password')
        category = request.json.get('category')

        c.execute('UPDATE trackers SET name = ?, url = ?, user = ?, password = ?, category = ? WHERE id = ?',
                  (name, url, user, password, category, id))
        get_db().commit()
        return json.dumps({})
    elif request.method == 'DELETE':
        if not authorize(user, 'admin_trackers'):
            abort(401)

        c.execute('DELETE FROM trackers WHERE id = ?', (id,))
        get_db().commit()
        return json.dumps({})

@app.route('/invitations.json', methods=['GET', 'POST'])
def invitations():
    c = get_db().cursor()
    user = get_current_user(session['token'])

    if request.method == 'POST':
        if not authorize(user, 'admin_invitations'):
            abort(401)

        token = sha.new(os.urandom(64)).hexdigest()
        now = datetime.utcnow()

        c.execute('INSERT INTO invitations(token, created_at) VALUES(?, ?)', (token, now))
        get_db().commit()
        id = c.lastrowid
        return json.dumps({'token': token, 'created_at': now.isoformat(), 'id': id})
    elif request.method == 'GET':
        if not authorize(user, 'admin_invitations'):
            abort(401)

        c.execute('SELECT id, token, created_at FROM invitations')
        invites = []

        for row in c:
            invite = dict()
            invite['id'] = row['id']
            invite['token'] = row['token']
            invite['created_at'] = row['created_at']
            invites.append(invite)

        return json.dumps(invites)

@app.route('/invitations/<token>.json', methods=['GET', 'DELETE'])
def invitation(token):
    c = get_db().cursor()

    if request.method == 'GET':
        c.execute('SELECT id, token, created_at FROM invitations WHERE token = ?', (token,))
        token = c.fetchone()

        if token is None:
            abort(404)

        return json.dumps({'token': token['token']})
    elif request.method == 'DELETE':
        user = get_current_user(session['token'])
        if not authorize(user, 'admin_invitations'):
            abort(401)

        c.execute('DELETE FROM invitations WHERE token = ?', (token,))
        get_db().commit()
        return json.dumps({})

@app.route('/users.json', methods=['GET', 'POST'])
def users():
    c = get_db().cursor()

    if request.method == 'POST':
        token = request.json.get('token')

        if token is None:
            abort(404)

        c.execute('SELECT * FROM invitations WHERE token = ?', (token,))
        res = c.fetchone()

        if res is None:
            abort(404)

        # TODO: validate
        email = request.json.get('email')
        name = request.json.get('name')
        password = request.json.get('password')

        c.execute('INSERT INTO users(email, name, password, token, role)'
                  'VALUES (?, ?, ?, ?, ?)', (email, name, password, token, 'member'))
        get_db().commit()
        id = c.lastrowid

        c.execute('DELETE FROM invitations WHERE token = ?', (token,))
        get_db().commit()

        session['token'] = token
        return json.dumps({})
    elif request.method == 'GET':
        user = get_current_user(session['token'])
        if not authorize(user, 'admin_users'):
            abort(401)

        c.execute('SELECT id, email, name, password, token, role FROM users')
        trackers = []

        for row in c:
            tracker = dict()
            tracker['id'] = row['id']
            tracker['email'] = row['email']
            tracker['name'] = row['name']
            tracker['password'] = row['password']
            tracker['token'] = row['token']
            tracker['role'] = row['role']
            trackers.append(tracker)

        return json.dumps(trackers)

@app.route('/users/<int:id>.json', methods=['PUT', 'DELETE'])
def user_id(id):
    c = get_db().cursor()
    user = get_current_user(session['token'])

    if request.method == 'PUT':
        if not authorize(user, 'admin_users'):
            abort(401)

        email = request.json.get('email')
        name = request.json.get('name')
        role = request.json.get('role')

        c.execute('UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?',
                  (name, email, role, id))
        get_db().commit()
        return json.dumps({})
    elif request.method == 'DELETE':
        if not authorize(user, 'admin_users'):
            abort(401)

        c.execute('DELETE FROM users WHERE id = ?', (id,))
        get_db().commit()
        return json.dumps({})

@app.route('/lock/<hash>.json')
def lock(hash):
    user = get_current_user(session['token'])

    if not authorize(user, 'lock'):
        abort(401)

    metadata = rtorrent.get_metadata(hash)
    locked = 'unlocked'

    if user['name'] in metadata['locks']:
        metadata['locks'].remove(user['name'])
    else:
        metadata['locks'].append(user['name'])
        locked = 'locked'

    rtorrent.set_metadata(hash, metadata)
    return json.dumps({'action': locked})

@app.route('/downloads.json')
def downloads():
    try:
        return json.dumps(rtorrent.downloads())
    except:
        abort(503)

@app.route('/download/<hash>.json')
def download(hash):
    try:
        return json.dumps(rtorrent.download(hash))
    except:
        abort(503)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def root(path):
    return send_file('assets/html/index.html')

def assets(asset):
    return send_from_directory('assets/', asset)

if False:
    app.add_url_rule('/assets/<path:asset>', 'assets', assets)

# if __name__ == '__main__':
#     app.debug = True
#     app.run()

