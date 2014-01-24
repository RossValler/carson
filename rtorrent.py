import xmlrpclib
from scgiclient import SCGIServerProxy
from math import trunc
import StringIO
import base64
import bencode
import datetime
import dateutil.parser
import hashlib
import json
import os.path
import re
import glob

import util

def rpc_path():
    return 'scgi://' + util.get_conf()['rtorrent']['rpc']

def load_raw(file, user):
    rtorrent = SCGIServerProxy(rpc_path())
    contents = file.read()

    try:
        decoded = bencode.bdecode(contents)
    except bencode.BTFailure:
        return None

    # regular torrent or magnet link
    if 'info' in decoded:
        encodedInfo = bencode.bencode(decoded['info'])
        hash = hashlib.sha1(encodedInfo).hexdigest()
    else:
        hash = re.search(r'urn:btih:([^&/]+)', contents).group(1)

    metadata = { 'user': user
               , 'date': datetime.datetime.utcnow().isoformat()
               , 'locks': [] }
    encodedMetadata = encode_metadata(metadata)

    rtorrent.load_raw_start(xmlrpclib.Binary(contents),
                            'd.set_custom=metadata,' + encodedMetadata)

    return hash

def load_magnet(magnet_uri, user):
    mag = StringIO.StringIO('d10:magnet-uri{0}:{1}e'.format(len(magnet_uri), magnet_uri))
    return load_raw(mag, user)

def encode_metadata(metadata):
    return base64.b64encode(json.dumps(metadata))

def decode_metadata(metadata):
    return json.loads(base64.b64decode(metadata))

def get_metadata(hash):
    rtorrent = SCGIServerProxy(rpc_path())
    return decode_metadata(rtorrent.d.get_custom(hash, 'metadata'))

def set_metadata(hash, metadata):
    rtorrent = SCGIServerProxy(rpc_path())
    return rtorrent.d.set_custom(hash, 'metadata', encode_metadata(metadata))

def progress(completed, size):
    if size == 0:
        return 0
    else:
        return (completed / float(size)) * 100

def state(active, complete, open, hashing):
    state = ""

    if not active:
        state = "stopped"
    elif not complete:
        state = "downloading"
    else:
        state = "seeding"

    if not open:
        state = "closed"

    if hashing:
        state = "hashing"

    return state

def human_size(num):
    for x in ['B','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

def create_download(tdata):
    st = state(tdata['active'], tdata['complete'],
               tdata['open'], tdata['hash_checking'])

    prog = progress(tdata['completed_chunks'], tdata['size_chunks'])
    prog = "{:d}".format(trunc(prog))

    ratio = tdata['ratio'] / float(1000)

    metadata = decode_metadata(tdata['metadata'])

    return {'hash': tdata['hash'].lower(),
            'name': tdata['name'],
            'message': tdata['message'],
            'ratio': ratio,
            'progress': prog,
            'state': st,
            'metadata': metadata}

def create_files(path, files, multi_file):
    fs = []

    for file in files:
        fdata = dict()

        fdata['path'] = file['path']
        fdata['sendpath'] = os.path.join(os.path.basename(path), file['path'])
        fdata['priority'] = file['priority']

        prog = progress(file['completed_chunks'], file['size_chunks'])
        fdata['progress'] = "{:d}".format(trunc(prog))

        fdata['size'] = human_size(file['size_bytes'])

        fs.append(fdata)

    if not multi_file:
        fs[0]['sendpath'] = fs[0]['path']

    return fs

def torrents(view, *methods):
    rtorrent = SCGIServerProxy(rpc_path())
    pretty = re.compile(r'is_|get_|=|custom')
    prettify = lambda str: pretty.sub(r'', str)
    calls = []

    for method in methods:
        if "=" in method:
            calls.append("d." + method)
        else:
            calls.append("d." + method + "=")

    results = rtorrent.d.multicall(view, *calls)
    downloads = []

    for result in results:
        tdata = dict()

        for method, res in zip(methods, result):
            tdata[prettify(method)] = res

        downloads.append(tdata)

    return downloads

def erase(torrents):
    rtorrent = SCGIServerProxy(rpc_path())
    mc = xmlrpclib.MultiCall(rtorrent)

    for torrent in torrents:
        mc.d.erase(torrent)

    return mc()

def torrent(hash, *methods):
    rtorrent = SCGIServerProxy(rpc_path())
    mc = xmlrpclib.MultiCall(rtorrent)
    pretty = re.compile(r'is_|get_|=|custom')
    prettify = lambda str: pretty.sub(r'', str)

    for method in methods:
        if method.startswith("get_custom"):
            getattr(mc, "d.get_custom")(hash, method[11:])
        else:
            getattr(mc, "d." + method)(hash)

    results = mc()
    tdata = dict()

    for method, result in zip(methods, results):
        tdata[prettify(method)] = result

    return tdata

# def torrent_calls(mc, *methods):
#     pretty = re.compile(r'is_|get_|=|custom')
#     prettify = lambda str: pretty.sub(r'', str)
# 
#     for method in methods:
#         getattr(mc, "d." + method)(hash)
# 
#     return mc

def files(hash, *methods):
    rtorrent = SCGIServerProxy(rpc_path())
    pretty = re.compile(r'is_|get_|=|custom')
    prettify = lambda str: pretty.sub(r'', str)

    calls = ["f." + method + "=" for method in methods]
    results = rtorrent.f.multicall(hash, 0, *calls)
    fs = []

    for result in results:
        fdata = dict()

        for method, res in zip(methods, result):
            fdata[prettify(method)] = res

        fs.append(fdata)

    return fs

def download(hash):
    tdata = torrent(hash,
                    'get_name',
                    'get_ratio',
                    'get_complete',
                    'get_directory',
                    'is_hash_checking',
                    'is_active',
                    'is_open',
                    'is_multi_file',
                    'get_size_bytes',
                    'get_size_chunks',
                    'get_completed_chunks',
                    'get_message',
                    'get_custom=metadata')

    tdata['hash'] = hash
    download = create_download(tdata)

    fdata = files(hash,
                  'get_path',
                  'get_priority',
                  'get_size_chunks',
                  'get_completed_chunks',
                  'get_size_bytes')
    fs = create_files(tdata['directory'], fdata, tdata['multi_file'])
    download['files'] = fs

    # only directories are extracted
    if tdata['multi_file']:
        base = util.get_conf()['rtorrent']['downloads']
        path = os.path.join(base, tdata['name'])
        extracting = os.path.join(path, '.extracting')

        if os.path.exists(extracting):
            download['extracting'] = True
        else:
            extract = os.path.join(path, 'extract')

            if os.path.exists(extract):
                download['extracting'] = False
                download['extract'] = []

                cwd = os.getcwd()
                os.chdir(extract)

                for root, dirs, fs in os.walk('.'):
                    for name in fs:
                        file = os.path.join(root, name)[2:]
                        download['extract'].append({'path': file,
                                                    'size': human_size(os.stat(file).st_size)})

                os.chdir(cwd)

    return download

def downloads():
    ts = torrents('main',
                  'get_hash',
                  'get_name',
                  'get_ratio',
                  'get_complete',
                  'is_hash_checking',
                  'is_active',
                  'is_open',
                  'get_size_bytes',
                  'get_size_chunks',
                  'get_completed_chunks',
                  'get_message',
                  'get_custom=metadata')

    downloads = [create_download(torrent) for torrent in ts]
    return downloads

