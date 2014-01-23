Carson is a lightweight, "real-time" web interface for [rtorrent]. It doesn't aim to resemble a native, full-fledged UI like µtorrent web ui or rutorrent do. Instead it tries to remain simple while being very flexible and interactive.

Carson leverages the latest web technologies such as HTML5 Canvas for beautiful download progress rendering and WebSockets for "real-time," persistent updates on the state of downloads. It's written as a lightweight Python [Flask] application serving a simple JSON API to an [Angular.js] front-end.

[rtorrent]: http://libtorrent.rakshasa.no/
[Flask]: http://flask.pocoo.org/
[Angular.js]: http://angularjs.org/

* highly interactive interface
    * drag-and-drop file uploads
    * easy and fast filtering of downloads
    * "real-time" updates on the state of downloads
* designed with multiple users in mind
    * lock system, used to avoid deleting things others are still interested in
    * simple role-based authorization system
    * invitation system

# Installation

Pre-requisites are Python 2.x and [rtorrent]. It's probably also a good idea to do this all within a virtual environment with [virtualenv]. A webserver such as [nginx] is also recommended to serve static files. Auto-extraction requires [7z]. All of these things should be available via your package manager.

[virtualenv]: http://www.virtualenv.org/en/latest/virtualenv.html#installation
[nginx]: http://nginx.org/
[7z]: http://p7zip.sourceforge.net/

``` bash
$ git clone https://github.com/blaenk/carson.git
$ cd carson
$ virtualenv env
$ source env/bin/activate
$ pip install -r packages.txt
$ mv carson.conf{.example,}
$ python util.py init
```

# Configuration

Be sure to configure **carson.conf**. It has comments to explain every setting.

## rtorrent
Of course rtorrent also needs configuration via **~/.rtorrent.rc**:

``` ini
# choose one; local preferable
#scgi_local = /where/you/want/rpc.socket
#scgi_port = localhost:5000

encoding_list = UTF-8

# to preserve state between launches
session = /where/you/want/session/

# where to store downloaded files
directory = /where/you/want/downloads/

# to allow large torrent uploads to go through
set_xmlrpc_size_limit = 5242880

# auto-extract (optional; requiers 7z program)
system.method.set_key = event.download.finished,extract,"execute=/path/to/carson/util.py,extract,$d.get_name="

# auto-erase files (optional)
system.method.set_key = event.download.erased,erase,"execute=/path/to/carson/util.py,erase,$d.get_name="
```

## nginx

It's also preferable to use a webserver such as nginx to serve the static files:

``` nginx
client_max_body_size 10M;

location /sendfile/ {
  internal;
  alias /path/to/downloads/dir/;
}

location / {
  include uwsgi_params;
  uwsgi_pass unix:/tmp/uwsgi.sock;
}

location /assets/ {
  alias /path/to/carson/assets/;
  gzip_static on;
  expires max;
  add_header Cache-Control public;
}
```

# Running

A **uwsgi.ini.example** file is provided in the **uwsgi/** directory with some default settings for the uwsgi server. Change the settings pertinent to your setup and remove the `.example` from the filename, then run as:

``` bash
$ /path/to/carson/env/bin/uwsgi --ini /path/to/carson/uwsgi/uwsgi.ini
```

You can reload the server with:

``` bash
$ kill -HUP `cat /tmp/uwsgi.pid`
```

You can kill the server with:

``` bash
$ kill -QUIT `cat /tmp/uwsgi.pid`
```

## systemd

A systemd service file is provided in the **uwsgi/** folder which automates these tasks via systemd so that you can do:

``` bash
$ sudo systemctl start uwsgi@youruser
$ sudo systemctl restart uwsgi@youruser
$ sudo systemctl stop uwsgi@youruser
```

# Background Jobs

There are other utility functions in **util.py**. One of them is **prune** which goes through the downloads and checks which have expired (no locks and older than 2 weeks) and removes them. Another is **stale** which goes through the **top-level** downloads directory to find any files that don't correspond to downloads inside rtorrent and removes them. These can be automated as cron jobs inside a crontab such as the following:

```
*/5 * * * * /path/to/carson/util.py prune
@daily /path/to/carson/util.py stale
```

There's also an **add** utility which loads the file pointed to by its argument. This is particularly useful for integration with autodownloader systems.

``` bash
$ /path/to/carson/util.py add /tmp/somefile
```

**Note**: The **util.py** file has a hashbang pointing to `python2` since on my system `python` is python 3. If your system doesn't have a `python2` binary or symlink (check with `which python2`) then simply change the hashbang to `python`, which should be python 2.x (confirm with `python -V`).

