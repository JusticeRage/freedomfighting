#!/usr/bin/env python3
"""
    notify_hook.py by @JusticeRage

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

import os
import re
import subprocess
import sys


# A list of processes that won't cause a notification to fire. This is useful for system script that are
# called on a regular basis to prevent generating useless alerts.
# Regular expressions are allowed in this list.
CALLER_WHITELIST = []

###############################################################################
# EDIT THE THE CODE BELOW TO CHANGE THE NOTIFICATION METHOD
###############################################################################
def notify_callback(msg_text):
    # signal-cli is available at https://github.com/AsamK/signal-cli
    # Set it up first if you want to use this!
    p = subprocess.Popen(["signal-cli", "--config", "/opt/signal-cli-0.6.0/.config", "-u",
                          "+33XXXXXXXXX", "send", "+33XXXXXXXXX", "-m", msg_text],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    p.communicate()
###############################################################################

INTERPRETERS = ["/bin/bash", "/usr/bin/perl"]

# -----------------------------------------------------------------------------

def get_caller():
    pid = os.getppid()
    try:
        with open('/proc/%d/cmdline' % pid, 'r') as f:
            cmdline = f.read().split("\x00")
            # The command line for scripts is "/bin/bash [script name]".
            # Get the script name rather than the interpreter.
            if len(cmdline) > 1 and cmdline[0] in INTERPRETERS:
                for i in range(1, len(cmdline)):
                    if os.path.exists(cmdline[i]):
                        return cmdline[i]
            return cmdline[0]
    except OSError:
        return None

# -----------------------------------------------------------------------------

def get_origin():
    try:
        return os.environ["SSH_CONNECTION"].split()[0]
    except KeyError:
        return None

# -----------------------------------------------------------------------------

def get_hostname():
    try:
        with open("/etc/hostname", "r") as f:
            return f.read().strip()
    except OSError:
        return None

# -----------------------------------------------------------------------------

def find_original_command(command):
    directories = os.environ["PATH"].split(':')
    for d in directories:
        if "/local/" in d:
            continue
        path = os.path.join(d, command)
        if os.path.exists(path):
            return path
    print("-bash: %s: command not found" % command)
    return None

# -----------------------------------------------------------------------------

def daemonize_and_notify(message):
    """
    Creates a new daemon process to send the notification. This prevents the user from
    noticing any delay that would be suspicious when calling a basic system utility.
    :return:
    """
    sys.stdout.flush()  # Flush stdout so previous messages aren't printed multiple times

    # Fork a first time.
    try:
        pid = os.fork()
        if pid > 0:
            # The parent process goes on and runs the original command.
            return
    except OSError:
        _, e = sys.exc_info()[:2]
        print("Error while forking! (%s)" % e.message)
        sys.exit(1)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    # Fork a second time.
    try:
        pid = os.fork()
        if pid > 0:
            # The first child exits immediately.
            sys.exit(0)
    except OSError:
        _, e = sys.exc_info()[:2]
        print("Error while forking! (%s)" % e.message)
        sys.exit(1)

    # The second child notifies and exit.
    notify_callback(message)
    sys.exit(0)

# -----------------------------------------------------------------------------

def main():
    # Verify that a notification should be sent.
    caller = get_caller()
    notify = True
    if caller:
        for r in CALLER_WHITELIST:
            if re.search(r, caller):
                notify = False
                break
    if notify:
        # Send notification
        hostname = get_hostname()
        origin = get_origin()
        program = os.path.basename(sys.argv[0])
        message = "Warning: %s command invoked" % program
        if hostname:
            message += " on %s" % hostname
        message += " by %s" % os.environ["USER"]
        if origin:
            message += " from %s" % origin
        if caller:
            message += " (%s)" % caller
        daemonize_and_notify(message)

    # Find the original program and run the original command
    command = [find_original_command(program)]
    if not command[0] or not os.path.exists(command[0]):
        return  # Could not find the intended program.
    if len(sys.argv) > 1:
        command += sys.argv[1:]
    subprocess.Popen(command).communicate()


if __name__ == "__main__":
    main()
