#!/usr/bin/python3
"""
This script was written to detect evil maid attacks. It does so by checking at
boot time if the hard drive was powered on but not the OS (for instance, if it
was taken out of the computer for a copy, or if someone tried to boot the
machine but was stopped by a FDE password).

It is distributed under the terms of the GPLv3 license. For more information,
see http://www.gnu.org/licenses/.

Installation:
-------------
You need to make sure this script will run at every boot. The following
instructions will work on distributions using systemd.

1) Copy boot_check.service to /etc/systemd/system/. Fix paths inside of it as needed.
   The script will run as root so make sure it is not world writable!
2) #> systemctl enable boot_check.service

Install dependencies:

3) #> apt install smartmontools dialog

Run the script once so it initializes:

4) #> ./boot_check.py

If a confirmation message appears, you're good to go.

                                              - Coded with love by @JusticeRage
"""

import json
import os
import subprocess
import sys


"""
This file is a JSON document containing the list of drives and the number of
times they were booted up.
"""
BOOT_COUNT_FILE = "/root/.boot_check"

# -----------------------------------------------------------------------------

def main():
    check_prerequisites()  # Exits if prerequisites are not met.

    # No file describing the state at the last boot exists: generate it.
    if not os.path.exists(BOOT_COUNT_FILE):
        # There is not known count for hard drive boot power cycles. Create it and return
        initialize()

    # The script is initialized and running in normal mode. Perform the checks.
    else:
        check_boot_count()

# -----------------------------------------------------------------------------

def check_prerequisites():
    """
    This function verifies that this script can execute properly.
    It performs the following checks:
    - Whether the script is running as root
    - Whether smartctl and lsblk are installed on the machine
    :return: None, but the script will exit with an error code of 1 upon error.
    """
    # Check that we have root permissions
    if not os.geteuid() == 0:
        print("[!] Error: This script must be run as root!", file=sys.stderr)
        sys.exit(1)
    # Check that smartctl is installed
    status = subprocess.Popen(["command", "-v", "smartctl"],
                              shell=True).wait()
    if status != 0:
        print("[!] Error: smartctl is not installed on this machine!\n"
              "    Please run apt install smartmontools.", file=sys.stderr)
        sys.exit(1)

    # Check that lsblk is installed
    status = subprocess.Popen(["command", "-v", "lsblk"], shell=True).wait()
    if status != 0:
        print("[!] Error: lsblk is not installed on this machine!\n")
        sys.exit(1)

    # Check that dialog is installed
    status = subprocess.Popen(["command", "-v", "dialog"], shell=True).wait()
    if status != 0:
        print("[!] Error: dialog is not installed on this machine!\n"
              "    Please run apt install dialog.", file=sys.stderr)
        sys.exit(1)

    return

# -----------------------------------------------------------------------------

def initialize():
    """
    This function performs the initial setup for the process.
    It creates the BOOT_COUNT_FILE with its initial values, and checks that
    the systemd service was created successfully.
    """
    # Verify that the script will run at startup.
    status = subprocess.Popen(["systemctl", "--quiet", "is-enabled", "boot_check.service"]).wait()
    if status:
        print("[\033[0;31m!\033[0m] \033[0;31mError: Boot Check is not enabled in "
              "systemd!\033[0m")
        return

    # Create the file containing the power cycle counts.
    init_data = {}
    for device in get_hard_drives():
        init_data[device] = get_power_cycle_count(device)

    with open(BOOT_COUNT_FILE, "w") as f:
        f.write(json.dumps(init_data))
    os.chmod(BOOT_COUNT_FILE, 0o600)
    print("[\033[0;32m*\033[0m] \033[0;32mBoot Check initialized successfully.\033[0m")

# =============================================================================
# Program logic
# =============================================================================

def check_boot_count():
    """
    This function verifies that the number of power cycles of the hard drive
    is consistent with OS startups.
    """
    with open(BOOT_COUNT_FILE, "r") as f:
        state = json.load(f)
    for device in get_hard_drives():
        # If the device is not present in the state file, it may be a
        # removable drive or a new drive. Not sure what to do here yet.
        # Notify?
        if device not in state:
            dialog("Error: no existing data for %s. Please remove %s and initialize this script"
                   "again." % (device, BOOT_COUNT_FILE))
            continue

        count = get_power_cycle_count(device)
        number_of_boots = count - state[device] - 1  # -1 because the current boot doesn't "count"
        if number_of_boots <= 0:  # Only one (or no) boot since the last check: everything is fine
            state[device] = count
        else:
            dialog("Warning: %s was started %d time%s since the last check!" %
                   (get_drive_model(device), number_of_boots, "s" if number_of_boots > 1 else ""))

            # The user was warned, resync the count now.
            state[device] = count

    # Save the latest state to the file for future checks.
    with open(BOOT_COUNT_FILE, "w") as f:
        f.write(json.dumps(state))

# =============================================================================
# Hardware data gathering functions
# =============================================================================

def get_hard_drives():
    """
    Determines what the computer's hard drives are.
    :return: A list of the devices on this computer.
    """
    p = subprocess.Popen(["lsblk", "-d", "-J"],
                         stdout=subprocess.PIPE)
    stdout, _ = p.communicate()
    devices = []
    lsblk = json.loads(stdout.decode("UTF-8"))
    for d in lsblk["blockdevices"]:
        if d["type"] != "disk":
            continue
        devices.append(d["name"])
    return devices

# -----------------------------------------------------------------------------

def get_drive_model(device):
    """
    This function translates a device name into the human-readable hard drive model.
    :param device: The device whose model we want to obtain, i.e. sda.
    :return: The model of the hard drive.
    """
    p = subprocess.Popen(["lsblk", "-S", "-J"],
                         stdout=subprocess.PIPE)
    stdin, _ = p.communicate()
    if stdin:
        lsblk = json.loads(stdin.decode("UTF-8"))
        try:
            for d in lsblk["blockdevices"]:
                if d["name"] == device:
                    return d["model"]
        except KeyError:
            pass
    return "/dev/%s" % device

# -----------------------------------------------------------------------------

def get_power_cycle_count(device):
    """
    Gets the current power cycle count from the SMART data.
    :param device: The device to interrogate.
    :return: The number of times the given hard drive was powered on
    """
    p = subprocess.Popen("smartctl /dev/%s -a | grep -i 'Power_Cycle_Count'" % device,
                         shell=True,
                         stdout=subprocess.PIPE)
    output, _ = p.communicate()
    return int(output.split()[-1])

# =============================================================================
# Display functions
# =============================================================================

def dialog(text, width=50):
    """
    This function displays a scary terminal dialog to inform the user that
    something is wrong. It contains a few hacks to make it work in a systemd
    boot context.
    :param text: The text to display.
    :return:
    """
    if not text:
        return

    # Switch to TTY2 where the script is running. Sleep a bit first or the display manager will grab focus.
    subprocess.Popen(["sleep 5 ; chvt 2"], shell=True).wait()

    # Determine the height of the textbox.
    # 5 because 4 lines required for the dialog box and one line of text minimum.
    lines_needed = 5 + (len(text) // (width - 4))

    # Display the error dialog. There's a trick here to get a dialog with a red background.
    # That would usually be controlled through a .rc file. To circumvent that, the configuration file is
    # pointed to stdin and the options are passed through the process' input. This prevents this script from
    # having to create and then delete a .rc file.
    dialog = subprocess.Popen('OLDDIALOGRC=$DIALOGRC;'
                              'export DIALOGRC=/dev/stdin;'
                              'dialog --clear --msgbox "%s" %s 50;'
                              'export DIALOGRC=$OLDDIALOGRC' % (text, str(lines_needed)),
                              shell=True,
                              stdin=subprocess.PIPE)
    dialog.communicate(input=b"screen_color = (CYAN,RED,ON)\n")
    # Restore the original TTY
    print("[\033[0;31m!\033[0m] Press [\033[0;31mCTRL+ALT+F7\033[0m] to go back to the desktop.")
    subprocess.Popen(["chvt 7"], shell=True).wait()

# =============================================================================

if __name__ == "__main__":
    main()
