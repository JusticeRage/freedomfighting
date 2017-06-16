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

#### Daemonizing the script

```
./nojail.py --daemonize
```
Assuming this is run from an SSH connexion, this command will delete all logs pertaining to the current user's activity
with the detected IP address and hostname right after the connexion is closed. This script will subsequently
automatically delete itself.
Please bear in mind that you won't have any opportunity to receive error messages from the application. You are encouraged
to try deleting the logs once before spawning the demon to make sure that the arguments you specified are correct.

### Sample output:
```
root@proxy:~# ./nojail.py
[ ] Cleaning logs for root (XXX.XXX.XXX.XXX - domain.com).
[*] 2 entries removed from /var/run/utmp!
[*] 4 entries removed from /var/log/wtmp!
[ ] No entries to remove from /var/log/btmp.
[*] Lastlog set to 2017-01-09 17:12:49 from pts/0 at lns-bzn-37-79-250-104-19.adsl.proxad.net
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

Finally, if you need to access authenticated pages on a website, you can provide
cookies to listurl.py from the command line with the ``--cookie`` option.

## Miscellaneous

### Donations
These scripts are 100% free. I do like Bitcoins though, so if you want to send some my way, here's an address you can
use: ```19wFVDUWhrjRe3rPCsokhcf1w9Stj3Sr6K```
Feel free to drop me a line if you donate to the project, so I can thank you personally!

### Contact
[![](https://manalyzer.org/static/mail.png)](justicerage@manalyzer[.]org)
[![](https://manalyzer.org/static/twitter.png)](https://twitter.com/JusticeRage)
[![](https://manalyzer.org/static/gpg.png)](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x40E9F0A8F5EA8754)