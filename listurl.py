#!/usr/bin/env python

"""
    listurl.py by @JusticeRage

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

# Standard library imports
from argparse import ArgumentParser
from operator import attrgetter
from os import linesep, path
from Queue import Empty, Queue
from re import search
from sys import stdout
from threading import Thread
from urlparse import urljoin, urlparse

# Third party library imports
from requests import exceptions, RequestException, Session, utils

try:
    from bs4 import BeautifulSoup
except ImportError:
    print "[\033[91m!\033[0m] BeautifulSoup is not installed! Please run '\033[93mpip install beautifulsoup4\033[0m' " \
          "and launch this script again."
    exit(1)

ARGS = None
IGNORED_EXTENSIONS = [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".eps", ".wav"]
USER_AGENT = {"User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1"}
COOKIES = None
PRINT_QUEUE = None

###############################################################################
# Usage
###############################################################################

def parse_arguments():
    parser = ArgumentParser(description="Map a website by recursively grabbing all its URLs.")
    parser.add_argument("--max-depth", "-m", help="The maximum depth to crawl (default is 3).", default=3, type=int)
    parser.add_argument("--threads", "-t", help="The number of threads to use (default is 10).", default=10, type=int)
    parser.add_argument("--url", "-u", help="The page to start from.")
    parser.add_argument("--external", "-e", help="Follow external links (default is false).", action="store_true",
                        default=False)
    parser.add_argument("--subdomains", "-d", help="Include subdomains in the scope (default is false).",
                        action="store_true", default=False)
    parser.add_argument("-c", "--cookie", help="Add a cookies to the request. May be specified multiple times."
                                               "Example: -c \"user=admin\".",
                        action="append")
    parser.add_argument("--exclude-regexp", "-r", help="A regular expression matching URLs to ignore. The given"
                                                       "expression doesn't need to match the whole URL, only a part"
                                                       "of it.")
    parser.add_argument("--show-regexp", "-s", help="A regular expression filtering displayed results. The given "
                                                    "expression is searched inside the results, it doesn't have to"
                                                    "match the whole URL. Example: \\.php$")
    parser.add_argument("--no-certificate-check", "-n", help="Disables the verification of SSL certificates.",
                        action="store_false", default=True)
    parser.add_argument("--output-file", "-o", help="The file into which the obtained URLs should be written")
    parser.add_argument("--verbose", "-v", help="Be more verbose. Can be specified multiple times.", action="count",
                        default=0)
    args = parser.parse_args()

    if args.url is None:
        print error("Please specify the URL to start from with the -u option.")
        parser.print_help()
        exit(1)

    # Convert the cookie argument into a requests cookiejar.
    if args.cookie:
        global COOKIES
        cookie_dict = {}
        for c in args.cookie:
            if c.count('=') != 1:
                print error("Input cookie should be in the form key=value (received: %s)!" % c)
                exit(1)
            cookie = c.split('=')
            cookie_dict[cookie[0]] = cookie[1]
        COOKIES = utils.cookiejar_from_dict(cookie_dict)

    if args.output_file and path.exists(args.output_file):
        print error("%s already exists! Aborting to avoid overwriting it." % args.output_file)
        exit(1)

    return args

###############################################################################
# Pretty printing functions
###############################################################################

GREEN = '\033[92m'
ORANGE = '\033[93m'
RED = '\033[91m'
END = '\033[0m'

def red(text): return RED + text + END
def orange(text): return ORANGE + text + END
def green(text): return GREEN + text + END
def error(text): return "[" + red("!") + "] " + red("Error: " + text)
def warning(text): return "[" + orange("*") + "] Warning: " + text
def success(text): return "[" + green("*") + "] " + green(text)
def info(text): return "[ ] " + text

# -----------------------------------------------------------------------------

class PrinterThread(Thread):
    """
    A thread which is in charge of printing messages to stdout.
    This is introduced so that multiple threads don't try to write things
    simultaneously.
    """

    def __init__(self, printing_queue):
        super(PrinterThread, self).__init__()
        self.alive = True
        self.pq = printing_queue

    def run(self):
        """
        The thread prints everything from its queue. The exit condition
        is checked every 2 seconds when the queue is empty.
        :return:
        """
        while True:
            try:
                message = self.pq.get(timeout=2)
                if message and message.__str__()[-1] == '\r':
                    print message,
                    stdout.flush()
                else:
                    print message
                self.pq.task_done()
            except Empty:
                if not self.alive:
                    return

    def kill(self):
        self.alive = False

###############################################################################
# Object model
###############################################################################

class InputParameter:
    """
    This class represents a POST parameter.
    Value is unused at the moment but could be useful in subsequent versions
    of the script.
    """
    def __init__(self, name, value, param_type):
        self.name = name
        self.value = value
        self.type = param_type.upper()

    def __str__(self):
        return "%s (%s)" % (self.name, self.type)

    def __eq__(self, other):
        if not isinstance(other, InputParameter):
            return False
        return self.name == other.name

# -----------------------------------------------------------------------------

class GrabbedURL:
    def __init__(self, url, method="GET"):
        """
        Creates an object representing an URL which was found by crawling.
        :param url: The URL of the page.
        :param method: The method it accepts (GET or POST).
        the URL.
        """
        if url is None:
            raise ValueError()
        self.url = url
        self.method = method.upper()
        self.parameters = None

    def __str__(self):
        if self.parameters is None:
            return "[%s] %s%s" % (self.method, " " if self.method == "GET" else "", self.url)
        res = "[%s] %s%s - params = %s" % (self.method, " " if self.method == "GET" else "", self.url,
                                           ", ".join(p.__str__() for p in self.parameters))
        return res

    def __eq__(self, other):
        if not isinstance(other, GrabbedURL):
            return False
        return self.url == other.url and self.method == other.method and self.parameters == other.parameters

    def __hash__(self):
        """
        This method is overridden so this class plays nicely with sets.
        """
        return self.__str__().__hash__()

###############################################################################
# Crawling functions
###############################################################################

def create_session():
    """
    Creates a requests session preloaded with the user-agent and cookies to use.
    :return: A Session object.
    """
    session = Session()
    session.headers = USER_AGENT
    session.verify = ARGS.no_certificate_check
    if COOKIES:
        session.cookies = COOKIES
    return session

# -----------------------------------------------------------------------------

def process_url(url, parent_url):
    """
    This function normalizes an URL. It is converted to an absolute location
    and anchors (#stuff) are removed.
    It is also in charge of filtering out urls which are not needed, such as
    links to external sites or static resources of no interest.
    :param url: The URL to normalize.
    :param parent_url: The URL of the page which links to it. It is expected
    that the parent's URL has already been normalized.
    :return: A normalized URL, or None if the URL should be rejected.
    """
    parent_purl = urlparse(parent_url)  # purl = parsed url
    if not url.startswith('http') and not url.startswith("//"):  # "//" for protocol-relative URLs
        url = urljoin(parent_purl.scheme + "://" + parent_purl.netloc, url)
        purl = urlparse(url)
    else:
        purl = urlparse(url)
        # The following boolean expression is a little complex. Basically, it verifies that:
        # - ARGS.external is enabled (A) if the URL points to an external domain (B)
        # - ARGS.subdomains is enabled (C) if the URL point to a subdomain (D)
        # This is made complex by the fact that D => B.
        # The resulting expression matching URLs to exclude is !A & B & !(C & D).
        if not ARGS.external and purl.netloc != parent_purl.netloc \
           and not (ARGS.subdomains and purl.netloc.endswith(parent_purl.netloc)):
            if ARGS.verbose > 1:
                PRINT_QUEUE.put(info("Ignoring a link to external URL %s." % purl.netloc))
            return None

    # Ignore non-http links (i.e. mailto://).
    if purl.scheme != "http" and purl.scheme != "https":
        return None

    # Remove the # fragment as is does not constitute a new page
    if '#' in url:
        url = url[:url.find('#')]

    # Ignore URLs which may point to static resources:
    if '.' in url:
        ext = url[url.rfind('.'):]
        if ext.lower() in IGNORED_EXTENSIONS:
            if ARGS.verbose > 1:
                PRINT_QUEUE.put(info("Ignoring %s." % url))
            return None

    # Ignore URLs matching the input regexp (optional)
    if ARGS.exclude_regexp and search(ARGS.exclude_regexp, url) is not None:
        if ARGS.verbose > 1:
            PRINT_QUEUE.put(info("Ignoring %s due to the regular expression." % url))
        return None

    return url

# -----------------------------------------------------------------------------

def extract_urls(page_data, page_url):
    """
    Extracts all the links from a page's contents and returns them as a list.
    :param page_url: The URL of the page we're working on. Used to normalize urls.
    :param page_data: The HTML page to work on.
    :return: A set of links that it contains.
    """
    # TODO: Strip comment tags to obtain URLs in comments
    soup = BeautifulSoup(page_data, 'html.parser')
    urls = set()
    # <a href=''> links
    for link in soup.find_all('a'):
        try:
            if link.get("href"):
                urls.add(GrabbedURL(process_url(link.get("href"), page_url)))
        except ValueError:  # May be thrown if the URL is to be rejected
            continue

    # <form action='' method=''> links
    for link in soup.find_all("form"):
        if link.get("action"):
            try:
                grabbed_url = GrabbedURL(process_url(link.get("action"), page_url), link.get("method", "GET"))
                # Also list the possible POST parameters
                params = []
                for inp in link.find_all("input"):
                    if inp.get("name") and inp.get("type") is not None:
                        params.append(InputParameter(inp.get("name"), inp.get("value"), inp.get("type")))
                if params:
                    grabbed_url.parameters = params
                urls.add(grabbed_url)
            except ValueError:  # May be thrown if the URL is to be rejected
                continue

    return urls

# -----------------------------------------------------------------------------

class RequesterThread(Thread):
    def __init__(self, input_queue, output_queue):
        super(RequesterThread, self).__init__()
        self.session = create_session()
        self.iq = input_queue
        self.oq = output_queue

    # --------------------------------------------------------------------------

    def run(self):
        try:
            url = True  # Initialized to True so we can enter the while loop.
            while url:
                try:
                    url = self.iq.get(block=False)  # Having the incrementation here allows us to move to the next
                    if ARGS.verbose > 0:  # iteration with "continue".
                        PRINT_QUEUE.put(info("Requesting %s" % url))
                    if url.method == "GET":
                        r = self.session.get(url.url)
                    else:  # url.method == "POST"
                        # TODO: generate random parameters?
                        r = self.session.post(url.url)
                    if r.status_code != 200:
                        PRINT_QUEUE.put(error("Could not obtain %s (HTTP error code: %d)" % (url, r.status_code)))
                        self.iq.task_done()
                        continue

                    urls = extract_urls(r.text, url.url)
                    for url in urls:
                        self.oq.put(url)

                # HTTP error: log and proceed to the next URL.
                except exceptions.SSLError as e:
                    PRINT_QUEUE.put(error(e.message.__str__()))
                    PRINT_QUEUE.put(error("An SSL error was detected. If this is expected, please re-run the program "
                                          "with --no-certificate-check (-n)."))
                except RequestException as e:
                    PRINT_QUEUE.put(error(e.message.__str__()))

                self.iq.task_done()
        except Empty:  # No more items to process. Let the thread die.
            return

###############################################################################
# Main
###############################################################################

def main():
    # Parse arguments
    global ARGS, PRINT_QUEUE
    ARGS = parse_arguments()

    input_queue = Queue()  # Stores URLs to crawl
    output_queue = Queue()  # Stores URLs discovered
    PRINT_QUEUE = Queue()  # Receives messages to print

    # Start a thread to handle stdout gracefully.
    printer_thread = PrinterThread(PRINT_QUEUE)
    printer_thread.start()

    # Obtain the first URLs to crawl by getting the original page.
    input_queue.put(GrabbedURL(ARGS.url))
    init = RequesterThread(input_queue, output_queue)
    init.run()  # Do not start a thread, just run synchronously for the first request.

    # Start crawling
    found_urls = set()
    found_urls.add(GrabbedURL(ARGS.url))
    for depth in range(0, ARGS.max_depth):
        try:
            PRINT_QUEUE.put(success("Started crawling at depth %d.     " % (depth + 1)))

            # Extract obtained URLs
            round_urls = set()
            try:
                for url in iter(output_queue.get_nowait, None):
                    round_urls.add(url)
                    output_queue.task_done()
            except Empty:
                pass

            # Add newly discovered URLs to the input queue.
            for url in round_urls:
                if url not in found_urls:  # Do not request pages twice.
                    input_queue.put(url)
            found_urls |= round_urls

            # I would much rather wait on input_queue.join() here, but this function is totally
            # oblivious to CTRL+C (as is thread.join() with no timeout). For this reason, we must
            # join() on each individual thread.
            threads = []
            max_round_requests = input_queue.qsize()
            for _ in range(0, ARGS.threads):
                t = RequesterThread(input_queue, output_queue)
                t.daemon = True
                t.start()
                threads.append(t)
            for t in threads:
                while t.is_alive():
                    t.join(1)
                    if ARGS.verbose == 0:
                        PRINT_QUEUE.put("%d requests so far in this round...\r" %
                                        (max_round_requests - input_queue.qsize()))

        # CTRL+C: stop crawling and print what we have so far.
        except KeyboardInterrupt:
            PRINT_QUEUE.put(error("\rInterrupt caught! Please wait a few seconds while the "
                                  "threads shut down..."))  # \r to erase the ^C
            round_urls = set()
            try:
                for _ in iter(input_queue.get_nowait, None):
                    input_queue.task_done()  # Empty the input queue to stop the threads
            except Empty:
                pass
            try:
                for url in iter(output_queue.get_nowait, None):
                    round_urls.add(url)
                    output_queue.task_done()
            except Empty:
                pass
            found_urls |= round_urls
            break

    # Print results if URLs were found (otherwise, found_urls only contains the input URL).
    if not ARGS.output_file and not len(found_urls) == 1:
        PRINT_QUEUE.put(success("URLs discovered:"))
        for url in sorted(found_urls, key=attrgetter('url')):
            if not ARGS.show_regexp or (ARGS.show_regexp and search(ARGS.show_regexp, url.url)):
                PRINT_QUEUE.put(url)
    elif not len(found_urls) == 1:
        with open(ARGS.output_file, 'w') as f:
            for url in sorted(found_urls, key=attrgetter('url')):
                if not ARGS.show_regexp or (ARGS.show_regexp and search(ARGS.show_regexp, url.url)):
                    f.write(url.__str__() + linesep)
        PRINT_QUEUE.put(success("Discovered URLs were written to %s." % ARGS.output_file))
    else:
        PRINT_QUEUE.put(error("No URLs were found."))

    # Cleanup
    printer_thread.kill()


if __name__ == "__main__":
    main()
