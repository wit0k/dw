from bs4 import BeautifulSoup # pip install bs4
from urllib.parse import urlparse, urlunparse

import requests
import re
import os
import logging
import argparse
import sys


app_name = "dw (Downloader)"
""" Set working directory so the script can be executed from any location/symlink """
os.chdir(os.path.dirname(os.path.abspath(__file__)))

""" Logger settings """
logger = logging.getLogger('dw')
log_handler = logging.FileHandler('logs/dw.log')
log_file_format = logging.Formatter('%(levelname)s - THREAD-%(thread)d - %(asctime)s - %(filename)s - %(funcName)s - %(message)s')
log_handler.setFormatter(log_file_format)
logger.addHandler(log_handler)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
log_console_format = logging.Formatter('%(message)s')
console_handler.setFormatter(log_console_format)
logger.addHandler(console_handler)
logger.setLevel(logging.NOTSET)  # Would be set by a parameter
logger_verobse_levels = ["INFO", "WARNING", "ERROR", "DEBUG"]

class downloader (object):


    def __init__(self, args):
        pass

    def parse_urls(self, urls):
        """ Remove URL obfuscation ect. """

        index = 0
        for url in urls:
            """ Replace well known obfuscation strings """
            url = url.strip()
            url = url.replace("hxxp", "http")
            url = url.replace("[.]", ".")
            url = url.replace("[.", ".")
            url = url.replace(".]", ".")
            urls[index] = url

            if re.match(r"^http:/{2}[^/]|^https:/{2}[^/]", url):
                continue
            else:
                """ Remove incorrect schema like: :// or : or :/ etc. """
                if re.match(r"(^/+|^:/+|^:+)", url):
                    """ Remove incorrect scheme, and leave it empty """
                    url = re.sub(r"(^/+|^:/+|^:+)", "", url)
                    urls[index] = url


            index += 1

        return urls

    def load_urls_from_input_file(self, input_file):

        urls = []
        if os.path.isfile(input_file):
            with open(input_file, "r", encoding="utf8") as file:
                lines = file.readlines()
                return self.parse_urls(lines)
        else:
            logger.error("Input file: %s -> Not found!" % input_file)

    def get_links(self, url):

        links = []

        try:
            url_obj = urlparse(url, 'http')
            url_host = url_obj.hostname
            url = urlunparse(url_obj)

            response = requests.get(url, verify=False)
            if not response.status_code == 200:
                logger.info("URL Fetch -> FAILED -> URL: %s" % url)
                return []
            else:
                logger.info("URL Fetch -> SUCCESS -> URL: %s" % url)

            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.findAll('a', attrs={'href': re.compile(r"^http://|https://|.*\..*")}):

                _href = link.get('href')
                """ Append http://%url_host% whenever necessary """
                if url_host not in _href:
                    """  url does not end with \ and the path neither """
                    if url[:-1] != "/" and _href[:1] != "/":
                        _href = url + r"/" + _href
                    else:
                        _href = url + _href

                links.append(_href)

        except requests.exceptions.InvalidSchema:
            logger.error("Invalid URL format: %s" % url)

        return links


def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                     description='Hyperion parser')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    """ Script arguments """
    script_args.add_argument("-v", "--verbose-level", type=str, action='store', dest='verbose_level', required=False,
                             default="WARNING", help="Set the verbose level to one of following: INFO, WARNING, ERROR or DEBUG (Default: WARNING)")
    script_args.add_argument("-i", "--input-file", type=str, action='store', dest='url_input_file', required=False,
                             help="File containing the URLs to be processed")

    script_args.add_argument("-gl", "--get-links", action='store_true', dest='get_links', required=False,
                             help="Would print out the links retrieved from a given URL")


    args = argsparser.parse_args()
    argc = argv.__len__()

    logger.info(f"Starting {app_name}")

    """ Check and set appropriate logger level """

    args.verbose_level = args.verbose_level.upper()
    if args.verbose_level.upper() in logger_verobse_levels:
        if args.verbose_level == "INFO":
            logger.setLevel(logging.INFO)
        elif args.verbose_level == "WARNING":
            logger.setLevel(logging.WARNING)
        elif args.verbose_level == "ERROR":
            logger.setLevel(logging.ERROR)
        elif args.verbose_level == "DEBUG":
            logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

    """ Init dw class """
    dw = downloader(args)
    urls = []

    if args.url_input_file:
        urls = dw.load_urls_from_input_file(args.url_input_file)

    if args.get_links and urls:
        hrefs = []
        if urls:
            for url in urls:
                hrefs.extend(dw.get_links(url))

            logger.info(hrefs)
            print(*hrefs, sep="\n")


if __name__ == "__main__":
    main(sys.argv)

