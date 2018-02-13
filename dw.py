__author__  = "Witold Lawacz (wit0k)"
__date__    = "2018-02-13"
__version__ = '0.0.4'


from bs4 import BeautifulSoup # pip install bs4
from urllib.parse import urlparse, urlunparse

import requests
import re
import os
import logging
import argparse
import sys
import zipfile
import shutil
import json
import hashlib

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

DOWNLOADED_FILE_NAME_LEN = 60
ARCHIVE_FOLDER = "archive/"

debug_proxies = {
  'http': 'http://127.0.0.1:8080',
  'https': 'http://127.0.0.1:8080'
}

class downloader (object):

    def __init__(self, args):

        self.verbose_level = args.verbose_level
        self.skip_download = args.skip_download
        self.submit_to_vendors = args.submit_to_vendors
        self.input = args.input
        self.input_type = None  # file | folder
        self.get_links = args.get_links
        self.zip_downloaded_files = args.zip_downloaded_files
        self.max_file_count_per_archive = args.max_file_count_per_archive
        self.download_folder = args.download_folder
        self.submission_comments = args.submission_comments
        self.requests_debug = args.requests_debug

        """ Check script arguments """
        self.check_args()

    open_zip_files = {}

    def _zip(self, file_path, _zip_file_name):
        """ Add file to zip file """

        logger.debug("Add '%s' to: '%s'" % (file_path, _zip_file_name))
        """ Load or create zip object """
        if _zip_file_name in self.open_zip_files:
            _zip_file = self.open_zip_files[_zip_file_name]
        else:
            _zip_file = zipfile.ZipFile(_zip_file_name, mode='w')
            self.open_zip_files[_zip_file_name] = _zip_file

        if os.path.isfile(file_path):
            _zip_file.write(file_path, os.path.basename(file_path))

    def compress_files(self, files_to_compress, zip_name_prefix=""):

        file_count = 0
        archive_name_index = 1
        archive_name_prefix = "samples"
        archive_extension = ".zip"
        archive_file = ""
        archive_files = []

        if files_to_compress:
            for file in files_to_compress:

                """ Skip compression of already compressed files """
                if zipfile.is_zipfile(file):
                    archive_file = ARCHIVE_FOLDER + os.path.basename(file)
                    if file == archive_file:
                        archive_files.append(archive_file)
                    else:
                        logger.debug("Copy: %s to: %s" % (file, archive_file))
                        shutil.copy2(file, archive_file)
                        archive_files.append(archive_file)
                    continue

                file_count += 1
                """ Build the archive name """
                # Case: Unlimited items in archive
                if self.max_file_count_per_archive == 0:
                    if zip_name_prefix:
                        archive_file = ARCHIVE_FOLDER + zip_name_prefix + archive_extension
                    else:
                        archive_file = ARCHIVE_FOLDER + archive_name_prefix + archive_extension
                else:
                    # Case: Limit items count in archive
                    if zip_name_prefix:
                        archive_file = ARCHIVE_FOLDER + zip_name_prefix + "-" + str(archive_name_index) + archive_extension
                    else:
                        archive_file = ARCHIVE_FOLDER + archive_name_prefix + "-" + str(archive_name_index) + archive_extension

                    if file_count == self.max_file_count_per_archive:
                        file_count = 0
                        archive_name_index += 1

                """ Add file to the specific archive """
                self._zip(file, archive_file)

        archive_files.extend(list(self.open_zip_files.keys()))
        """ Finally close all involved archives """
        self.close_archives()

        return archive_files

    def close_archives(self):
        """ Close all open archive objects """
        for archive in self.open_zip_files.values():
            archive.close()

    def parse_urls(self, urls):
        """ Remove URL obfuscation ect. """

        new_urls = []
        index = 0
        for url in urls:
            _url = url
            """ Replace well known obfuscation strings """
            if url == "\n":
                continue

            url = url.strip()
            url = url.replace("hxxp", "http")
            url = url.replace("[.]", ".")
            url = url.replace("[:]", ":")
            url = url.replace("[.", ".")
            url = url.replace(".]", ".")
            urls[index] = url

            if re.match(r"^http:/{2}[^/]|^https:/{2}[^/]", url):
                logger.debug("Parsing URL: %s to: %s" % (_url, urls[index]))
                new_urls.append(url)
                continue
            else:
                """ Remove incorrect schema like: :// or : or :/ etc. """
                if re.match(r"(^/+|^:/+|^:+)", url):
                    """ Remove incorrect scheme, and leave it empty """
                    url = re.sub(r"(^/+|^:/+|^:+)", "", url)
                    urls[index] = url

            logger.debug("Parsing URL: %s to: %s" % (_url, urls[index]))
            new_urls.append(urls[index])
            index += 1

        return new_urls

    def load_urls_from_input_file(self, input_file):

        urls = []
        if os.path.isfile(input_file):
            with open(input_file, "r", encoding="utf8") as file:
                lines = file.readlines()
                return self.parse_urls(lines)
        else:
            logger.error("Input file: %s -> Not found!" % input_file)

    def load_files_from_input_folder(self, input_folder):

        files = []
        folder_listing = os.listdir(input_folder)
        for file in folder_listing:
            file_path = os.path.join(input_folder, file)
            if os.path.isfile(file_path):
                if not ".DS_Store" in file_path:
                    files.append(file_path)

        return files

    def get_hrefs(self, url):

        links = []

        try:
            logger.info("Getting hrefs from: %s" % url)
            print("Getting hrefs from: %s" % url)
            url_obj = urlparse(url, 'http')
            url_host = url_obj.hostname
            url = urlunparse(url_obj)

            if self.requests_debug:
                response = requests.get(url, proxies=debug_proxies, verify=False)
            else:
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
                    if _href.startswith("http://") or _href.startswith("https://"):
                        pass
                    else:
                        """  url does not end with / and the path neither """
                        if url[:-1] != "/" and _href[:1] != "/":
                            _href = url + r"/" + _href
                        else:
                            _href = url + _href

                links.append(_href)

        except requests.exceptions.InvalidSchema:
            logger.error("Invalid URL format: %s" % url)
            return links

        print(*links, sep="\n")
        return links

    def _update_headers(self, headers, vendor_file):

        vendor_config = None

        if os.path.isfile(vendor_file):
            with open(vendor_file, 'r') as file:
                vendor_config = json.load(file)

                for header_name, value in headers.items():
                    if value == "":
                        try:
                            headers[header_name] = (None, vendor_config["form_data"][header_name])
                        except KeyError:
                            pass

        else:
            logger.error("Unable to load vendor file: %s" % vendor_file)
            exit(-1)

        return headers

    def download(self, urls):

        download_index = 0
        downloaded_files = []
        sha256 = ""

        for url in urls:
            """ Submit the request """
            if self.requests_debug:
                response = requests.get(url, stream=True, proxies=debug_proxies, verify=False)
            else:
                response = requests.get(url, stream=True, verify=False)

            if not response.status_code == 200:
                logger.info("URL Download -> FAILED -> [HTTP%s] - URL: %s" % (response.status_code, url))
                continue
            else:
                logger.info("URL Download -> SUCCESS -> [HTTP%s] - URL: %s" % (response.status_code, url))

                """ Determine output file name """
                local_filename = ""
                url_obj = urlparse(url, 'http')
                if 'Content-Disposition' in response.headers.keys():
                    local_filename = response.headers['Content-Disposition'].split('=')[-1].strip('"')

                if not local_filename:
                    local_filename = os.path.basename(url)

                if not local_filename:
                    local_filename = url_obj.path.replace(r"/", "")

                if not local_filename:
                    local_filename = url_obj.netloc.replace(r"/", "")

                if len(local_filename) > DOWNLOADED_FILE_NAME_LEN:
                    local_filename = local_filename[1:DOWNLOADED_FILE_NAME_LEN]

                out_file = self.download_folder + "/" + local_filename

                """ Make sure that files do not get overwritten """
                _out_file = out_file
                while True:
                    if os.path.isfile(_out_file):
                        _out_file = out_file + " - " + str(download_index)
                        download_index += 1
                    else:
                        out_file = _out_file
                        break

                with open(out_file, 'wb') as file:
                    shutil.copyfileobj(response.raw, file)
                    downloaded_files.append(out_file)
                    file.close()

                """ Log downloaded file and its hash """
                hash_obj = hashlib.sha256()
                with open(out_file, "rb") as file:
                    for chunk in iter(lambda: file.read(4096), b""):
                        hash_obj.update(chunk)

                    sha256 = hash_obj.hexdigest()
                    file.close()

                logger.info("[sha256: %s] - %s" % (sha256, out_file))
                print("[sha256: %s] - %s" % (sha256, out_file))

        return downloaded_files

    # http://docs.python-requests.org/en/master/user/quickstart/
    POST_DATA = {
        "Symantec": {
            "url": "https://submit.symantec.com/websubmit/bcs.cgi",
            "config_file": "config/symantec.vd",
            "success_message": "Your submission has been sent",
            "form_data": {
                "mode": (None, '2'),
                "fname": "",
                "lname": "",
                "cname": "",
                "email": "",
                "email2": "",
                "pin": "",
                "stype": (None, 'upfile'),
                "url": (None, ''),
                "hash": (None, ''),
                "comments": (None, ''),
                "upfile": ""
            },
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)",
                "Cache-Control": "max-age=0",
                "Origin": "https://submit.symantec.com",
                "Upgrade-Insecure-Requests": "1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Referer": "https://submit.symantec.com/websubmit/bcs.cgi"
            }
        }
    }

    def submit(self, files, vendor_name="Symantec"):

        if files:
            url = ""
            file_content = None
            submission_success_message = ""
            form_data = {}
            headers = {}

            """ Pull vendor specific POST data fields """
            if vendor_name == "Symantec":
                form_data = self.POST_DATA["Symantec"]["form_data"]
                headers = self.POST_DATA["Symantec"]["headers"]
                url = self.POST_DATA["Symantec"]["url"]
                submission_success_message = self.POST_DATA["Symantec"]["success_message"]

            for file in files:
                logger.info("Submitting: %s to: %s" % (file, url))
                file_name = os.path.basename(file)

                """ Adjust form_data according to script parameters """
                if self.submission_comments:
                    form_data["comments"] = self.submission_comments
                else:
                    form_data["comments"] = file_name

                """ Adjust form_data with data from vendor file  """
                self._update_headers(form_data, self.POST_DATA["Symantec"]["config_file"])

                """ Load the file content """
                with open(file, 'rb') as file_obj:
                    file_content = file_obj.read()
                    form_data["upfile"] = (file_name, file_content, 'application/x-zip-compressed')
                    file_obj.close()

                """ Submit the request """
                if self.requests_debug:
                    response = requests.post(url, files=form_data, proxies=debug_proxies, headers=headers, verify=False)
                else:
                    response = requests.post(url, files=form_data, headers=headers, verify=False)

                if not response.status_code == 200:
                    logger.error("[%s] - FAILED to submit: %s" % (response.status_code, url))
                else:
                    if vendor_name == "Symantec":
                        if submission_success_message in response.text:
                            logger.info("Submission OK -> %s" % file)
        else:
            logger.warning("Nothing to submit!")

    def check_args(self):

        if not os.path.isfile(self.input):
            logger.warning("Input file: %s not found!" % self.input)
            if os.path.isdir(self.input):
                self.input_type = "folder"
            else:
                logger.error("Input file or folder: %s not found!" % self.input)
                exit(-1)
        else:
            self.input_type = "file"

        if not os.path.isdir(self.download_folder):
            logger.warning("Download folder: %s not found!" % self.download_folder)
            try:
                logger.error("Create download folder: %s" % self.download_folder)
                os.mkdir(self.download_folder)
            except Exception:
                exit(-1)

        """ When zip enabled and archive folder does not exist """
        if self.zip_downloaded_files and not os.path.isdir(ARCHIVE_FOLDER):
            os.makedirs(ARCHIVE_FOLDER)

        """ Enable compression if submit option is enabled """
        if self.submit_to_vendors:
            self.zip_downloaded_files = True

        """ Skip download in case user specified a folder """
        if self.input_type == "folder":
            self.skip_download = True



def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                     description='Hyperion parser')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    """ Script arguments """
    script_args.add_argument("-v", "--verbose-level", type=str, action='store', dest='verbose_level', required=False,
                             default="DEBUG", help="Set the verbose level to one of following: INFO, WARNING, ERROR or DEBUG (Default: WARNING)")
    script_args.add_argument("-i", "--input", type=str, action='store', dest='input', required=False,
                             help="File containing the URLs to be processed, or folder with files to be processed")

    script_args.add_argument("-d", "--download-folder", action='store', dest='download_folder', required=False,
                             default="downloads/", help="Specify custom download folder (Default: downloads/")

    script_args.add_argument("--skip-download", action='store_true', dest='skip_download', required=False,
                             default=False, help="Would process the URL only")

    script_args.add_argument("-gl", "--get-links", action='store_true', dest='get_links', required=False,
                             default=False, help="Would print out the links retrieved from a given URL")

    script_args.add_argument("-z", "--zip", action='store_true', dest='zip_downloaded_files', required=False,
                             default=False, help="Would compress all downloaded files, or files from input folder")

    script_args.add_argument("--limit-archive-items", action='store', dest='max_file_count_per_archive', required=False,
                             default=9, help="Sets the limit of files per archive (Default: 9, 0: Unlimited)")

    script_args.add_argument("--submit", action='store_true', dest='submit_to_vendors', required=False,
                             default=False, help="Submit files to AV vendors (Default: False)")

    script_args.add_argument("-sc", "--submission-comments", action='store', dest='submission_comments', required=False,
                             help="Insert submission comments (Default: archive name)")

    script_args.add_argument("--debug-requests", action='store_true', dest='requests_debug', required=False,
                             default=False, help="Sends GET/POST requests via local proxy server 127.0.0.1:8080")

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
    logger.debug("Initialize dw (Downloader)")
    dw = downloader(args)
    urls = []
    hrefs = []
    downloaded_files = []
    archives = []

    """ Proceed accordingly to input type """
    if dw.input:
        if dw.input_type == "file":
            urls = dw.load_urls_from_input_file(dw.input)
            logger.debug("Loaded [%d] URLs from: %s" % (len(urls), dw.input))
        elif dw.input_type == "folder":
            downloaded_files = dw.load_files_from_input_folder(dw.input)
            logger.debug("Loaded [%d] files from: %s" % (len(downloaded_files), dw.input))
        else:
            logger.error("Unsupported input type" % dw.input)
            exit(-1)

    """ Skip download step if required """
    if not dw.skip_download:
        """ Retrieve HREFs from URLs """
        if dw.get_links and urls:
            if urls:
                logger.debug("Get links from each URL")
                for url in urls:
                    _urls = dw.get_hrefs(url)
                    logger.debug("Found [%d] hrefs on: %s" % (len(_urls), url))
                    hrefs.extend(_urls)

                logger.info("All retrieved HREFs:")
                logger.info(hrefs)
                print("All retrieved HREFs:")
                print(*hrefs, sep="\n")

        if hrefs:
            """ Download pulled hrefs """
            downloaded_files = dw.download(hrefs)
        else:
            """ Download given URLs """
            downloaded_files = dw.download(urls)

        """ Compress files if instructed to """
        if downloaded_files and dw.zip_downloaded_files:
            archives = dw.compress_files(downloaded_files)

    else:
        # Local file processing only (No download)
        """ Compress files if instructed to """
        if downloaded_files and dw.zip_downloaded_files:
            archives = dw.compress_files(downloaded_files)

    """ Print files by archive """
    if archives:
        print("Archives content:")
        for archive in archives:
            with zipfile.ZipFile(archive, 'r') as _archive:
                members = _archive.namelist()
                print("Archive: %s" % archive)
                for member in members:
                    print(" - %s" % member)
                logger.debug("Archive: %s -> Members: %s" % (archive, members))

    """ Submit files to vendors """
    if dw.submit_to_vendors:
        dw.submit(archives)
    else:
        logger.debug("Skipping Vendor submission")


if __name__ == "__main__":
    main(sys.argv)

