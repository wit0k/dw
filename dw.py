__author__  = "Witold Lawacz (wit0k)"
__date__    = "2018-02-13"
__version__ = '0.0.9'


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

user_agents = ["Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)"]

debug_proxies = {
  'http': 'http://127.0.0.1:8080',
  'https': 'http://127.0.0.1:8080'
}

default_mime_types = [
    "application/hta",
    "application/x-internet-signup",
    "application/x-mscardfile",
    "application/x-perfmon",
    "application/x-pkcs7-certificates",
    "application/x-sv4crc",
    "application/octet-stream",
    "application/x-msclip",
    "application/x-msmoney",
    "application/x-pkcs7-certreqresp",
    "application/envoy",
    "application/pkcs7-signature",
    "application/postscript",
    "application/set-registration-initiation",
    "application/vnd.ms-excel",
    "application/x-cpio",
    "application/x-dvi",
    "application/x-pkcs7-certificates",
    "application/msword",
    "application/msword",
    "application/pkcs7-mime",
    "application/postscript",
    "application/vnd.ms-works",
    "application/x-csh",
    "application/x-iphone",
    "application/x-perfmon",
    "application/x-troff-man",
    "application/x-hdf",
    "application/x-msmediaview",
    "application/x-texinfo",
    "application/set-payment-initiation",
    "application/vndms-pkistl",
    "application/x-msaccess",
    "application/oda",
    "application/winhlp",
    "application/x-netcdf",
    "application/x-sh",
    "application/x-shar",
    "application/x-tcl",
    "application/x-troff-ms",
    "application/oleobject",
    "application/olescript",
    "application/vnd.ms-excel",
    "application/vnd.ms-project",
    "application/x-director",
    "application/x-stuffit",
    "application/octet-stream",
    "application/pkix-crl",
    "application/postscript",
    "application/vnd.ms-excel",
    "application/vnd.ms-works",
    "application/x-internet-signup",
    "application/x-mspublisher",
    "application/x-mswrite",
    "application/futuresplash",
    "application/mac-binhex40",
    "application/pkcs10",
    "application/vnd.ms-excel",
    "application/vnd.ms-excel",
    "application/x-director",
    "application/x-javascript",
    "application/x-msmediaview",
    "application/x-msterminal",
    "application/x-perfmon",
    "application/x-troff-me",
    "application/vnd.ms-works",
    "application/x-latex",
    "application/x-msmediaview",
    "application/x-msmetafile",
    "application/x-x509-ca-cert",
    "application/x-zip-compressed",
    "application/x-pkcs12",
    "application/x-pkcs12",
    "application/x-x509-ca-cert",
    "application/pdf",
    "application/vnd.ms-excel",
    "application/x-texinfo",
    "application/pkcs7-mime",
    "application/vnd.ms-powerpoint",
    "application/x-director",
    "application/x-gtar",
    "text/scriptlet",
    "application/fractals",
    "application/octet-stream",
    "application/vnd.ms-powerpoint",
    "application/vndms-pkicertstore",
    "application/vndms-pkipko",
    "application/x-msschedule",
    "application/x-tar",
    "application/x-troff",
    "application/x-troff",
    "application/pics-rules",
    "application/rtf",
    "application/vnd.ms-powerpoint",
    "application/vnd.ms-works",
    "application/x-bcpio",
    "application/x-msdownload",
    "application/x-perfmon",
    "application/x-perfmon",
    "application/x-troff",
    "application/x-wais-source",
    "application/internet-property-stream",
    "application/vndms-pkiseccat",
    "application/x-cdf",
    "application/x-compressed",
    "application/x-sv4cpio",
    "application/x-tex",
    "application/x-ustar",
    "application/x-x509-ca-cert",
    "audio/x-pn-realaudio",
    "audio/mid",
    "audio/basic",
    "audio/basic",
    "audio/wav",
    "audio/aiff",
    "audio/x-mpegurl",
    "audio/x-pn-realaudio",
    "audio/aiff",
    "audio/mid",
    "audio/x-aiff",
    "audio/mpeg",
    "application/x-gzip",
    "application/x-compress",
    "text/tab-separated-values",
    "text/xml",
    "text/h323",
    "text/webviewhtml",
    "text/html",
    "text/html",
    "text/xml",
    "text/html",
    "image/cis-cod",
    "image/ief",
    "image/x-portable-bitmap",
    "image/tiff",
    "image/x-portable-pixmap",
    "image/x-rgb",
    "image/bmp",
    "image/jpeg",
    "image/x-cmx",
    "image/x-portable-anymap",
    "image/jpeg",
    "image/pjpeg",
    "image/tiff",
    "image/jpeg",
    "image/x-xbitmap",
    "image/x-cmu-raster",
    "image/gif"
]

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
        self.recursion_depth = args.recursion_depth
        self.recursion = args.recursion
        self.crawl_local_host_only = args.crawl_local_host_only

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
            url = url.replace(" ", "")
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

    def update_list(self, url, links):
        if url not in links:
            links.append(url)
            if self.verbose_level == "DEBUG":
                print(url)
        else:
            logger.debug("DEV: URL: '%s' already in links list!" % url)

    def get_hrefs(self, url, con=None, links=[], depth=0):

        try:
            if depth == 0:
                logger.info("Getting hrefs from: %s" % url)
                print("Getting hrefs from: %s" % url)
            elif depth >= self.recursion_depth and self.recursion_depth != 0:
                logger.info("href: %s -> Max depth [%d] reached!" % (url, depth))
                return []

            """ Standardize URL """
            url_obj = urlparse(url, 'http')
            url_host = url_obj.hostname
            url_base = url_obj.scheme + "://" + url_obj.netloc
            url = urlunparse(url_obj)

            """ Create new session """
            response = None

            if not con:
                con = requests.Session()
                con.headers.update({'User-Agent': user_agents[0]})

                """ Set connection/session properties """
                if self.requests_debug:
                    con.proxies.update(debug_proxies)
                    con.verify = False
                    con.allow_redirects = True
                else:
                    con.verify = False
                    con.allow_redirects = True

            """ Access given URL (Get the headers only) """
            try:
                response = con.head(url)
            except Exception as msg:
                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                return links

            """ Obtain the final URL after redirection """
            if response:
                if not response.status_code == 200:
                    if response.status_code in [301, 302]:
                        try:
                            url = response.headers["Location"]
                            logger.debug("HTTP: %s -> %s to %s" % (response.status_code, response.url, url))

                            """ Get URL's headers (Only) """
                            try:
                                response = con.head(url)
                            except Exception as msg:
                                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                                return links

                        except KeyError:
                            logger.debug("[HTTP %s]: %s -> Failed to retrieve final URL" % (response.status_code, url))
                            return links
                    else:
                        logger.info("[HTTP %s]: URL Fetch -> FAILED -> URL: %s" % (response.status_code, url))
                        return links

            logger.info("URL Fetch -> SUCCESS -> URL: %s" % url)

            """ If the resource is of given MIME type, mark it as href and do not resolve the links  """
            response_headers = response.headers
            if "Content-Type" in response_headers:
                if response_headers["Content-Type"] in default_mime_types:
                    logger.debug("Skip href lookup for: %s - The resource is: %s" % (
                        url, response_headers["Content-Type"]))
                    self.update_list(url, links)
                    return links

            """ Update visited URLs (Links) """
            self.update_list(url, links)

            """ This time, get the content with GET request """
            try:
                response = con.get(url)
            except Exception as msg:
                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                return links

            """ Parse the HTTP response """
            soup = BeautifulSoup(response.text, "html.parser")

            """ Retrieve all href/a elements  """
            # _links = soup.findAll('a', attrs={'href': re.compile(r"^http://|https://|.*\..*")})
            _links = soup.findAll('a')

            """ If any hrefs found, build href's url """
            if _links:
                for link in _links:
                    _url = ""
                    _href = link.get('href')

                    """ Skip hrefs to Parent Directory """
                    if _href == "/":
                        continue

                    if not _href:
                        continue

                    """ Build new url """
                    if url_host not in _href:
                        if _href.startswith("http://") or _href.startswith("https://"):
                            _url = _href
                        else:
                            if _href[:1] != "/":
                                """  The href does not start with / """
                                _url = url_base + r"/" + _href
                            elif _href[:1] == "/":
                                """ The href start with / """
                                _url = url_base + _href

                    if self.recursion:

                        """ Skip the URL if it's not in allowed list """
                        if self.crawl_local_host_only:
                            if url_host not in _url:
                                logger.debug("Skip: %s -> The host: %s not found" % (_url, url_host))
                                continue

                        if _url:
                            if _url not in links:
                                self.get_hrefs(_url, con, links, depth + 1)
                        else:
                            if _href not in links:
                                self.get_hrefs(_href, con, links, depth + 1)
                    else:
                        if _url:
                            self.update_list(_url, links)
                        else:
                            self.update_list(_href, links)

        except requests.exceptions.InvalidSchema:
            logger.error("Invalid URL format: %s" % url)
            return links

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

            con = requests.Session()
            con.headers.update({'User-Agent': user_agents[0]})

            """ Set connection/session properties """
            if self.requests_debug:
                con.proxies.update(debug_proxies)
                con.verify = False
                con.allow_redirects = True
            else:
                con.verify = False
                con.allow_redirects = True

            """ Access given URL """
            try:
                response = con.get(url)
            except Exception as msg:
                logger.error(msg)
                continue

            """ Obtain the final URL after redirection """
            if response:
                if not response.status_code == 200:
                    if response.status_code in [301, 302]:
                        try:
                            url = response.headers["Location"]
                            logger.debug("HTTP: %s -> %s to %s" % (response.status_code, response.url, url))
                            """ Get final URL """
                            try:
                                response = con.get(url)
                            except Exception as msg:
                                logger.error(msg)
                                continue
                        except KeyError:
                            logger.info("URL Download -> FAILED -> [HTTP%s] - URL: %s" % (response.status_code, url))
                            continue
                    else:
                        logger.info("URL Download -> FAILED -> [HTTP%s] - URL: %s" % (response.status_code, url))
                        continue

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
            out_file = out_file.replace(r"//", r"/")
            """ Make sure that files do not get overwritten """
            _out_file = out_file
            while True:
                if os.path.isfile(_out_file):
                    _out_file = out_file + " - " + str(download_index)
                    download_index += 1
                else:
                    out_file = _out_file
                    break

            if response.raw.data:
                with open(out_file, 'wb') as file:
                    shutil.copyfileobj(response.raw, file)
                    downloaded_files.append(out_file)
                    file.close()
            else:
                with open(out_file, 'w', encoding="utf8") as file:
                    file.write(response.text)
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

        """ Enable -gl if recursive mode (-r) selected """
        if self.recursion:
            logger.debug("Recursive mode specified, hence enabling '-gl' ...")
            self.get_links = True

        """ Disable --recursion-depth """
        if self.crawl_local_host_only:
            self.recursion = True
            self.recursion_depth = 0



def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                     description='Hyperion parser')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    custom_args = argsparser.add_argument_group('Custom arguments', "\n")
    """ Script arguments """
    script_args.add_argument("-i", "--input", type=str, action='store', dest='input', required=False,
                             help="Load and deobfuscate URLs from input file, or load files from given folder")

    script_args.add_argument("-d", "--download-folder", action='store', dest='download_folder', required=False,
                             default="downloads/", help="Specify custom download folder location (Default: downloads/")

    script_args.add_argument("-gl", "--get-links", action='store_true', dest='get_links', required=False,
                             default=False, help="Retrieve all available links/hrefs from loaded URLs")

    script_args.add_argument("-rl", "--recursive-hostonly", action='store_true', dest='crawl_local_host_only', required=False,
                             help="Enable recursive crawling (Applies to -gl), but crawl for hrefs containing the same url host as input url (Sets --limit-archive-items 0)")

    script_args.add_argument("-r", "--recursive", action='store_true', dest='recursion', required=False,
                             default=False, help="Enable recursive crawling (Applies to -gl)")

    custom_args.add_argument("-rd", "--recursion-depth", action='store', dest='recursion_depth', required=False,
                             default=20, help="Max recursion depth level for -r option (Default: 20)")

    script_args.add_argument("-z", "--zip", action='store_true', dest='zip_downloaded_files', required=False,
                             default=False, help="Compress all downloaded files, or files from input folder (If not zipped already)")

    custom_args.add_argument("--limit-archive-items", action='store', dest='max_file_count_per_archive', required=False,
                             default=9, help="Sets the limit of files per archive (Default: 9). [0 = Unlimited]")

    script_args.add_argument("--submit", action='store_true', dest='submit_to_vendors', required=False,
                             default=False, help="Submit files to AV vendors")

    script_args.add_argument("--skip-download", action='store_true', dest='skip_download', required=False,
                             default=False, help="Skips the download operation")

    script_args.add_argument("--debug-requests", action='store_true', dest='requests_debug', required=False,
                             default=False, help="Sends GET/POST requests via local proxy server 127.0.0.1:8080")

    script_args.add_argument("-v", "--verbose", type=str, action='store', dest='verbose_level', required=False,
                             default="DEBUG",
                             help="Set the logging level to one of following: INFO, WARNING, ERROR or DEBUG (Default: WARNING)")
    custom_args.add_argument("-sc", "--submission-comments", action='store', dest='submission_comments', required=False,
                             help="Insert submission comments (Default: <archive_name>)")

    #custom_args.add_argument("--allowed-hosts", action='store', dest='allowed_hosts', required=False, help="List of allowed domains, IPs that will be crawled")



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

        # Local file processing only (No download)
        """ Compress files if instructed to """
        if downloaded_files and dw.zip_downloaded_files:
            archives = dw.compress_files(downloaded_files)

    """ Print files by archive """
    if archives:
        print("Archives content:")
        for archive in archives:
            try:
                with zipfile.ZipFile(archive, 'r') as _archive:
                    members = _archive.namelist()
                    print("Archive: %s" % archive)
                    for member in members:
                        print(" - %s" % member)
                    logger.debug("Archive: %s -> Members: %s" % (archive, members))
            except Exception as msg:
                print("Archive: %s -> Unable to get members" % archive)
                logger.warning("Archive: %s -> Unable to get members" % archive)

    """ Submit files to vendors """
    if dw.submit_to_vendors:
        dw.submit(archives)
    else:
        logger.debug("Skipping Vendor submission")


if __name__ == "__main__":
    main(sys.argv)

