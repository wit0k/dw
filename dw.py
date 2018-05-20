__author__  = "Witold Lawacz (wit0k)"
__date__    = "2018-03-12"
__version__ = '0.3.9'

"""
TO DO:
- Add exclusion to url
- Fix display issue when adding --url-info and mime url 
- Add bit.ly resolution to url class maybe ...
- archive folder check 
- Adopt AV to load_vendors (Proxy already supported)
- Print file info, when only loding files (like hash etc.)
- Add user agent randomization 

Sys req:
- brew install tesseract
"""

import md.submitter as submission
import re
import os
import pathlib
import logging
import argparse
import sys
import zipfile
import shutil
import json
import hashlib
import magic
import platform as _os
import requests
import time
import md.smb as cifs
import md.pastebin as _paste_bin
import md.url as _url_mod
from md.db import handler, database

import random

from md.uniq import *
from bs4 import BeautifulSoup # pip install bs4
from urllib.parse import urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app_name = "dw"
""" Set working directory so the script can be executed from any location/symlink """
os.chdir(os.path.dirname(os.path.abspath(__file__)))

MAGIC_FILE_PATH_LINUX = '/etc/magic'
MAGIC_FILE_PATH_MAC = '/usr/local/Cellar/libmagic/5.29/share/misc/magic'
MAGIC_FILE_PATH_WIN = r'C:/Users/Python3/Lib/site-packages/magic/libmagic/magic'

MIME_MARKER = ' ,(MIME: '
MIME_FOOTER = ')'

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
current_user_agent_index = 0
user_agents = ["Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)",
               "Wget/1.19.4 (darwin15.6.0)",
               "Wget/1.14 (linux-gnu)",
               "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0"
               ]
user_headers = {'Accept': '*/*'}
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
    "image/gif",
    "application/x-dosexec"
]

file_extensions = ["386","acm","asp","bas","bat","cab","cgi","chm","cla","class","cmd","cnv","com","cpl","crt","csh",
                   "ctl","dll","drv","exe","gms","hlp","hta","inf","ini","ins","isp","job","js","jse","lnk","mpd","msik",
                   "msp","ocx","opo","php","pif","pl","prc","rat","reg","scf","sct","scr","sh","shs","sys","tlb","tsp","vb",
                   "vbe","vbs","vxd","wbs","wbt","wiz","wsc","wsf","wsh",".zip",".7z",".rar",".exe",".dll",".msi",".ps1",".jar",
                   ".vbs",".log",".frx",".frm",".cls",".vbp",".scc",".bas", ".lib", ".apk"]

# Cache of URLs (It links URL string [key] with associated url object [value])
URL_CACHE = {}

class downloader (object):

    def __init__(self, args):

        self.verbose_level = args.verbose_level
        self.download_files = args.download_files
        self.submit_to_vendors = args.submit_to_vendors
        self.input = args.input
        self.archive_folder = args.archive_folder
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
        self.url_info = args.url_info
        self.unique_files = args.unique_files
        self.output_directory = args.output_directory
        self.url_info_force = args.url_info_force
        self.submitter_email = args.submitter_email
        self.submit_to_proxy_vendors = args.submit_to_proxy_vendors
        self.new_proxy_category = args.new_proxy_category
        self.proxy_vendors = {}
        self.submitter_obj = submission.submitter()
        self.pastebin_api_key = args.pastebin_api_key
        self.user_agent = args.user_agent
        self.do_not_print_mime_type = args.do_not_print_mime_type
        self.submit_hashes = args.submit_hashes

        """ pastebin """
        self.stdout_to_pastebin = args.stdout_to_pastebin
        self.pastebin_type = str(args.pastebin_type)
        self.pastebin_paste_expiration = args.pastebin_paste_expiration
        self.pastebin_title = args.pastebin_title

        """ Load proxy vendors """
        _proxy_vendor_names = self.to_list(args.proxy_vendors)
        self.proxy_vendors = self.submitter_obj.load_vendors("PROXY", _proxy_vendor_names, {"submitter_email": self.submitter_email})

        """ Check script arguments """
        self.check_args()

    def to_list(self, param, separator=","):
        param_list = []
        if param:
            if separator in param:
                for p in param.split(","):
                    param_list.append(p.strip())
            else:
                return [param]
        return param_list

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
                    archive_file = self.archive_folder + os.path.basename(file)
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
                        archive_file = self.archive_folder + zip_name_prefix + archive_extension
                    else:
                        archive_file = self.archive_folder + archive_name_prefix + archive_extension
                else:
                    # Case: Limit items count in archive
                    if zip_name_prefix:
                        archive_file = self.archive_folder + zip_name_prefix + "-" + str(archive_name_index) + archive_extension
                    else:
                        archive_file = self.archive_folder + archive_name_prefix + "-" + str(archive_name_index) + archive_extension

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

    def load_hashes_from_input_file(self, input_file):

        hashes = []
        if os.path.isfile(input_file):
            with open(input_file, "r", encoding="utf8") as file:
                lines = file.readlines()
                for line in lines:
                    if line == "\n":
                        continue

                    if line.upper() == '[END]' or line.upper() == '[END]\n':
                        break

                    line = line.strip()
                    if not line.startswith("#"):
                        hashes.append(line)

                return hashes
        else:
            logger.error("Input file: %s -> Not found!" % input_file)

    def load_urls_from_input_file(self, input_file):

        urls = []
        if os.path.isfile(input_file):
            with open(input_file, "r", encoding="utf8") as file:
                lines = file.readlines()
                for line in lines:

                    if line == '\n':
                        continue

                    if line.upper() == '[END]' or line.upper() == '[END]\n':
                        break

                    line = line.strip()
                    if not line.startswith("#"):

                        # Handle the case with MIME type included in the URL
                        if MIME_MARKER in line:
                            url, _, mime = line.partition(MIME_MARKER)
                            url = url.strip()
                            if url:
                                line = url

                        _url = _url_mod.url(line.strip())
                        urls.append(_url)

                return urls
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

        if isinstance(url, tuple):
            mime = url[1]
            url = url[0]
            url_with_mime = url + MIME_MARKER + str(mime) + MIME_FOOTER
        else:
            mime = None
            url_with_mime = None
            url_with_mime = url + MIME_MARKER + "None" + MIME_FOOTER

        if url not in links.keys():

            links[url] = {"mime": mime, "url_mime": url_with_mime}

            #links.append(url_with_mime)

            if self.verbose_level == "DEBUG":
                if mime:
                    print("%s, (%s)" % (url, mime))
                else:
                    print(url)
        else:
            logger.debug("DEV: URL: '%s' already in links list!" % url)

    def update_list_org(self, url, links):

        if isinstance(url, tuple):
            mime = url[1]
            url = url[0]
            url_with_mime = url + MIME_MARKER + str(mime) + MIME_FOOTER
        else:
            mime = None
            url_with_mime = None
            url_with_mime = url + MIME_MARKER + "None" + MIME_FOOTER

        if url not in links:
            links.append(url)
            #links.append(url_with_mime)

            if self.verbose_level == "DEBUG":
                if mime:
                    print("%s, (%s)" % (url, mime))
                else:
                    print(url)
        else:
            logger.debug("DEV: URL: '%s' already in links list!" % url)

    def _url_endswith(self, url="", extensions=[]):

        if url:
            if extensions:
                # Do not consider the TLD as an extension
                if url.count(r'/') > 3:
                    for _ext in extensions:
                        if url.endswith(_ext):
                            return True

                return False

    def get_hrefs_smb(self, url_obj, con=None, links=[], depth=0, protocol="file"):

        if not con:
            con = cifs.smb()

        con.connect(remote_server=url_obj.hostname, path=url_obj.path[1:])
        sys.exit(-1)

    def get_hrefs(self, url, con=None, links={}, depth=0):

        try:
            if depth == 0:
                logger.info("Getting hrefs from: %s" % url)
                print("Getting hrefs from: %s" % url)
            elif depth >= self.recursion_depth and self.recursion_depth != 0:
                logger.info("href: %s -> Max depth [%d] reached!" % (url, depth))
                return links


            """ Standardize URL ... i shall adopt it to new url object style """
            url_obj = urlparse(url, "http")
            url_host = url_obj.hostname
            url_base = url_obj.scheme + "://" + url_obj.netloc
            #url = urlunparse(url_obj)


            # test
            if url_obj.scheme == "file":
                self.get_hrefs_smb(url_obj=url_obj, links=links.keys())


            """ Create new session """
            response = None

            if not con:
                con = requests.Session()
                con.headers.update({'User-Agent': self.get_user_agent()})
                con.headers.update(user_headers)

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
                if self.in_links(url, links):
                    return links

                logger.debug("HTTP HEAD: %s" % url)
                response = con.head(url)
            except Exception as msg:
                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                return links

            """ Obtain the final URL after redirection """
            if response is not None:
                if not response.status_code == 200:
                    if response.status_code in [301, 302]:
                        try:
                            # Check here once the location is not URL!!!
                            url = response.headers["Location"]
                            logger.debug("HTTP HEAD: %s -> %s to %s" % (response.status_code, response.url, url))

                            """ Get URL's headers (Only) """
                            try:
                                logger.debug("HTTP HEAD: %s" % url)
                                response = con.head(url)
                            except Exception as msg:
                                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                                return links

                        except KeyError:
                            logger.debug("[HTTP HEAD %s]: %s -> Failed to retrieve final URL" % (response.status_code, url))
                            return links
                    else:
                        logger.info("[HTTP HEAD %s]: URL Fetch -> FAILED -> URL: %s" % (response.status_code, url))
                        return links

            logger.info("HTTP HEAD -> URL Fetch -> SUCCESS -> URL: %s" % url)

            """ If the resource is of given MIME type, mark it as href and do not resolve the links  """
            response_headers = response.headers
            if "Content-Type" in response_headers:
                if response_headers["Content-Type"] in default_mime_types:
                    content_type = response_headers["Content-Type"]
                    logger.debug("Skip href lookup for: %s - The resource is: %s" % (
                        url, content_type))
                    self.update_list((url, response_headers["Content-Type"]), links)
                    return links

            """ If the resource is know file extension, but Content-Type is not sent by the server """
            if self._url_endswith(url, file_extensions) :
                self.update_list(url, links)
                return links

            """ Update visited URLs (Links) """
            self.update_list(url, links)

            """ This time, get the content with GET request """
            try:
                logger.debug("HTTP GET: %s" % url)
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

                    if url == "?":
                        pass

                    if not _href:
                        continue

                    """ Skip hrefs to Parent Directory """
                    if _href == "/":
                        continue

                    if r"../" in _href:
                        continue

                    """ Automatically detect parent dir """
                    if _href[:1] == "/":
                        parent_url = url_base + _href
                        if len(parent_url) < len(url):
                            if parent_url in url:
                                continue

                    """ Detect and Skip mod_autoindex hrefs """
                    if re.match(r"(^\?[a-zA-Z]=[0-9A-Za-z];{0,1})([a-zA-Z]=[0-9A-Za-z];{0,1})*", _href):
                        continue

                    """ Detect and skip links automatically created in open directory like: Name, Last modified, Size, Description """
                    if _href in ["?ND", "?MA", "?SA", "?DA", "?sort=na", "?sort=nd", "?sort=da", "?sort=dd", "?sort=ea",
                                 "?sort=ed", "#"]:
                        continue

                    """ Build new url """
                    if url_host not in _href:
                        if _href.startswith("http://") or _href.startswith("https://"):
                            _url = _href
                        else:
                            if url[-1:] == "/" and _href[:1] == "/":
                                """  The url ends with / and the href starts with / """
                                _url = url + _href[1:]
                            elif url[-1:] != "/" and _href[:1] != "/":
                                """  The url does not end with / and the href does not start with / """
                                _url = url + "/" + _href
                            else:
                                _url = url + _href

                    """ Case: -r """
                    if self.recursion:
                        """ Case: -rl Skip the href if its host is not the same as the host of the base URL  """
                        if self.crawl_local_host_only:
                            if url_host not in _url:
                                logger.debug("Skip: %s -> The host: %s not found" % (_url, url_host))
                                continue

                        if _url:
                            # _url not in links
                            if not self.in_links(_url, links):
                                self.get_hrefs(_url, con, links, depth + 1)
                        else:
                            # _href not in links
                            if not self.in_links(_href, links):
                                self.get_hrefs(_href, con, links, depth + 1)
                    else:
                        if _url:
                            self.update_list(_url, links)
                        else:
                            self.update_list(_href, links)
            else:
                """ Update visited URLs (Links) """
                self.update_list(url, links)

        except requests.exceptions.InvalidSchema:
            logger.error("Invalid URL format: %s" % url)
            return links

        return links

    def in_links(self, link, links={}):
        if links:
            if link in links.keys():
                return True
            else:
                return False

        else:
            return False

    def get_hrefs_org(self, url, con=None, links=[], depth=0):

        try:
            if depth == 0:
                logger.info("Getting hrefs from: %s" % url)
                print("Getting hrefs from: %s" % url)
            elif depth >= self.recursion_depth and self.recursion_depth != 0:
                logger.info("href: %s -> Max depth [%d] reached!" % (url, depth))
                return []


            """ Standardize URL ... i shall adopt it to new url object style """
            url_obj = urlparse(url, "http")
            url_host = url_obj.hostname
            url_base = url_obj.scheme + "://" + url_obj.netloc
            #url = urlunparse(url_obj)


            # test
            if url_obj.scheme == "file":
                self.get_hrefs_smb(url_obj=url_obj, links=links)


            """ Create new session """
            response = None

            if not con:
                con = requests.Session()
                con.headers.update({'User-Agent': self.get_user_agent()})
                con.headers.update(user_headers)

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
                if url in links:
                    return links

                logger.debug("HTTP HEAD: %s" % url)
                response = con.head(url)
            except Exception as msg:
                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                return links

            """ Obtain the final URL after redirection """
            if response is not None:
                if not response.status_code == 200:
                    if response.status_code in [301, 302]:
                        try:
                            # Check here once the location is not URL!!!
                            url = response.headers["Location"]
                            logger.debug("HTTP HEAD: %s -> %s to %s" % (response.status_code, response.url, url))

                            """ Get URL's headers (Only) """
                            try:
                                logger.debug("HTTP HEAD: %s" % url)
                                response = con.head(url)
                            except Exception as msg:
                                logger.error("con.get(%s) -> Error: %s" % (url, msg))
                                return links

                        except KeyError:
                            logger.debug("[HTTP HEAD %s]: %s -> Failed to retrieve final URL" % (response.status_code, url))
                            return links
                    else:
                        logger.info("[HTTP HEAD %s]: URL Fetch -> FAILED -> URL: %s" % (response.status_code, url))
                        return links

            logger.info("HTTP HEAD -> URL Fetch -> SUCCESS -> URL: %s" % url)

            """ If the resource is of given MIME type, mark it as href and do not resolve the links  """
            response_headers = response.headers
            if "Content-Type" in response_headers:
                if response_headers["Content-Type"] in default_mime_types:
                    content_type = response_headers["Content-Type"]
                    logger.debug("Skip href lookup for: %s - The resource is: %s" % (
                        url, content_type))
                    self.update_list((url, response_headers["Content-Type"]), links)
                    return links

            """ If the resource is know file extension, but Content-Type is not sent by the server """
            if self._url_endswith(url, file_extensions):
                self.update_list(url, links)
                return links

            """ Update visited URLs (Links) """
            self.update_list(url, links)

            """ This time, get the content with GET request """
            try:
                logger.debug("HTTP GET: %s" % url)
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

                    if url == "?":
                        pass

                    if not _href:
                        continue

                    """ Skip hrefs to Parent Directory """
                    if _href == "/":
                        continue

                    if r"../" in _href:
                        continue

                    """ Automatically detect parent dir """
                    if _href[:1] == "/":
                        parent_url = url_base + _href
                        if len(parent_url) < len(url):
                            if parent_url in url:
                                continue

                    """ Detect and Skip mod_autoindex hrefs """
                    if re.match(r"(^\?[a-zA-Z]=[0-9A-Za-z];{0,1})([a-zA-Z]=[0-9A-Za-z];{0,1})*", _href):
                        continue

                    """ Detect and skip links automatically created in open directory like: Name, Last modified, Size, Description """
                    if _href in ["?ND", "?MA", "?SA", "?DA", "?sort=na", "?sort=nd", "?sort=da", "?sort=dd", "?sort=ea",
                                 "?sort=ed", "#"]:
                        continue

                    """ Build new url """
                    if url_host not in _href:
                        if _href.startswith("http://") or _href.startswith("https://"):
                            _url = _href
                        else:
                            if url[-1:] == "/" and _href[:1] == "/":
                                """  The url ends with / and the href starts with / """
                                _url = url + _href[1:]
                            elif url[-1:] != "/" and _href[:1] != "/":
                                """  The url does not end with / and the href does not start with / """
                                _url = url + "/" + _href
                            else:
                                _url = url + _href

                    """ Case: -r """
                    if self.recursion:
                        """ Case: -rl Skip the href if its host is not the same as the host of the base URL  """
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
            else:
                """ Update visited URLs (Links) """
                self.update_list(url, links)

        except requests.exceptions.InvalidSchema:
            logger.error("Invalid URL format: %s" % url)
            return links

        return links

    def get_file_info(self, filepath, url=None):

        file_info = []
        proxy_category = None

        """ Get the hash """
        hash_obj = hashlib.sha256()
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_obj.update(chunk)

            file_info.append(hash_obj.hexdigest())

        """ Get file MIME type """
        if 'Darwin' in _os.platform():
            MAGIC_FILE_PATH = MAGIC_FILE_PATH_MAC
        elif 'Linux' in _os.platform():
            MAGIC_FILE_PATH = MAGIC_FILE_PATH_LINUX
        else:
            MAGIC_FILE_PATH = MAGIC_FILE_PATH_WIN

        obj_magic = magic.Magic(magic_file=MAGIC_FILE_PATH, mime=True, uncompress=True)
        file_info.append(obj_magic.from_file(filepath))

        """ Append file path """
        file_info.append(filepath)

        if url:
            url_obj = urlparse(url, 'http')
            url_host = url_obj.hostname

            if self.url_info_force:
                proxy_category = self.get_url_info(url)

            if self.url_info:
                proxy_category = self.get_url_info(url_host)

            if proxy_category:
                file_info.append(proxy_category)

            file_info.append(url)

        return ",".join(file_info)

    def get_user_agent(self):

        if self.user_agent:
            return self.user_agent

        return user_agents[current_user_agent_index]

    def download(self, urls, report=[]):

        download_index = 0
        downloaded_files = []
        sha256 = ""

        con = requests.Session()
        con.headers.update({'User-Agent': self.get_user_agent()})
        con.headers.update(user_headers)

        logger.debug("Headers: %s" % con.headers.items())

        """ Set connection/session properties """
        if self.requests_debug:
            con.proxies.update(debug_proxies)
            con.verify = False
            con.allow_redirects = True
            con.stream = True
        else:
            con.verify = False
            con.allow_redirects = True
            con.stream = True

        for url in urls:

            """ Access given URL """
            try:
                response = con.get(url)
            except Exception as msg:
                logger.error(msg)
                continue

            """ Obtain the final URL after redirection """
            if response:
                if not response.status_code == 200:
                    if response.status_code in [301, 302]: # Sometimes allow_redirects does not work; hence this additional routine
                        try:
                            url = response.headers["Location"]
                            logger.info("Resolve redirect: HTTP: %s -> %s to %s" % (response.status_code, response.url, url))
                            """ Get final URL """
                            try:
                                response = con.get(url)
                            except Exception as msg:
                                logger.error(msg)
                                continue
                        except KeyError:
                            logger.info("URL Download -> FAILED -> [HTTP GET %s] - URL: %s" % (response.status_code, url))
                            continue
                    else:
                        logger.info("URL Download -> FAILED -> [HTTP GET %s] - URL: %s" % (response.status_code, url))
                        continue
            else:
                logger.info("URL Download -> FAILED -> [HTTP GET %s] - URL: %s" % (response.status_code, url))
                continue

            """ Keep the track of final URL """
            if response.url != url:
                url = response.url
                logger.info("Final URL: %s -> %s" % (url, response.url))
            else:
                url = response.url

            logger.info("URL Download -> SUCCESS -> [HTTP GET %s] - URL: %s" % (response.status_code, url))

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

            # Make sure that the local file name is safe file name
            extension = pathlib.Path(local_filename).suffix
            local_filename = "".join(x for x in local_filename if x.isalnum())
            if extension:
                local_filename = local_filename + extension

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
                    file.write(response.raw.data)
                    downloaded_files.append(out_file)
                    file.close()
            else:
                try:
                    response_text = response.text
                except Exception as msg:
                    response_text = None

                if response_text:
                    with open(out_file, 'w') as file:
                        try:
                            file.write(response.text)
                            downloaded_files.append(out_file)
                            file.close()
                        except:
                            logger.warning("Unable to save response.text -> ur:" % url)
                            continue
                else:
                    # Fix to requests bug
                    logger.warning("Error: response.raw.data and response.text are Null. URL: %s" % url)
                    continue

            """ Log file info """
            file_info = self.get_file_info(out_file, url)
            print(file_info)
            logger.info(file_info)

            report.append(file_info)


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

    def get_tracking_id(self, response_text):

        pattern = re.compile(r'Number: ([0-9]{8,9}){1}<', re.I | re.MULTILINE)

        for match in pattern.finditer(response_text):
            tracking_id = match.groups()
            if tracking_id:

                return str(''.join(tracking_id))
            else:
                return None

    def submit_hash(self, hashes, vendor_name="Symantec"):

        if hashes:
            url = ""
            file_content = None
            submission_success_message = ""
            form_data = {}
            headers = {}

            """ Pull vendor specific POST data fields """
            if vendor_name == "Symantec":
                form_data = self.POST_DATA["Symantec"]["form_data"]
                form_data['stype'] = (None, 'hash')
                headers = self.POST_DATA["Symantec"]["headers"]
                url = self.POST_DATA["Symantec"]["url"]
                submission_success_message = self.POST_DATA["Symantec"]["success_message"]

            for hash in hashes:
                logger.info("Submitting: %s to: %s" % (hash, url))

                form_data['hash'] = (None, hash)

                """ Adjust form_data according to script parameters """
                if self.submission_comments:
                    form_data["comments"] = self.submission_comments
                else:
                    form_data["comments"] = hash

                """ Adjust form_data with data from vendor file  """
                self._update_headers(form_data, self.POST_DATA["Symantec"]["config_file"])

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
                            tracking_id = self.get_tracking_id(response.text)

                            logger.info("Vendor: %s: Submission Success -> Hash: %s, %s" % (vendor_name, hash, tracking_id))
                            print("Vendor: %s: Submission Success -> Hash: %s, %s" % (vendor_name, hash, tracking_id))

                            """ Wait a random time """
                            sleep_time = random.randint(1, 3)
                            logger.debug("Thread Sleep for %d seconds" % sleep_time)
                            time.sleep(sleep_time)
                        else:
                            logger.info(
                                "Vendor: %s: Submission Failure: Hash: %s\n Message: \n %s" % (vendor_name, hash, response.text))
                            print("Vendor: %s: Submission Failure: Hash: %s\n Message: \n %s" % (vendor_name, hash, response.text))

        else:
            logger.warning("Nothing to submit!")

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
                            tracking_id = self.get_tracking_id(response.text)
                            logger.info(
                                "Vendor: %s: Submission Success -> File: %s, %s" % (vendor_name, file, tracking_id))
                            print("Vendor: %s: Submission Success -> File: %s, %s" % (vendor_name, file, tracking_id))

                            """ Wait a random time """
                            sleep_time = random.randint(1, 3)
                            logger.debug("Thread Sleep for %d seconds" % sleep_time)
                            time.sleep(sleep_time)
                        else:
                            logger.info(
                                "Vendor: %s: Submission Failure: File: %s\n Message: \n %s" % (vendor_name, file, response.text))
                            print("Vendor: %s: Submission Failure: File: %s\n Message: \n %s" % (vendor_name, file, response.text))


        else:
            logger.warning("Nothing to submit!")

    def check_args(self):

        if not os.path.isfile(self.input):
            logger.warning("Input file: %s not found!" % self.input)
            if os.path.isdir(self.input):
                self.input_type = "folder"
                logger.info("Input folder set to: %s" % self.input)
            else:
                logger.error("Input file or folder: %s not found! Use -i <param> to specify the input data" % self.input)
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

        """ Check output directory """
        if self.output_directory:
            if os.path.isfile(self.output_directory):
                logger.error("The output folder: %s is already taken by file" % self.output_directory)
                exit(-1)
            elif not os.path.isdir(self.output_directory):
                logger.debug("Creating output folder: %s" % self.output_directory)
                os.mkdir(self.output_directory)

        """ When zip enabled and archive folder does not exist """
        if self.zip_downloaded_files and not os.path.isdir(self.archive_folder):
            os.makedirs(self.archive_folder)

        """ Enable -gl if recursive mode (-r) selected """
        if self.recursion:
            logger.debug("Recursive mode specified, hence enabling '-gl' ...")
            self.get_links = True

        """ Disable --recursion-depth """
        if self.crawl_local_host_only:
            self.recursion = True
            self.recursion_depth = 0
            self.get_links = True

        """ Skip download in case user specified a folder """
        if self.input_type == "folder":
            self.download_files = False
            self.get_links = False
            self.url_info = False

        """ Enable compression if submit option is enabled """
        if self.submit_to_vendors:
            self.zip_downloaded_files = True
            #self.get_links = False
            #self.recursion = False

            if self.input_type != "folder":
                self.download_files = True

        """ pastebin params """
        if self.stdout_to_pastebin:
            if not self.pastebin_api_key:
                logger.error("pastebin: API key not specified !")
                sys.exit(-1)

        if self.pastebin_type not in _paste_bin.private_values.keys():
            logger.error("pastebin: Incorrect paste type !")
            sys.exit(-1)

        if self.pastebin_paste_expiration not in _paste_bin.expire_values.keys():
            logger.error("pastebin: Incorrect expiration time !")
            sys.exit(-1)

    def get_url_info(self, urls, vendor_name="bluecoat"):

        url_submitter = self.proxy_vendors[vendor_name.upper()]
        url_category = None

        if url_submitter:

            if not isinstance(urls, list):
                urls = [urls]

            for url in urls:
                if url:
                    url_category = url_submitter.get_category(url, self.url_info_force)

                    if url_category:
                       pass

            return url_category

        else:
            logger.error("Vendor: '%s' -> Unable to initialize the submitter class" % vendor_name)
            return "Error"

    def submit_url_category(self, url, category):

        for vendor_name, submitter in self.proxy_vendors.items():
            submitter.submit_category(category, url)

    def uplaod_to_pastebin(self, data_entries, paste_name='Example Script', paste_type='0', paste_expire='1H', paste_format='Python', is_guest=True):

        _ldata = []
        _data = []
        for entry in data_entries:
            if isinstance(entry, list):
                for i in entry:
                    _ldata.append(i)
            else:
                _ldata.append(entry)

        # Make it less error prone with For and try catch
        try:
            data = "\n".join(_ldata)
        except Exception:
            logger.error("Unexpected data found. Cancelling pastebin upload.")
            logger.error("Pastebin data: %s %s" % ("\n", _ldata))
            return None

        if self.pastebin_api_key:
            api = _paste_bin.PasteBin(api_dev_key=self.pastebin_api_key)
            paste_url = api.paste(data, guest=is_guest, name=paste_name, format=paste_format, private=paste_type, expire=paste_expire)
            print("PasteBin URL: %s" % paste_url)

def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS, description='Hyperion parser')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    crawling_args = argsparser.add_argument_group('Crawling arguments', "\n")
    networking_args = argsparser.add_argument_group('Networking arguments', "\n")
    submission_args = argsparser.add_argument_group('submission arguments', "\n")
    pastebin_args = argsparser.add_argument_group('pastebin arguments', "\n")

    """ Script arguments """
    script_args.add_argument("-i", "--input", type=str, action='store', dest='input', required=False,
                             default="urls.txt", help="Load and deobfuscate URLs from input file, or load files from given folder for further processing")

    script_args.add_argument("-d", "--download-folder", action='store', dest='download_folder', required=False,
                             default="downloads/", help="Specify custom download folder location (Default: downloads/")

    script_args.add_argument("-a", "--archive", type=str, action='store', dest='archive_folder', required=False, default="archive/",
                             help="Specify custom archive folder location (Default: 'archive/')")

    script_args.add_argument("-o", action='store', dest='output_directory', required=False,
                             default=None, help="Copy loaded/deduplicated files into specified output directory (Applicable when -dd is used)")

    script_args.add_argument("-dd", "--dedup", action='store_true', dest='unique_files', required=False,
                             default=False, help="Deduplicate the input and downloaded files")

    script_args.add_argument("-v", "--verbose", type=str, action='store', dest='verbose_level', required=False,
                             default="INFO",
                             help="Set the logging level to one of following: INFO, WARNING, ERROR or DEBUG (Default: WARNING)")

    script_args.add_argument("--download", action='store_true', dest='download_files', required=False,
                             default=False, help="Download loaded or crawled URLs")

    script_args.add_argument("-z", "--zip", action='store_true', dest='zip_downloaded_files', required=False,
                             default=False, help="Compress all downloaded files, or files from input folder (If not zipped already)")

    script_args.add_argument("--no-mime", "-nm", action='store_true', dest='do_not_print_mime_type', required=False,
                             default=False,
                             help="Print All retrieved HREFs without a mime type")

    script_args.add_argument("--limit-archive-items", action='store', dest='max_file_count_per_archive', required=False,
                             default=9, help="Sets the limit of files per archive (Default: 9). [0 = Unlimited]")

    """  CRAWLING  ------------------------------------------------------------------------------------------------- """
    crawling_args.add_argument("-gl", "--get-links", action='store_true', dest='get_links', required=False,
                               default=False, help="Retrieve all available links/hrefs from loaded URLs")

    crawling_args.add_argument("-rl", "--recursive-hostonly", action='store_true', dest='crawl_local_host_only',
                               required=False,
                               help="Enable recursive crawling (Applies to -gl), but crawl for hrefs containing the same url host as input url (Sets --recursion-depth 0 and enables -gl)")

    crawling_args.add_argument("-r", "--recursive", action='store_true', dest='recursion', required=False,
                               default=False, help="Enable recursive crawling (Applies to -gl, enables -gl)")

    crawling_args.add_argument("-rd", "--recursion-depth", action='store', dest='recursion_depth', required=False,
                               default=20, help="Max recursion depth level for -r option (Default: 20)")

    """  SUBMISSION  ----------------------------------------------------------------------------------------------- """
    submission_args.add_argument("--submit", action='store_true', dest='submit_to_vendors', required=False,
                             default=False, help="Submit files to AV vendors (Enables -z by default)")

    submission_args.add_argument("--submit-hash", action='store_true', dest='submit_hashes', required=False,
                                 default=False, help="Submit hashes to AV vendors")

    submission_args.add_argument("--submit-url", action='store_true', dest='submit_to_proxy_vendors', required=False,
                             default=False, help="Submit loaded URLs to PROXY vendors...")

    submission_args.add_argument("-ui", "--url-info", action='store_true', dest='url_info', required=False,
                             default=False,
                             help="Retrieve URL information from supported vendors for all loaded input URLs.")

    submission_args.add_argument("-uif", "--url-info-force", action='store_true', dest='url_info_force', required=False,
                             default=False,
                             help="Force url info lookup for every crawled URL (NOT recommended)")

    submission_args.add_argument("-sc", "--submission-comments", action='store', dest='submission_comments',
                                 required=False,
                                 help="Insert submission comments (Default: <archive_name>)")

    submission_args.add_argument("--proxy-vendors", action='store', dest='proxy_vendors', required=False,
                             default="bluecoat", help="Comma separated list of PROXY vendors used for URL category lookup and submission")

    submission_args.add_argument("--email", action='store', dest='submitter_email', required=False,
                             default="", help="Specify the submitter's e-mail address")

    submission_args.add_argument("--proxy-category", action='store', dest='new_proxy_category', required=False,
                             default="", help="Specify new proxy category (If not specified default proxy category will be used)")

    """  REQUESTS -------------------------------------------------------------------------------------------------- """
    networking_args.add_argument("--user-agent", action='store', dest='user_agent', required=False,
                             help="User-agent string, which would be used by -gl and --download")

    networking_args.add_argument("--debug-requests", action='store_true', dest='requests_debug', required=False,
                                 default=False, help="Sends GET/POST requests via local proxy server 127.0.0.1:8080")

    """  PASTEBIN -------------------------------------------------------------------------------------------------- """
    pastebin_args.add_argument("--pastebin-api", action='store', dest='pastebin_api_key', required=False,
                             help="API dev key for pastebin.com (If not specified, other pastebin params would be ignored)")

    pastebin_args.add_argument("-pu", "--pastebin-upload", action='store_true', dest='stdout_to_pastebin', required=False, default=False,
                             help="Uploads stdout to pastebin and prints the paste's url")

    pastebin_args.add_argument("-pv", "--pastebin-visibility", action='store', dest='pastebin_type', required=False,
                             default="0", help="Set the paste visibility: 0 - Public or 2 - Private (Default: 0)")

    pastebin_args.add_argument("-pe", "--pastebin-expiration", action='store', dest='pastebin_paste_expiration', required=False,
                               default="1W", help="Set the paste expiration time to one of following: 'N': 'Never', '10M': "
                                                  "'10 Minutes','1H': '1 Hour','1D': '1 Day','1W': '1 Week','2W': '2 Weeks','1M': '1 Month' ... (Default: 1H)")

    pastebin_args.add_argument("-pt", "--pastebin-title", action='store', dest='pastebin_title', required=False,
                               default="", help="Paste title")

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
    _uniq = uniq()
    urls = []
    hashes = []
    hashes_tracking = []
    hrefs = []
    hrefs_mime = []
    downloaded_files = []
    archives = []
    pastebin_report = []


    """ TEST """
    #db = database("database.pdl")
    #db_handler = handler(db)

    """ Load URLs from input file, or directly load files from a folder """
    if dw.input:
        if dw.input_type == "file":
            if dw.submit_hashes:
                hashes = dw.load_hashes_from_input_file(dw.input)
                logger.debug("Loaded [%d] Hashes from: %s" % (len(hashes), dw.input))
            else:
                urls = dw.load_urls_from_input_file(dw.input)
                logger.debug("Loaded [%d] URLs from: %s" % (len(urls), dw.input))
        elif dw.input_type == "folder":
            downloaded_files = dw.load_files_from_input_folder(dw.input)
            logger.debug("Loaded [%d] files from: %s" % (len(downloaded_files), dw.input))
        else:
            logger.error("Unsupported input type" % dw.input)
            exit(-1)

    # TEST
    # db_handler.insert(urls[0])

    """ Deduplicate the input """
    if dw.unique_files:
        _uniq = uniq()
        if downloaded_files:
            downloaded_files = _uniq.get_unique_files(downloaded_files)
            print("Distinct input files:")
            print(*downloaded_files, sep="\n")
        elif urls:
            urls = _uniq.get_unique_entries(urls)
            print("Distinct input URLs:")
            print(*[u.url for u in urls], sep="\n")
        elif hashes:
            hashes = _uniq.get_unique_entries(hashes)

    """ Update pastebin report """
    if urls:
        pastebin_report.append("Input URLs:")
        pastebin_report.append([u.url for u in urls])
    elif downloaded_files:
        pastebin_report.append("Input files:")
        pastebin_report.append(downloaded_files)
    else:
        pastebin_report.append("Input hashes:")
        pastebin_report.append(hashes)

    """ Save deduplicated loaded files to another directory """
    if dw.output_directory:
        if dw.unique_files:
            if downloaded_files:
                logger.info("Copy deduplicated files to %s:" % dw.output_directory)
                for file in downloaded_files:
                    dirname = os.path.dirname(file)
                    destination_file = os.path.join(dirname, dw.output_directory)
                    logger.debug("Save: %s to %s/ folder" % (file, destination_file))
                    shutil.copy2(file, destination_file)


    """ Get URL info for all loaded URLs (Fills in the URL_PROXY_CATEGORIZATION dict)"""
    if dw.url_info:
        pastebin_report.append("Input URL(s) info:")
        print("Input URL(s) info:")
        for url in urls:
            url.set_proxy_category({"bluecoat": dw.get_url_info(url.url)})
            pastebin_report.append("%s, %s, %s, %s" % (url.ip, url.domain, url.get_proxy_catgeory(True), url.url))
            print("%s, %s, %s, %s" % (url.ip, url.domain, url.get_proxy_catgeory(True), url.url))
    else:
        logger.debug("Skipping URL info gathering")

    """ Submit loaded URLs to proxy vendors """
    if dw.submit_to_proxy_vendors:
        for url in urls:
            dw.submit_url_category(url.url, dw.new_proxy_category)

    """ Submit loaded hashes to configured AV vendors """
    if dw.submit_hashes:
        if hashes:
            hashes_tracking = dw.submit_hash(hashes)



    """ Retrieve HREFs for each URL """
    if dw.get_links and urls:
        logger.debug("Get links from each URL")
        for url in urls:

            if url.url not in hrefs:
                links = {}
                _hrefs = dw.get_hrefs(url.url, links=links)
                logger.debug("Found [%d] hrefs on: %s" % (len(_hrefs), url.url))
                hrefs.extend(links.copy())

                for key, value in _hrefs.items():
                    url_mime = value.get("url_mime", None)
                    hrefs_mime.append(url_mime)

            else:
                logger.debug("SKIP: %s -> already in URL cache" % url.url)

        if dw.do_not_print_mime_type:
            logger.info("All retrieved HREFs:")
            logger.info(hrefs)
            print("All retrieved HREFs:")
            print(*hrefs, sep="\n")
            print("----------------------------------------------------------.")
        else:
            logger.info("All retrieved HREFs:")
            logger.info(hrefs_mime)
            print("All retrieved HREFs:")
            print(*hrefs_mime, sep="\n")
            print("----------------------------------------------------------.")

        pastebin_report.append("Detected HREFs:")
        pastebin_report.append(_uniq.get_unique_entries(hrefs))

    else:
        logger.debug("Skipping href lookup")

    """ Download if required """
    if dw.download_files:

        pastebin_report.append("Downloaded files:")

        if hrefs:
            """ Download pulled hrefs """
            downloaded_files = dw.download(hrefs, pastebin_report)
        else:
            """ Download given URLs """
            downloaded_files = dw.download([u.url for u in urls], pastebin_report)

        """ Deduplicate downloaded files """
        if dw.unique_files:
            if downloaded_files:
                downloaded_files = _uniq.get_unique_files(downloaded_files)
    else:
        logger.debug("Skipping files download")

    """ Compress files if instructed to """
    if downloaded_files and dw.zip_downloaded_files:
        archives = dw.compress_files(downloaded_files)
    else:
        logger.debug("Skipping files compression")

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

    """ Upload a report to pastebin """
    if dw.stdout_to_pastebin:
        dw.uplaod_to_pastebin(pastebin_report, dw.pastebin_title, dw.pastebin_type, dw.pastebin_paste_expiration)
    else:
        logger.debug("Skipping pastebin submission")


if __name__ == "__main__":
    main(sys.argv)

