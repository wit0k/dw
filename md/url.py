import logging
import re
import socket

from urllib.parse import urlparse, urlunparse
import iocextract
from dns import reversename, resolver

logger = logging.getLogger('dw')

ipv4_v2 = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'
domain = r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'
domain2 = r'^([\-A-Za-z0-9\.])+$'

class url(object):

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __init__(self, url):

        """ I shall add the file type as well and expose it as a sample class or so """
        self.url = None
        self.file = None
        self.hash = None
        self.protocol = None
        self.initialized = None
        self.host = None
        self.host_name = None
        self.netloc = None
        self.base = None
        self.schema = None
        self.ip = None
        self.domain = None
        self.mime_type = None

        if not url:
            self.url = None
        elif '.' not in url:
            self.url = None
        else:

            self.url = self.deobfuscate(url)
            if self.url:
                # Determine the URL type
                if re.match(r"^file:/{2}[^/]", self.url):
                    self.protocol = "file"

            if self.url:
                self.initialized = True
                self._url_split()
                self._url_resolve()
            else:
                self.url = None

    def url(self, obfuscate=False):

        if obfuscate == False:
            return self.url
        else:
            return self.obfuscate(self.url)

    def obfuscate(self, str_item):

        if str_item:
            return str_item.replace('.', '[.]')



    def deobfuscate(self, url):

        if url:
            # Parse the URL via iocextract
            url_set = set(iocextract.extract_urls(url, refang=True))

            if url_set:
                _url = url_set.pop()
                logger.debug("Parsing URL: %s to: %s" % (url, _url))
                return _url
            else:
                return self._deobfuscate_m(url)

        else:
            return None

    def _url_split(self, schema='http'):

        try:
            url_obj = urlparse(self.url, schema)
            self.host = url_obj.hostname
            self. base = url_obj.scheme + "://" + url_obj.netloc
            self.netloc = url_obj.netloc
            self.schema = url_obj.scheme

            return True

        except Exception as msg:
            logger.error("Unable to parse URL: %s -> Error: %s" % (self.url, msg))
            return None

    def _url_resolve(self):

        if self.initialized:
            """ Check the URL typ """
            if re.match(ipv4_v2, self.host, re.IGNORECASE):
                """ Resolve the IP to a domain """
                self.ip = self.host

                try:
                    socket.inet_aton(self.ip)
                    self.domain = socket.getfqdn(self.ip)

                    rev_name = reversename.from_address(self.ip)
                    self.dns_ptr = str(resolver.query(rev_name, "PTR")[0])

                except Exception as msg:
                    return None

            elif re.match(domain, self.host, re.IGNORECASE) or re.match(domain2, self.host, re.IGNORECASE):
                self.domain = self.host

                try:
                    self.ip = socket.gethostbyname(self.domain)
                except Exception as msg:
                    return None

            else:
                logger.error("Unsupported URL: %s" % self.url)
                return None

    def _deobfuscate_m(self, url):
        """ Last resort - URL deobfuscation, currently not used """
        output_url = ""

        if url == "\n":
            return None

        output_url = url.strip()

        output_url = re.sub(r'^\/+', '', output_url)
        output_url = output_url.replace("[http://]", "http://")
        output_url = output_url.replace("[https://]", "https://")
        output_url = output_url.replace("hps://", "https://")
        output_url = output_url.replace(" (HTTP)", "")
        output_url = output_url.replace(" ", "")
        output_url = output_url.replace("htxp", "http")
        output_url = output_url.replace("hxtp", "http")
        output_url = output_url.replace("hxxp", "http")
        output_url = output_url.replace("h11p", "http")
        output_url = output_url.replace("xxp://", "http")
        output_url = output_url.replace(" || . || ", ".")
        output_url = output_url.replace("|| . ||", ".")
        output_url = output_url.replace("||.||", ".")
        output_url = output_url.replace("]]", "")
        output_url = output_url.replace("[[", "")
        output_url = output_url.replace("[.]", ".")
        output_url = output_url.replace("{.}", ".")
        output_url = output_url.replace(".]]]", ".")
        output_url = output_url.replace("[[[.", ".")
        output_url = output_url.replace("[:]", ":")
        output_url = output_url.replace("[.", ".")
        output_url = output_url.replace(".]", ".")
        output_url = output_url.replace(".[", ".")
        output_url = output_url.replace("].", ".")
        output_url = output_url.replace("[.", ".")
        output_url = output_url.replace("\.", ".")
        output_url = output_url.replace("/]", "/")
        output_url = output_url.replace(r"\]", '\\')
        output_url = output_url.replace(r'^.', '.')



        """ Remove incorrect schema like: :// or : or :/ etc. """
        if re.match(r"(^/+|^:/+|^:+)", output_url):
            """ Remove incorrect scheme, and leave it empty """
            output_url = re.sub(r"(^/+|^:/+|^:+)", "", output_url)
            output_url = "http://" + output_url
            output_url = output_url.replace(r"///", r"//")


        if output_url.startswith('http') or output_url.startswith('https') or output_url.startswith('file'):
            output_url = output_url.replace(r"///", r"//")
        else:
            output_url = "http://" + output_url
            output_url = output_url.replace(r"///", r"//")

        logger.debug("Parsing URL: %s to: %s" % (url, output_url))

        return output_url
