import logging
import re
import socket

from urllib.parse import urlparse, urlunparse

logger = logging.getLogger('dw')

ipv4_v2 = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'
domain = r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'

class url(object):

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __init__(self, url):

        """ I shall add the file type as well and expose it as a sample class or so """
        self.url = None
        self.url_final = None
        self.time_created = None
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
        self.av_category = None

        self.proxy_category = {}

        if not url:
            logger.error("")
        else:
            if self.parse_url(url):
                self.initialized = True
                self._split_url()
                self._resolve_url()

    def set_proxy_category(self, vendor_category):

        if isinstance(vendor_category, dict):
            for proxy_vendor, url_proxy_category in vendor_category.items():
                self.proxy_category[proxy_vendor] = url_proxy_category
        else:
            logger.error("Proxy category must be in format:  dict['proxy_vendor'']='url_proxy_category'")
            return None

    def get_proxy_catgeory(self, category_only=False):

        if self.proxy_category:
            if category_only:
                categories = []

                for url_proxy_category in self.proxy_category.values():
                    categories.append(url_proxy_category)

                if categories:
                    return ",".join(categories)
                else:
                    return ""
            else:
                return self.proxy_category

    def _split_url(self, schema='http'):

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

    def _resolve_url(self):

        if self.initialized:
            """ Check the URL typ """
            if re.match(ipv4_v2, self.host, re.IGNORECASE):
                """ Resolve the IP to a domain """
                self.ip = self.host

                try:
                    socket.inet_aton(self.ip)
                    self.domain = socket.getfqdn(self.ip)
                except Exception as msg:
                    return None

            elif re.match(domain, self.host, re.IGNORECASE):
                self.domain = self.host

                try:
                    self.ip = socket.gethostbyname(self.domain)
                except Exception as msg:
                    return None

            else:
                logger.error("Unsupported URL: %s" % self.url)
                return None

    def parse_url(self, url):

        output_url = ""
        input_url = url

        if url == "\n":
            return None

        output_url = url.strip()

        output_url = output_url.replace("[http://]", "http://")
        output_url = output_url.replace("[https://]", "https://")
        output_url = output_url.replace(" (HTTP)", "")
        output_url = output_url.replace(" ", "")
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



        """ Assume that the URL is valid at this stage """
        if re.match(r"^http:/{2}[^/]|^https:/{2}[^/]", output_url):
            logger.debug("Parsing URL: %s to: %s" % (input_url, output_url))
            self.url = output_url
            return output_url

        elif re.match(r"^file:/{2}[^/]", output_url):
            self.protocol = "file"
            self.url = output_url
            return output_url
        else:
            """ Remove incorrect schema like: :// or : or :/ etc. """
            if re.match(r"(^/+|^:/+|^:+)", output_url):
                """ Remove incorrect scheme, and leave it empty """
                output_url = re.sub(r"(^/+|^:/+|^:+)", "", output_url)
                output_url = "http://" + output_url
                output_url = output_url.replace(r"///", r"//")
            else:
                output_url = "http://" + output_url
                output_url = output_url.replace(r"///", r"//")

        logger.debug("Parsing URL: %s to: %s" % (input_url, output_url))

        self.url = output_url
        return output_url
