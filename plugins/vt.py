"""
TO DO:
...
"""

import logging
from md.plugin import plugin

logger = logging.getLogger('dw')


class vt(plugin):

    author = 'wit0k'
    description = 'Handle VirusTotal Private API'
    config_file = 'plugins/vt.py.vd'
    plugin_type = 'VT'
    vendor_name = 'Google'
    required_params = ['debug_proxies', 'submission_comments', 'requests_debug']
    config_data = {}

    def _is_supported_hash(self, file_hash):
        return True

    def download_file(self, file_hash, out_file=None):

        downloaded_file = None
        if self._is_supported_hash(file_hash):
            api_key = self.config_data.get("api_key", None)
            if api_key:
                params = {'apikey': api_key, 'hash': file_hash}

                try:
                    url = 'https://www.virustotal.com/vtapi/v2/file/download'
                    response = self.con.get(url, params=params)

                    downloaded_file = response.content

                    if downloaded_file:
                        if not out_file:
                            out_file = r'downloads/' + file_hash

                        with open(out_file, 'wb') as file:
                            file.write(downloaded_file)

                        """ Re-check the hash """
                        test = ""
                    else:
                        test = ""

                except Exception as msg:
                    logger.error('HTTP GET: %s %s -> Error: %s' % (url, str(params), str(msg)))
                    return None
            else:
                logger.error('Unable to load the API key')
                return None
        else:
            logger.error('Unsupported hash: %s' % file_hash)
            return None

            api_key = None

        return downloaded_file


    def submit_url(self, urlobj, submission_comments=None, submitter_email=None):
        pass

    def query_url(self, urlobj, params={}):
        pass

    """ Exposed plugin functions via plugin.call """
    plugin_functions = {"submit_url": submit_url,
                        "query_url": query_url,
                        "download_file": download_file
                        }
