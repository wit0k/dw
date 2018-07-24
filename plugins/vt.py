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

        if self.hasher.get_hash_type(file_hash) in ['sha256', 'md5', 'sha1']:
            return True
        else:
            return False

    def get_report_file(self, file_hash):
        pass

    def download_file(self, file_hash, out_file=None):

        downloaded_file = None
        downloaded_file_hash = None

        logger.debug('VT Download: %s' % file_hash)

        if self._is_supported_hash(file_hash):

            hash_type = self.hasher.get_hash_type(file_hash)

            api_key = self.config_data.get("api_key", None)
            if api_key:
                params = {'apikey': api_key, 'hash': file_hash}

                try:
                    url = 'https://www.virustotal.com/vtapi/v2/file/download'
                    response = self.con.get(url, params=params)

                    if response:
                        if response.status_code == 404:
                            logger.debug('VT Download: HTTP 404 -> Hash: %s' % file_hash)
                        elif response.status_code == 200:
                            downloaded_file = response.content

                            if downloaded_file:

                                """ Check integrity """
                                downloaded_file_hash = self.hasher.get_hash(downloaded_file, hash_type)

                                if not downloaded_file_hash == file_hash:
                                    logger.error('Downloaded file integrity failed ...')
                                    return None

                                if not out_file:
                                    out_file = r'downloads/' + file_hash

                                logger.debug('VT Download success: %s {hash: %s}' % (url, file_hash))
                                with open(out_file, 'wb') as file:
                                    file.write(downloaded_file)
                                    logger.debug('VT Buffer save success: %s, %s' % (out_file, file_hash))

                            else:
                                test = ""
                        else:
                            logger.error('Unexpected result from VT API - HTTP %s' % response.status_code)
                            return None
                    else:
                        logger.error('A connection to VirusTotal failed and was not handled')
                        return None

                except Exception as msg:
                    logger.error('HTTP GET: %s %s -> Error: %s' % (url, file_hash, str(msg)))
                    return None
            else:
                logger.error('VT Download: Unable to load the API key')
                return None
        else:
            logger.error('VT Download: Unsupported hash: %s' % file_hash)
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
