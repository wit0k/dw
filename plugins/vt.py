"""
TO DO:
- Update cache sections
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
    config_data = {}

    def _is_supported_hash(self, file_hash):

        if self.hasher.get_hash_type(file_hash) in ['sha256', 'md5', 'sha1']:
            return True
        else:
            return False

    def file_report(self, file_hash, return_excerpt=False):

        logger.debug('VT Report: %s' % file_hash)

        vt_response = None
        excerpt = None

        if self._is_supported_hash(file_hash):
            api_key = self.config_data.get("api_key", None)

            if api_key:
                params = {'apikey': api_key, 'resource': file_hash, 'allinfo': 1}

                headers = self.config_data.get('headers', None)
                response = self.con.get('https://www.virustotal.com/vtapi/v2/file/report',
                                        params=params, headers=headers)
                vt_response = response.json()

                positives = str(vt_response.get('positives', None))
                total = str(vt_response.get('total', None))

                score = ''
                if positives and total:
                    score = positives + "/" + total

                av_selected_vendor_names = ['Symantec']
                av_selected_vendor_results = []

                scans = vt_response.get('scans', None)
                if scans:
                    for av_vendor_name in av_selected_vendor_names:
                        if scans.get(av_vendor_name, None):
                            av_selected_vendor_results.append(av_vendor_name + ': ' + scans.get(av_vendor_name, None).get('result'))

                result_line = ', '.join(av_selected_vendor_results)
                excerpt = score + ', ' + result_line

            logger.debug('Excerpt: %s' % excerpt)

            if return_excerpt:
                return excerpt
            else:
                return vt_response

        return None

    def file_download(self, file_hash, out_file=None):

        downloaded_file = None

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
                                logger.error('Unexpected Error: Downloaded file buffer is empty...')
                                return None
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

    """ Exposed plugin functions via plugin.call """
    plugin_functions = {"file_download": file_download,
                        "file_report": file_report
                        }
