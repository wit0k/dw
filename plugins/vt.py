"""
TO DO:
- Update cache sections
"""

import logging
from os.path import isfile

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

        vt_response = self.cache.vt.get_report(file_hash)
        excerpt = self.cache.vt.get_excerpt(file_hash)

        if vt_response:
            logger.debug('CACHE -> Excerpt: %s' % excerpt)
            print('%s, %s' % (file_hash, excerpt))

            if return_excerpt:
                return excerpt
            else:
                return vt_response

        if self._is_supported_hash(file_hash):
            api_key = self.config_data.get("api_key", None)

            if api_key:
                params = {'apikey': api_key, 'resource': file_hash, 'allinfo': 1}

                headers = self.config_data.get('headers', None)
                response = self.con.get('https://www.virustotal.com/vtapi/v2/file/report',
                                        params=params, headers=headers)

                vt_response = response.json()

                """ Case where file is not submitted yet """
                if vt_response.get('response_code', None) == 0:
                    return ' Not Found on VT'

                positives = str(vt_response.get('positives', None))
                total = str(vt_response.get('total', None))

                score = ''
                if positives and total:
                    score = "VT Score: " + positives + "/" + total

                av_selected_vendor_names = ['Symantec', 'Microsoft']
                av_selected_vendor_results = []

                scans = vt_response.get('scans', None)
                if scans:
                    for av_vendor_name in av_selected_vendor_names:
                        if scans.get(av_vendor_name, None):
                            _vendor_result = scans.get(av_vendor_name, None)
                            if _vendor_result:
                                _vendor_result = str(_vendor_result.get('result'))

                            av_selected_vendor_results.append(av_vendor_name + ': ' + _vendor_result)
                        else:
                            av_selected_vendor_results.append(av_vendor_name + ': Not returned')

                result_line = ', '.join(av_selected_vendor_results)
                excerpt = score + ', ' + result_line

            logger.debug('Excerpt: %s' % excerpt)
            #print('%s, %s' % (file_hash, excerpt))
            if return_excerpt:
                self.cache.vt.add_excerpt(file_hash, excerpt)
                self.cache.vt.add_report(file_hash, vt_response)
                return excerpt
            else:
                self.cache.vt.add_excerpt(file_hash, excerpt)
                self.cache.vt.add_report(file_hash, vt_response)
                return vt_response

        else:
            logger.error('Unsupported file_hash: %s' % file_hash)
            return None

    def file_download(self, file_hash, out_file=None):

        downloaded_file = None
        out_file = None

        logger.debug('VT Download: %s' % file_hash)

        out_file = self.cache.vt.get_file_path(file_hash)

        if out_file:
            if isfile(out_file):
                logger.debug('CACHE -> file_path: %s' % out_file)
                print('%s, %s' % (file_hash, out_file))
                return out_file

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
                            return None
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

                                self.cache.file.add(file_hash)
                                self.cache.vt.set_file_path(file_hash, out_file)
                                print('%s, %s' % (file_hash, out_file))
                                return out_file

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
