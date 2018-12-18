"""
TO DO:
- ...
"""

import logging
from md.plugin import plugin
from time import sleep
import md.hasher as hasher

import random
logger = logging.getLogger('dw')

class la_labapi(plugin):

    author = 'wit0k'
    description = 'Handle the interactions with LabAPI'
    config_file = 'plugins/la_labapi.py.vd'
    plugin_type = 'LABAPI'
    vendor_name = 'LabAPI'
    config_data = {}

    """ Helper functions """

    def _is_supported_hash(self, file_hash):

        if hasher.get_hash_type(file_hash) in ['sha256', 'md5', 'sha1']:
            return True
        else:
            return False

    def labapi_file_download(self, file_hashes, download_folder):

        for hash in file_hashes:
            self._file_download(hash, download_folder)



    def _file_download(self, file_hash, download_folder):

        out_file = None
        logger.debug('Download: %s' % file_hash)
        random_time = random.randint(5, 10)
        logger.debug('Waiting random time: %s' % random_time)
        sleep(random_time)

        if not self._is_supported_hash(file_hash):
            logger.error('Unsupported input format: "%s"' % file_hash)
            return None

        api_key = self.config_data.get("api_key", None)
        server_addr = self.config_data.get("server_addr", None)
        server_port = self.config_data.get("server_port", None)

        if not api_key or not server_addr or not server_port:
            logger.error('Unable to load all required data from .vd file')
            return None

        url = f'http://{server_addr}:{server_port}/file/download/{file_hash}'
        logger.debug('%s' % url)

        parameters = {
            "token": api_key}

        headers = {
            'Cache-Control': "no-cache",
        }

        self.con.allow_redirects = True
        response = self.con.get(url, headers=headers, params=parameters, allow_redirects=True)

        if response is not None:

            test = response.content

            if response.status_code == 200:
                logger.debug('Hash: %s - Found on LabAPI' % file_hash)

                downloaded_file = response.content

                out_file = download_folder + file_hash
                with open(out_file, 'wb') as file:
                    file.write(downloaded_file )
                logger.error('%s - Found on LabAPI' % file_hash)
            else:
                logger.error('%s - Not found on LabAPI!' % file_hash)
        else:
            logger.error('Unable to access the URL: %s' % url)

        return out_file

    """ Exposed plugin functions via plugin.call """
    plugin_functions = {
        "labapi_file_download": labapi_file_download
    }
