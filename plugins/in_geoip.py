"""
TO DO:
- ...
"""

import logging
from md.plugin import plugin

logger = logging.getLogger('dw')

class in_geoip(plugin):

    author = 'wit0k'
    description = 'Handle GeoLocation API'
    config_file = 'plugins/in_geoip.py.vd'
    plugin_type = 'INTEL'
    vendor_name = 'ipinfo.io'
    config_data = {}

    def _is_supported_input(self, input_data):

        if self.regex.is_ip_v4(input_data) or self.regex.is_a_domain(input_data):
            return True
        else:
            return False

    def get_geolocation(self, input_data, url=None):

        ipinfo_response = None
        logger.debug('GeoIP Report: %s' % input_data)

        if not self._is_supported_input(input_data):
            logger.error('Unsupported input format: "%s"' % input_data)
            return None

        payload_url = ('https://ipinfo.io/' + input_data + '/json')
        payload = {'token': self.config_data.get('api_key', None)}
        response = self.con.get(payload_url, params=payload)

        if response.status_code == 200:
            ipinfo_response = response.json()

            if ipinfo_response:
                row = []
                order = ['ip', 'country', 'city', 'region', 'org', 'hostname', 'loc']

                for key in order:
                    row.append(key + ": " + ipinfo_response.get(key, ''))

                logger.debug(", ".join(row) + ", " + url)
                print(", ".join(row) + ", " + url)
        else:
            logger.error('HTTP %s - Unable to access GeoLoaction API -> %s' % (response.status_code, payload_url))

        return ipinfo_response


    """ Exposed plugin functions via plugin.call """
    plugin_functions = {"get_geolocation": get_geolocation
    }
