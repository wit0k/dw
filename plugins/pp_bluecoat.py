"""
TO DO:
- Find a nice way to transfer debug_proxies variable and submission comments from dw

USE:

- plugin_manager.plugins['pp_bluecoat'].call("submit_url", ["..."])
- plugin_manager.plugins['pp_bluecoat'].call("query_url", ["..."])

"""
import logging
from md.plugin import plugin

logger = logging.getLogger('dw')


class pp_bluecoat(plugin):

    author = 'wit0k'
    description = 'Submit/Query URLs to Symantec Bluecoat Proxy submission portal'
    config_file = 'plugins/pp_bluecoat.py.vd'
    plugin_type = 'PROXY'
    vendor_name = 'Symantec'
    required_params = ['debug_proxies', 'submission_comments', 'requests_debug']
    config_data = {}

    def submit_url(self):
        pass

    def query_url(self):
        pass

    plugin_functions = {"submit_url": submit_url,
                        "query_url": query_url
                        }
