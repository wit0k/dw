import time
import logging

logger = logging.getLogger('dw')

""" Class variables """
URL_CACHE = {
    '<url>': {
            'time_created': '',
            'urlobj': None,
            'metadata': {
                'mime_type': '',
            },
            'proxy': {
                'category': {'<vendor_name>': ('category1', 'category2')},
                'new_category': {'<vendor_name>': ('category1', 'category2')},
                'tracking_id': {'<vendor_name>': ('category1', 'category2')}
            },
            'vt': {
                'result': {'<vendor_name>': ('category1', 'category2')}
            }
    }
}


FILE_CACHE = {
    'sha256': {}
}

def get_urlobj(surl):

    if surl:
        return URL_CACHE.get(surl, None).get("urlobj", None)
    else:
        return None

class proxy(object):

    def add(self, urlobj, host_only=False):

        if urlobj:
            if host_only:
                key = urlobj.host
            else:
                key = urlobj.url

            logger.debug("CACHE - PROXY - Create new entry: %s" % key)
            time_created = time.strftime("%Y-%m-%d %H:%M:%S")

            URL_CACHE[key] = {
                'urlobj': urlobj,
                'time_created': time_created,
                'proxy': {
                    'category': {},
                    'tracking_id': {}
                },
                'vt': {
                    'result': {}
                }
            }

    def exist(self, surl):

        if surl in URL_CACHE.keys():
            return True
        else:
            return False

    def get(self, surl):

        cache_entry = URL_CACHE.get(surl, None)
        if cache_entry:
            return cache_entry

    def _set_property_value(self, surl, item_name, property_name, vendor_name, value):

        if value:
            if surl in URL_CACHE.keys():
                entry = URL_CACHE[surl][item_name].get(property_name, {})

                if len(entry) > 0:
                    if vendor_name in entry.keys():
                        # Update existing value
                        entry[vendor_name] = value
                    else:
                        # Add new value
                        entry[vendor_name] = value
                else:
                    # Add new value
                    entry[vendor_name] = value

    def get_category(self, surl, vendor_name=None):

        cache_entry = URL_CACHE.get(surl, None)
        if cache_entry:
            if vendor_name:
                category_entry = cache_entry.get('proxy', {}).get('category', None)
                if category_entry:
                    return category_entry.get(vendor_name, None)
            else:
                return cache_entry.get('proxy', {}).get('category', None)
        else:
            return None

    def get_tracking_id(self, surl):

        cache_entry = URL_CACHE.get(surl, None)
        if cache_entry:
            return cache_entry.get('proxy', {}).get('tracking_id', None)
        else:
            return None

    def set_category(self, surl, vendor_name, category_name):

        logger.debug("CACHE - PROXY - Set category: %s, %s" % (category_name, surl))
        self._set_property_value(surl, "proxy", "category", vendor_name, category_name)

    def set_new_category(self, surl, vendor_name, category_name):

        logger.debug("CACHE - PROXY - Set category: %s, %s" % (category_name, surl))
        self._set_property_value(surl, "proxy", "new_category", vendor_name, category_name)

    def set_tracking_id(self, surl, vendor_name, tracking_id):

        logger.debug("CACHE - PROXY - Set Tracking ID: %s, %s" % (tracking_id, surl))
        self._set_property_value(surl, "proxy", "tracking_id", vendor_name, tracking_id)


proxy = proxy()



