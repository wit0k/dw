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

        """
                    28.03.2018:

                    IF the captcha is required:
                     - Download the captcha and save it to the CWD as 'captcha.jpg'.  Then, use tesseract-ocr to solve
                       the captcha and store the solution as a string to be submitted with our URL request.

                    IF the captcha is not required, submit the url directly
                    """
        if url:
            logger.debug("Lookup the URL: %s" % url)

            url_obj = urlparse(url, 'http')
            url_host = url_obj.hostname

            """ Return cached category """
            logger.debug("Lookup URL tracking cache")
            if url in self.URL_TRACKING.keys():
                logger.debug("CACHE -> Vendor: %s | URL: %s" % (self.name, url))
                return self.URL_TRACKING[url]["category"]

            if not force:
                if url_host in self.URL_TRACKING.keys():
                    logger.debug("CACHE -> Vendor: %s | URL: %s" % (self.name, url))
                    return self.URL_TRACKING[url_host]["category"]

            current_categorization = None
            tracking_id = None

            """ Check if captcha is required """
            logger.debug("Checking if captcha is required ")
            self.headers['Referer'] = 'https://sitereview.bluecoat.com/'
            r = self.con.get('https://sitereview.bluecoat.com/resource/captcha-request', headers=self.headers)

            response_dict = simplejson.loads(r.text)
            captcha_required = response_dict.get("required", None)

            """ Resolve captcha (Still the old method, but it works)"""
            if captcha_required:
                logger.debug("Captcha check is required. Pulling the captcha from the server")
                epoch_timestamp = str(calendar.timegm(time.gmtime()) * 1000)  # Epoch timestamp in ms.
                captcha_url = 'https://sitereview.bluecoat.com/rest/captcha.jpg?%s' % (
                    epoch_timestamp)  # Captcha URL
                local_filename = 'captcha.jpg'

                try:
                    r = self.con.get(captcha_url, headers=self.headers, stream=True)
                except Exception as msg:
                    return ("N/A")

                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)

                if os.path.isfile('captcha.jpg'):
                    captcha = pytesseract.image_to_string(Image.open('captcha.jpg'))
                    captcha = "".join(captcha.split())
                    os.remove('captcha.jpg')  # Remove the downloaded captcha.
                    # OLD: check_status_payload = 'url=%s&captcha=%s' % (url, captcha)  # URL format to be used when Captcha is required.
                    check_status_payload = {"url": f'{url}', "captcha": f'{captcha}'}

            else:
                check_status_payload = {"url": f'{url}', "captcha": ''}

            """ Lookup url """
            try:
                """ Wait a random time """
                sleep_time = random.randint(1, 3)
                logger.debug("Thread Sleep for %d seconds" % sleep_time)
                time.sleep(sleep_time)

                self.headers['Referer'] = 'https://sitereview.bluecoat.com/lookup'
                r = self.con.post('https://sitereview.bluecoat.com/resource/lookup', headers=self.headers,
                                  json=check_status_payload)

                if r.status_code != 200:
                    logger.error("HTTP POST Failed -> https://sitereview.bluecoat.com/resource/lookup")
                    logger.error("Headers: %s" % self.headers)
                    logger.error("Data: %s" % check_status_payload)
                    return ("ERROR")

                response_dict = simplejson.loads(r.text)

                tracking_id = response_dict.get("curTrackingId", {})
                current_categorization = response_dict.get("categorization", [])

                category = []
                for _category in current_categorization:
                    category.append(_category.get('name', ""))

                category = ",".join(category)

                """ Update URL cache """
                self.URL_TRACKING[url] = {"tracking_id": tracking_id, "category": category}
                self.URL_TRACKING[url_host] = {"tracking_id": tracking_id, "category": category}

            except Exception as msg:
                return ("N/A")

            logger.debug("QUERY -> Vendor: %s | Category: %s | URL: %s" % (self.name, category, url))
            return (category)

    plugin_functions = {"submit_url": submit_url,
                        "query_url": query_url
                        }
