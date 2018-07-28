"""
TO DO:
- Improve message handling (Implement regex)
- Think about smart url submisison ... if files are from same href etc.
- Fix proxy submission error (While testing i've got additional popup which appears, maybe that's why ...)
USE:

- plugin_manager.plugins['pp_bluecoat'].call("submit_url", ["..."])
- plugin_manager.plugins['pp_bluecoat'].call("query_url", ["..."])

"""

import logging
import random
import pytesseract  # pip install pytesseract
import simplejson
import calendar
import time
import os

from md.plugin import plugin
from PIL import Image  # pip install pillow


logger = logging.getLogger('dw')


class pp_bluecoat(plugin):

    author = 'wit0k'
    description = 'Submit/Query URLs to Symantec Bluecoat Proxy submission portal'
    config_file = 'plugins/pp_bluecoat.py.vd'
    plugin_type = 'PROXY'
    vendor_name = 'Symantec'
    required_params = ['debug_proxies', 'submission_comments', 'requests_debug']
    config_data = {}
    default_category = ''
    category_mappings = {
        'Computer/Information Security': '108', 'For Kids': '87', 'Alcohol': '23',
        'Entertainment': '20', 'Travel': '66',
        'Proxy Avoidance': '86', 'Potentially Unwanted Software': '102',
        'Charitable Organizations': '29', 'Weapons': '15',
        'Religion': '54', 'Health': '37', 'Sexual Expression': '93',
        'File Storage/Sharing': '56', 'Gambling': '11',
        'Software Downloads': '71', 'Email': '52', 'News/Media': '46',
        'Personals/Dating': '47', 'Adult/Mature Content': '1',
        'Newsgroups/Forums': '53', 'Piracy/Copyright Concerns': '118',
        'Mixed Content/Potentially Adult': '50', 'Shopping': '58',
        'Remote Access Tools': '57', 'Business/Economy': '21', 'Informational': '107',
        'Non-Viewable/Infrastructure': '96',
        'Society/Daily Living': '61', 'Peer-to-Peer (P2P)': '83', 'Media Sharing': '112',
        'Scam/Questionable/Illegal': '9',
        'Audio/Video Clips': '84', 'Humor/Jokes': '68', 'Spam': '101',
        'Office/Business Applications': '85',
        'Political/Social Advocacy': '36', 'Internet Connected Devices': '109',
        'Translation': '95',
        'Alternative Spirituality/Belief': '22', 'Extreme': '7', 'Online Meetings': '111',
        'Sex Education': '4',
        'Web Ads/Analytics': '88', 'Technology/Internet': '38', 'Tobacco': '24',
        'Art/Culture': '30', 'Phishing': '18',
        'Intimate Apparel/Swimsuit': '5', 'Vehicles': '67', 'Abortion': '16',
        'Web Hosting': '89', 'TV/Video Streams': '114',
        'Controlled Substances': '25', 'Malicious Outbound Data/Botnets': '44', 'Games': '33',
        'Auctions': '59',
        'Brokerage/Trading': '32', 'Military': '35', 'Hacking': '17',
        'E-Card/Invitations': '106', 'Social Networking': '55',
        'Chat (IM)/SMS': '51', 'Sports/Recreation': '65', 'Search Engines/Portals': '40',
        "I Don't Know": '90', 'Job Search/Careers': '45',
        'Reference': '49', 'Content Servers': '97', 'Nudity': '6',
        'Restaurants/Dining/Food': '64', 'Suspicious': '92',
        'Child Pornography': '26', 'Marijuana': '121', 'Placeholders': '98',
        'Radio/Audio Streams': '113', 'Government/Legal': '34',
        'Financial Services': '31', 'Malicious Sources/Malnets': '43', 'Real Estate': '60',
        'Pornography': '3', 'Dynamic DNS Host': '103',
        'Education': '27', 'Internet Telephony': '110', 'Personal Sites': '63',
        'Violence/Hate/Racism': '14'
    }

    def submit_url(self, urlobj, submission_comments=None, submitter_email=None, new_category=None):
        """ Submit new category to bluecoat """

        url = urlobj.url

        form_data = self.config_data.get('form_data', None)
        headers = self.config_data["headers"]

        if not new_category:
            new_category = self.config_data.get('default_category', None)

        if new_category not in self.category_mappings.keys():
            logger.error("New category: %s not implemented yet. Skip the submission")
            return None

        if not submission_comments:
            submission_comments = url

        if not submitter_email:
            submitter_email = form_data.get('email', None)

            if not submitter_email:
                logger.error("Unable to pull submitter e-mail addr. Exit Function")
                return None

        category_id = int(self.category_mappings[new_category])
        tracking_id = self.cache.proxy.get_tracking_id(url)

        """ Tracking ID not found, hence running get_category"""
        if not tracking_id:
            self.query_url(urlobj)
            tracking_id = self.cache.proxy.get_tracking_id(url)

        current_category_array = self.cache.proxy.get_category(url, self.vendor_name)
        tracking_id = tracking_id.get(self.vendor_name, None)

        if not tracking_id:
            logger.warning("Unable to obtain Tracking ID for: %s" % url)
            return None

        # This case shall not happen for now.
        if not submitter_email:
            email_checkbox = 'off'
            payload = {"comments": submission_comments, "email1": "", "email2": "", "partner": "bluecoatsg"
                , "referrer": "", "sendEmail": False, "trackid": tracking_id, "cat1": category_id, "cat2": None}
        else:
            email_checkbox = 'on'
            payload = {"comments": submission_comments, "email1": submitter_email, "email2": "", "partner": "bluecoatsg"
                , "referrer": "", "sendEmail": True, "trackid": tracking_id, "cat1": category_id, "cat2": None}

            # payload = 'referrer=bluecoatsg&suggestedcat=%s&suggestedcat2=&emailCheckBox=%s&email=%s&emailcc=&comments=&overwrite=no&trackid=%s' \
            # % (category_id, email_checkbox, self.submitter_email, str(tracking_id))

        try:
            logger.debug("Set proxy category: %s to: %s" % (new_category, url))

            """ Wait a random time """
            sleep_time = random.randint(1, 3)
            logger.debug("Thread Sleep for %d seconds" % sleep_time)
            time.sleep(sleep_time)

            headers['Referer'] = 'https://sitereview.bluecoat.com/lookup'
            r = self.con.post('https://sitereview.bluecoat.com/resource/submitCategorization',
                              headers=headers, json=payload)
        except Exception as msg:
            logger.error("Failed to submit new category. Error: %s" % str(msg))
            return None

        if not r.status_code == 200:
            logger.error("HTTP POST Failed -> https://sitereview.bluecoat.com/resource/submitCategorization")
            logger.error("Headers: %s" % headers)
            logger.error("Data: %s" % payload)
            return None

        response_dict = simplejson.loads(r.text)
        submission_message = response_dict.get("message", {})


        print("%s, %s, %s" % (url, submission_message, current_category_array))

        if (str(r.status_code) == '200' and submission_message[0:38] == 'Your page submission has been received'):
            logger.debug("Submission OK -> Vendor: %s | URL: %s" % (self.vendor_name, url))
            return True
        elif 'This Web page is already categorized as you believe it should be' in submission_message:
            logger.debug("Submission NOT REQUIRED -> Vendor: %s | URL: %s | Result: %s, %s" % (
            self.vendor_name, url, "This Web page is already categorized as you believe it should be", current_category_array))
            return True
        elif 'The Web page that you entered is currently under review' in submission_message:
            logger.debug("Submission NOT REQUIRED -> Vendor: %s | URL: %s | Result: %s, %s" % (
            self.vendor_name, url, "The Web page that you entered is currently under review", current_category_array))
            return True

        elif 'You have already submitted this Web page and it has been reviewed' in submission_message:
            logger.debug("Submission NOT REQUIRED -> Vendor: %s | URL: %s | Result: %s, %s" % (
                self.vendor_name, url, "You have already submitted this Web page and it has been reviewed", current_category_array))
            return True
        else:
            logger.debug("Submission FAILED -> Vendor: %s | URL: %s" % (self.vendor_name, url))
            return False

    def query_url(self, urlobj, params={}):

        """
            28.03.2018:

            IF the captcha is required:
            - Download the captcha and save it to the CWD as 'captcha.jpg'.  Then, use tesseract-ocr to solve
            the captcha and store the solution as a string to be submitted with our URL request.

            IF the captcha is not required, submit the url directly
        """

        url = urlobj.url
        url_host = urlobj.host

        current_category = None
        cached_category = None
        captcha_required = None
        tracking_id = None
        captcha_hint = None
        current_category_array = []

        logger.debug("Get proxy category of: %s" % url)

        """ Pre-create an entry in Cache if it doesn't exist yet """
        if not self.cache.url.exist(url) and not self.cache.url.exist(url_host):
            self.cache.url.add(urlobj)
            self.cache.url.add(urlobj, host_only=True)

            """ Case when new URL is not in cache yet, but its url_host is """
        elif not self.cache.url.exist(url) and self.cache.url.exist(url_host):
            self.cache.url.add(urlobj)

        tracking_id = self.cache.proxy.get_tracking_id(url)

        if params:
            force = params.get("force", False)
        else:
            force = False

        if url:
            logger.debug("Lookup the URL: %s" % url)

            """ Return cached category, if it exists  """
            logger.debug("Lookup URL tracking cache")

            cached_category = self.cache.proxy.get_category(url)
            if cached_category:
                logger.debug("CACHE -> Vendor: %s | Category: %s | URL: %s" % (self.vendor_name, cached_category, url))
                return cached_category

            """ Return cached category for urlhost (Less expensive, since category would likely be the same due to urlhost etc.) """
            if not force:
                cached_category = self.cache.proxy.get_category(url_host, self.vendor_name)
                if cached_category:
                    logger.debug(
                        "CACHE -> Vendor: %s | Category: %s | URLHost: %s" % (self.vendor_name, cached_category, url_host))

                    self.cache.proxy.set_category(url, self.vendor_name, cached_category)

                    return cached_category

            """ Check if captcha is required """
            logger.debug("Captcha requirement check ")
            headers = self.config_data.get('headers', None)
            headers['Referer'] = 'https://sitereview.bluecoat.com/'

            try:
                r = self.con.get('https://sitereview.bluecoat.com/resource/captcha-request', headers=headers)
                response_dict = simplejson.loads(r.text)
                captcha_required = response_dict.get("required", None)
            except Exception as msg:
                logger.error("Unable to send captcha request: %s" % 'https://sitereview.bluecoat.com/resource/captcha-request')

            """ Resolve captcha (Still the old method, but it works)"""
            if captcha_required:
                epoch_timestamp = str(calendar.timegm(time.gmtime()) * 1000)  # Epoch timestamp in ms.
                captcha_url = 'https://sitereview.bluecoat.com/rest/captcha.jpg?%s' % (
                    epoch_timestamp)  # Captcha URL
                local_filename = 'captcha.jpg'

                logger.debug("Captcha required: True -> Pull %s" % captcha_url)

                try:
                    r = self.con.get(captcha_url, headers=headers, stream=True)
                except Exception as msg:
                    logger.error("Failed to pull captcha image. Exit function")
                    return None

                logger.debug("Saving captcha file: %s" % local_filename)
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)

                if os.path.isfile('captcha.jpg'):
                    logger.debug("Parsing captcha file")
                    captcha_hint = pytesseract.image_to_string(Image.open('captcha.jpg'))
                    captcha_hint = "".join(captcha_hint.split())
                    logger.debug("Captcha hint: %s" % captcha_hint)
                    os.remove('captcha.jpg')  # Remove the downloaded captcha.
                    # OLD: check_status_payload = 'url=%s&captcha=%s' % (url, captcha)  # URL format to be used when Captcha is required.
                    check_status_payload = {"url": f'{url}', "captcha": f'{captcha_hint}'}
                else:
                    logger.error("Unable to locate captcha file")

            else:
                check_status_payload = {"url": f'{url}', "captcha": ''}

            """ Lookup url """
            try:
                """ Wait a random time """
                sleep_time = random.randint(1, 3)
                logger.debug("Thread Sleep for %d seconds" % sleep_time)
                time.sleep(sleep_time)

                logger.debug("Lookup proxy category: %s" % 'https://sitereview.bluecoat.com/lookup')
                headers['Referer'] = 'https://sitereview.bluecoat.com/lookup'
                r = self.con.post('https://sitereview.bluecoat.com/resource/lookup', headers=headers,
                                  json=check_status_payload)

                if r.status_code != 200:

                    if 'URL contains an invalid top-level domain (TLD)' in r.text:
                        logger.debug("Query Failed -> Vendor: %s | URL: %s | Result: %s" % (
                            self.vendor_name, url, "Unsupported: URL contains an invalid top-level domain (TLD)"))
                        return ["TLD not supported"]
                    else:
                        logger.error("HTTP POST Failed -> https://sitereview.bluecoat.com/resource/lookup")
                        logger.error("Headers: %s" % headers)
                        logger.error("Data: %s" % check_status_payload)
                        return None

                response_dict = simplejson.loads(r.text)
                tracking_id = response_dict.get("curTrackingId", {})

                self.cache.proxy.set_tracking_id(url, self.vendor_name, tracking_id)

                current_category = response_dict.get("categorization", [])

                for _category in current_category:
                    current_category_array.append(_category.get('name', ''))

                current_category_str = ",".join(current_category_array)

                """ Update URL cache """
                self.cache.proxy.set_category(url, self.vendor_name, current_category_array)
                self.cache.proxy.set_category(url_host, self.vendor_name, current_category_array)

            except Exception as msg:
                logger.debug("Unexpected error while URL lookup. Error: %s" % str(msg))
                return None

            return self.cache.url.get(url)


    """ Exposed plugin functions via plugin.call """
    plugin_functions = {"submit_url": submit_url,
                        "query_url": query_url
                        }
