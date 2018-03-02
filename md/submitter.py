# The code partially taken from: https://raw.githubusercontent.com/rwhalen/bluecoat-sitereview/master/src/bluecoat.py

import requests
import logging

from PIL import Image  # pip install pillow
from urllib.parse import urlparse

import pytesseract  # pip install pytesseract
import simplejson
import calendar
import time
import os


logger = logging.getLogger('dw')


class submitter(object):

    vendor_types = ["PROXY"]

    def __init__(self):
        pass

    def load_vendors(self, vendor_type, vendor_names=[], params={}):

        if vendor_type and vendor_names:
            """ Make sure that vendor type is supported """
            if vendor_type.upper() not in self.vendor_types:
                logger.error("Unsupported vendor type: %s" % vendor_type)
                return False

            """ Load all specified proxy vendors """
            if vendor_type.upper() == "PROXY":
                _proxy_vendors = {}
                for proxy_vendor in vendor_names:
                    proxy_vendor = proxy_vendor.upper()
                    if proxy_vendor in proxy.SUPPORTED_VENDORS.keys():
                        """ Init the vendor object """
                        _proxy_vendors[proxy_vendor] = proxy.SUPPORTED_VENDORS[proxy_vendor](params)

                return _proxy_vendors
        else:
            return None

class proxy(submitter):

    class bluecoat():

        name = "bluecoat"
        POST_DATA = {
            "headers": {
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36',
                'Origin': 'https://sitereview.bluecoat.com',
                'Referer': 'https://sitereview.bluecoat.com/sitereview.jsp'
            }
        }

        category_mappings = {'Computer/Information Security': '108', 'For Kids': '87', 'Alcohol': '23',
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
                             'Violence/Hate/Racism': '14'}

        URL_TRACKING = {
            "url": {"tracking_id": None, "category": None}
        }

        def __init__(self, params={}):

            self.headers = self.POST_DATA["headers"]
            self.con = requests.session()
            self.submitter_email = ""

            if "submitter_email" in params.keys():
                self.submitter_email = params["submitter_email"]


        def lookup_url_tracking_table(self, url, field_name):

            if url in self.URL_TRACKING.keys():
                try:
                    return self.URL_TRACKING[url][field_name]
                except ValueError:
                    logger.warning("The value: '%s' not found in: URL_TRACKING table")
                    return None
            else:
                return None

        def get_category(self, url):

            '''
            Download the captcha and save it to the CWD as 'captcha.jpg'.  Then, use tesseract-ocr to solve
            the captcha and store the solution as a string to be submitted with our URL request.
            '''

            """ Return cached category """
            if url in self.URL_TRACKING.keys():
                logger.debug("CACHE -> Vendor: %s | URL: %s" % (self.name, url))
                return self.URL_TRACKING[url]["category"]

            current_categorization = None
            tracking_id = None
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
                check_status_payload = 'url=%s&captcha=%s' % (
                url, captcha)  # URL format to be used when Captcha is required.

                try:
                    r = self.con.post('https://sitereview.bluecoat.com/rest/categorization', headers=self.headers,
                                      data=check_status_payload)  # Generate HTTP POST to check current category status

                    response_dict = simplejson.loads(r.text)

                    tracking_id = response_dict.get("curtrackingid", {})
                    current_categorization = response_dict.get("categorization", {}).split(">")[1].split("<")[0]

                    url_obj = urlparse(url, 'http')
                    url_host = url_obj.hostname

                    """ Update URL cache """
                    self.URL_TRACKING[url] = {"tracking_id": tracking_id, "category": current_categorization}
                    self.URL_TRACKING[url_host] = {"tracking_id": tracking_id, "category": current_categorization}

                except Exception as msg:
                    return ("N/A")

            logger.debug("QUERY -> Vendor: %s | Category: %s | URL: %s" % (self.name, current_categorization, url))
            return (current_categorization)

        def submit_category(self, new_category, url):

            if new_category not in self.category_mappings.keys():
                logger.error("New category: %s not implemented yet. Skip the submission")
                return False

            category_id = self.category_mappings[new_category]
            tracking_id = self.lookup_url_tracking_table(url, "tracking_id")

            """ Tracking ID not found, hence running get_category"""
            if not tracking_id:
                self.get_category(url)
                tracking_id = self.lookup_url_tracking_table(url, "tracking_id")

            if not tracking_id:
                logger.warning("Unable to obtain Tracking ID for: %s" % url)
                return None

            if self.submitter_email == '':
                email_checkbox = 'off'
            else:
                email_checkbox = 'on'

            payload = 'referrer=bluecoatsg&suggestedcat=%s&suggestedcat2=&emailCheckBox=%s&email=%s&emailcc=&comments=&overwrite=no&trackid=%s' \
                      % (category_id, email_checkbox, self.submitter_email, str(tracking_id))

            try:
                logger.debug("Submitting new category: '%s' for: %s" % (new_category, url))
                r = self.con.post('https://sitereview.bluecoat.com/rest/submitCategorization',
                                  headers=self.headers, data=payload)
            except Exception as msg:
                return ("N/A")

            response_dict = simplejson.loads(r.text)
            submission_message = response_dict.get("message", {})

            print("%s, %s" % (url, submission_message))

            if (str(r.status_code) == '200' and submission_message[0:38] == 'Your page submission has been received'):
                logger.debug("Submission OK -> Vendor: %s | URL: %s" % (self.name, url))
                return True
            elif 'This Web page is already categorized as you believe it should be' in submission_message:
                logger.debug("Submission NOT REQUIRED -> Vendor: %s | URL: %s | Result: %s" % (self.name, url, "This Web page is already categorized as you believe it should be"))
                return True
            elif 'The Web page that you entered is currently under review' in submission_message:
                logger.debug("Submission NOT REQUIRED -> Vendor: %s | URL: %s | Result: %s" % (self.name, url, "The Web page that you entered is currently under review"))
                return True
            else:
                test = ""
                logger.debug("Submission FAILED -> Vendor: %s | URL: %s" % (self.name, url))
                return False

    """ Proxy vendor keys must be in capital letters """
    SUPPORTED_VENDORS = {"BLUECOAT": bluecoat}


