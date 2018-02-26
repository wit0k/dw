# The code partially taken from: https://raw.githubusercontent.com/rwhalen/bluecoat-sitereview/master/src/bluecoat.py

import requests
import logging

from PIL import Image  # pip install pillow
import pytesseract  # pip install pytesseract
import simplejson
import calendar
import time
import os

logger = logging.getLogger('dw')

class submitter(object):
    pass


class proxy(submitter):

    POST_DATA = {
        "bluecoat": {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36',
            'Origin': 'https://sitereview.bluecoat.com',
            'Referrer': 'https://sitereview.bluecoat.com/sitereview.jsp'
        }
    }

    def __init__(self, proxy_vendor):

        if proxy_vendor in self.POST_DATA.keys():
            self.con_post_data = self.POST_DATA[proxy_vendor]
            self.con = requests.session()
        else:
            logger.error("Vendor: %s - not supported yet" % proxy_vendor)


    def is_valid_url(self):
        import re

        regex = re.compile(
            # r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if regex.search(self.url):
            return True
        else:
            return False

    def get_category(self, url):


        '''
        Download the captcha and save it to the CWD as 'captcha.jpg'.  Then, use tesseract-ocr to solve
        the captcha and store the solution as a string to be submitted with our URL request.
        '''
        self.url = url

        epoch_timestamp = str(calendar.timegm(time.gmtime()) * 1000)  # Epoch timestamp in ms.
        captcha_url = 'https://sitereview.bluecoat.com/rest/captcha.jpg?%s' % (
            epoch_timestamp)  # Captcha URL
        local_filename = 'captcha.jpg'

        r = self.con.get(captcha_url, headers=self.con_post_data, stream=True)

        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        captcha = pytesseract.image_to_string(Image.open('captcha.jpg'))
        captcha = "".join(captcha.split())

        os.remove('captcha.jpg')  # Remove the downloaded captcha.

        check_status_payload = 'url=%s&captcha=%s' % (
            self.url, captcha)  # URL format to be used when Captcha is required.
        r = self.con.post('https://sitereview.bluecoat.com/rest/categorization', headers=self.con_post_data,
                        data=check_status_payload)  # Generate HTTP POST to check current category status
        response_dict = simplejson.loads(r.text)

        self.tracking_id = response_dict.get("curtrackingid", {})
        current_categorization = response_dict.get("categorization", {}).split(">")[1].split("<")[0]

        return (current_categorization)

    def submit_category(self, Category, Email=''):
        import simplejson

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
        '''
        with open('categories.conf', 'r') as f:
            for d in csv.DictReader(f):
                category_mappings[d['Category']]=d['ID']
        '''

        new_category = category_mappings[Category]

        if Email == '':
            email_checkbox = 'off'
        else:
            email_checkbox = 'on'

        payload = 'referrer=bluecoatsg&suggestedcat=%s&suggestedcat2=&emailCheckBox=%s&email=%s&emailcc=&comments=&overwrite=no&trackid=%s' \
                  % (new_category, email_checkbox, Email, self.tracking_id)

        r = self.con.post('https://sitereview.bluecoat.com/rest/submitCategorization', headers=self.con_post_data,
                        data=payload)
        response_dict = simplejson.loads(r.text)
        submission_message = response_dict.get("message", {})

        if (str(r.status_code) == '200' and submission_message[0:38] == 'Your page submission has been received'):
            return True

        else:
            return False