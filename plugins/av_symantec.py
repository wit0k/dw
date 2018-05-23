"""
TO DO:
- Find a nice way to transfer debug_proxies variable and submission comments from dw

USE:

- plugin_manager.plugins['av_symantec'].call("submit_hash", ["5e913948be877c16b392390f8d21bbfd47b912720ac17664b6e1ea19ab9bff20"])
- plugin_manager.plugins['av_symantec'].call("submit_file", ["downloads/file.exe"])

"""
import logging
import os.path
import simplejson
import requests
import random
import time
import re

logger = logging.getLogger('dw')


class av_symantec(object):

    author = 'wit0k'
    description = 'Submits files or hashes to Symantec BCS submission portal'
    config_file = 'plugins/av-symantec.py.vd'
    plugin_type = 'AV'
    vendor_name = 'Symantec'
    required_params = ['debug_proxies', 'submission_comments', 'requests_debug']
    config_data = {}

    def __init__(self):

            self.debug_proxies = {
                'http': 'http://127.0.0.1:8080',
                'https': 'http://127.0.0.1:8080'
            }

            self.submission_comments = ""
            self.requests_debug = False

    def load_config(self):

        if self.config_file == "":
            logger.debug('This plugin does not require config file')
            return True

        if self.config_file:
            logger.debug('Attempt to load_config(%s)' % self.config_file)

            if os.path.isfile(self.config_file):

                with open(self.config_file, 'r') as file:
                    try:
                        vendor_config = simplejson.load(file)
                        if vendor_config:
                            logger.debug('Successfully loaded JSON data')
                            self.config_data = vendor_config
                            return True
                        else:
                            logger.error('Failed to load config data. Contact plugin developer ')
                            return False
                    except Exception as msg:
                        logger.error('Failed to load config data. Contact plugin developer. Error: %s ' % str(msg))
                        return False

            else:
                logger.error('Config file not found!')
                return False

    """ Helper functions """
    def get_tracking_id(self, response_text):

        pattern = re.compile(r'Number: ([0-9]{8,9}){1}<', re.I | re.MULTILINE)

        for match in pattern.finditer(response_text):
            tracking_id = match.groups()
            if tracking_id:

                return str(''.join(tracking_id))
            else:
                return None

    """ Functions exposed via Call """

    def submit_hash(self, hashes, submission_comments=None, requests_debug=None, debug_proxies=None):

        if hashes:
            url = ""
            submission_success_message = ""
            form_data = {}
            headers = {}

            """ Pull vendor specific POST data fields from config_data """
            form_data = self.config_data["form_data"]
            form_data['stype'] = (None, 'hash')
            headers = self.config_data["headers"]
            url = self.config_data["url"]
            submission_success_message = self.config_data["success_message"]

            for hash in hashes:
                logger.info("Submitting: %s to: %s" % (hash, url))

                form_data['hash'] = (None, hash)

                """ Adjust form_data according to script parameters """
                if self.submission_comments:
                    form_data["comments"] = self.submission_comments
                else:
                    form_data["comments"] = hash

                """ Submit the request """
                if self.requests_debug:
                    response = requests.post(url, files=form_data, proxies=self.debug_proxies, headers=headers,
                                             verify=False)
                else:
                    response = requests.post(url, files=form_data, headers=headers, verify=False)

                if not response.status_code == 200:
                    logger.error("[%s] - FAILED to submit: %s" % (response.status_code, url))
                else:
                    if submission_success_message in response.text:
                        tracking_id = self.get_tracking_id(response.text)

                        logger.info(
                            "Vendor: %s: Submission Success -> Hash: %s, %s" % (self.vendor_name, hash, tracking_id))
                        print("Vendor: %s: Submission Success -> Hash: %s, %s" % (self.vendor_name, hash, tracking_id))

                        """ Wait a random time """
                        sleep_time = random.randint(1, 3)
                        logger.debug("Thread Sleep for %d seconds" % sleep_time)
                        time.sleep(sleep_time)
                    else:
                        logger.info(
                            "Vendor: %s: Submission Failure: Hash: %s\n Message: \n %s" % (
                                self.vendor_name, hash, response.text))
                        print("Vendor: %s: Submission Failure: Hash: %s\n Message: \n %s" % (
                            self.vendor_name, hash, response.text))

        else:
            logger.warning("Nothing to submit!")

    def submit_file(self, files, submission_comments=None, requests_debug=None, debug_proxies=None):

        if files:
            url = ""
            submission_success_message = ""
            form_data = {}
            headers = {}

            """ Pull vendor specific POST data fields """
            form_data = self.config_data["form_data"]
            form_data['stype'] = (None, 'upfile')
            headers = self.config_data["headers"]
            url = self.config_data["url"]
            submission_success_message = self.config_data["success_message"]

            for file in files:
                if os.path.isfile(file):

                    logger.info("Submitting: %s to: %s" % (file, url))
                    file_name = os.path.basename(file)

                    """ Adjust form_data according to script parameters """
                    if self.submission_comments:
                        form_data["comments"] = self.submission_comments
                    else:
                        form_data["comments"] = file_name

                    """ Load the file content """
                    with open(file, 'rb') as file_obj:
                        file_content = file_obj.read()
                        form_data["upfile"] = (file_name, file_content, 'application/x-zip-compressed')
                        file_obj.close()

                    """ Submit the request """
                    if self.requests_debug:
                        response = requests.post(url, files=form_data, proxies=self.debug_proxies, headers=headers,
                                                 verify=False)
                    else:
                        response = requests.post(url, files=form_data, headers=headers, verify=False)

                    if not response.status_code == 200:
                        logger.error("[%s] - FAILED to submit: %s" % (response.status_code, url))
                    else:
                        if submission_success_message in response.text:
                            tracking_id = self.get_tracking_id(response.text)
                            logger.info(
                                "Vendor: %s: Submission Success -> File: %s, %s" % (
                                    self.vendor_name, file, tracking_id))
                            print("Vendor: %s: Submission Success -> File: %s, %s" % (
                                self.vendor_name, file, tracking_id))

                            """ Wait a random time """
                            sleep_time = random.randint(1, 3)
                            logger.debug("Thread Sleep for %d seconds" % sleep_time)
                            time.sleep(sleep_time)
                        else:
                            logger.info(
                                "Vendor: %s: Submission Failure: File: %s\n Message: \n %s" % (
                                    self.vendor_name, file, response.text))
                            print("Vendor: %s: Submission Failure: File: %s\n Message: \n %s" % (
                                self.vendor_name, file, response.text))

        else:
            logger.warning("Nothing to submit!")

    def call(self, function_name, params=()):

        if function_name in self.plugin_functions.keys():
            self.plugin_functions[function_name](self,  *params)


    plugin_functions = {"submit_file": submit_file,
                        "submit_hash": submit_hash
                        }
