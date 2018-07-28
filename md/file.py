import logging

from os.path import isfile
from md.hasher import get_hash_type, get_hash

logger = logging.getLogger('dw')


class file(object):

    def __init__(self, file_hash):

        self.md5 = None
        self.sha256 = None
        self.sha1 = None
        self.file_path = None

        if not get_hash_type(file_hash) == 'sha256':
            logger.error('Unable to initialize file object. The hash: %s is not sha256' % file_hash)
        else:
            self.sha256 = file_hash

    def __init__(self, file_path):

        self.md5 = None
        self.sha256 = None
        self.sha1 = None
        self.file_path = None

        if not isfile(file_path):
            logger.error('Unable to initialize file object. The file: %s is not accessible' % file_path)
        else:
            self.sha256 = get_hash(file_path,'sha256')
            self.file_path = file_path
