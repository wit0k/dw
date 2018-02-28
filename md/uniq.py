import requests
import logging
import hashlib
import logging

logger = logging.getLogger('dw')

class uniq():

    def __init__(self):
        pass

    def get_unique_entries(self, entries):

        unique_list = []
        old_count = len(entries)

        for item in entries:
            if item not in unique_list:
                unique_list.append(item)

        logger.info("Deduplication: %d -> %d" % (old_count, len(unique_list)))

        return unique_list

    def get_unique_files(self, files):

        unique_files = []
        file_list = {}
        old_count = len(files)

        for file in files:

            """ Log downloaded file and its hash """
            hash_obj = hashlib.sha256()
            with open(file, "rb") as _file:
                for chunk in iter(lambda: _file.read(4096), b""):
                    hash_obj.update(chunk)

                sha256 = hash_obj.hexdigest()

                if sha256 not in file_list.keys():
                    file_list[sha256] = file

        for value in file_list.values():
            unique_files.append(value)

        logger.info("Deduplication: %d -> %d" % (old_count, len(unique_files)))


        return unique_files
