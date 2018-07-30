"""
TO DO:
- Finish get_hashes()

"""
import hashlib
import zlib
import os
import re
import logging

logger = logging.getLogger('dw')

SupportedHashes = ['md5', 'sha1', 'sha256', 'sha512', 'crc32']

def get_hash_type(hash_string):

    hash_string = hash_string.lower()

    if re.match(r'^[a-f0-9]{32}$', hash_string):
        return 'md5'
    elif re.match(r'^[a-f0-9]{64}$', hash_string):
        return 'sha256'
    elif re.match(r'^[a-f0-9]{40}$', hash_string):
        return 'sha1'
    else:
        return 'unhandled'

def get_hash(input_data, hash_type):

    buffer_type = None
    buffer = None
    hash_obj = None

    if hash_type in SupportedHashes:

        try:
            if os.path.isfile(input_data):
                buffer_type = 'file'
                with open(input_data, "rb") as file:
                    buffer = file.read()

        except Exception as msg:

            buffer_type = 'buffer'
            buffer = input_data

        if hash_type == 'md5':
            hash_obj = hashlib.md5()
        elif hash_type == 'sha256':
            hash_obj = hashlib.sha256()
        elif hash_type == 'sha1':
            hash_obj = hashlib.sha1()
        else:
            logger.error('Hash routine, not implemented yet')

        if hash_obj:
            hash_obj.update(buffer)
            return hash_obj.hexdigest()
        else:
            return None
    else:
        return None

def get_hashes(input_data):

    file_hashes = {}

    if os.path.isfile(input_data):
        with open(input_data, "rb") as file:
            buffer = file.read()
    else:
        buffer = input_data

    for hash_type in SupportedHashes:

        if hash_type == 'crc32':
            file_hashes[hash_type] = zlib.crc32(buffer)
        else:
            file_hashes[hash_type] = hashlib.new(hash_type)
            file_hashes[hash_type].update(buffer)

            #print ("%s: %s" % (hash, OutputHash[hash].hexdigest()))

    return file_hashes

# CRC32
# SSdeep