__author__ = 'daslanian'
import os
import binascii
import datetime


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.

    For the sake of simplicity, this function executes in constant time only when the two strings have the same length.
    It short-circuits when they have different lengths.

    Python 2.7.7 and newer have hmac.compare_digest(), but using this instead for older versions.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


def from_utc(utc_time, fmt="%Y-%m-%dT%H:%M:%SZ"):
    """
    Convert UTC time string to time.struct_time
    """
    return datetime.datetime.strptime(utc_time, fmt)


def generate_key(key_size_bytes):
    return binascii.hexlify(os.urandom(key_size_bytes))
