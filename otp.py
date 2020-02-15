from base64 import b32decode, b32encode
from hashlib import (
        sha1, sha256, sha512, md5)
from struct import pack
from time import time
import hmac


class BaseOtp:
    @staticmethod
    def str2key(key):
        miss_padding = 8 - (len(key) % 8)
        if (miss_padding == 0) or (miss_padding == 8):
            bkey = key
        else:
            bkey = key + ("=" * miss_padding)
        return b32decode(bkey)

    def __init__(self, key=None, factor=0, digit=6, digest=sha1):
        """
        """
        self.key = BaseOtp.str2key(key)
        self.factor = int(factor)
        self.digit = int(digit)

        if digest == "sha1":
            self.digest = sha1
        elif digest == "sha256":
            self.digest = sha256
        elif digest == "sha512":
            self.digest = sha512
        elif digest == "md5":
            self.digest = md5
        else:
            self.digest = digest

    def _hmac(self):
        return hmac.new(self.key, pack('>Q', self.factor), self.digest).digest()

    def _truncate(self):
        hmac_result = self._hmac()

        offset = (hmac_result[19]) & 0xf
        bin_code = (((hmac_result[offset] & 0x7f) << 24) |
                    ((hmac_result[offset + 1] & 0xff) << 16) |
                    ((hmac_result[offset + 2] & 0xff) << 8) |
                    ((hmac_result[offset + 3] & 0xff)))
        otp_code = bin_code % (10 ** self.digit)

        return format(otp_code, '>0' + str(self.digit) + 'd')


class Hotp(BaseOtp):
    def __init__(self, key=None, factor=0, digit=6, digest=sha1):
        super().__init__(key, factor, digit, digest)

    @property
    def code(self):
        value = self._truncate()
        self.factor += 1
        return value

class Totp(BaseOtp):
    def __init__(self, key=None, factor=0, digit=6, digest=sha1, time_step=30, T0=0):
        super().__init__(key, factor, digit, digest)
        self.time_step = time_step
        self.T0 = T0

    def _T2factor(self):
        self.factor = int((time() - self.T0) / self.time_step)

    @property
    def code(self):
        self._T2factor()
        value = self._truncate()
        return value

__all__ = ["Hotp", "Totp"]
