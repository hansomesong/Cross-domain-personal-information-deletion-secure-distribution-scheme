from binascii import unhexlify
from time import time
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
# from Sha3_256_util import Sha3_256_util


class CMAC_util():
    @staticmethod
    def getHash(data, key):
        # return 128-bit CMAC CODE(now return is hex 32)
        c = CMAC.new(key, data, ciphermod=AES)
        return c.hexdigest()


if __name__ == '__main__':
    # cmac = CMAC_util()
    # hash = cmac.getHash('我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊我想你啊',123456)
    # print(hash)
    sha256 = Sha3_256_util()
    hash = sha256.getHash('Hello World')

    secret = unhexlify('31323334353637383132333435363738')
    print(secret)
    sessionId = unhexlify('11')
    print(sessionId)
    timeStamp = unhexlify(str(int(time())))
    metaData = hash + sessionId + timeStamp
    print(metaData)
    c = CMAC.new(secret, metaData, ciphermod=AES)
    print(c.hexdigest())
