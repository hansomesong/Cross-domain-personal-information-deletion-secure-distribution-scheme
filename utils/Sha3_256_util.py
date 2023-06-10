from Crypto.Hash import SHA3_256
import  hashlib
from binascii import unhexlify,hexlify
class Sha3_256_util():
    @staticmethod
    def getHash(data):
        # return 256-bit Sha3-256 CODE
        sha256 = hashlib.sha3_256()

        if isinstance(data,str):
            sha256.update(data.encode("UTF-8"))
        else:
            sha256.update(data)
        # return 32-length bytes
        return  sha256.hexdigest()

if __name__ == '__main__':
    sha256 = Sha3_256_util()
    hash = sha256.getHash('Hello World!')
    print(hash)