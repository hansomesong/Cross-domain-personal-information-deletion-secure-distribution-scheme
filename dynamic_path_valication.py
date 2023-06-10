from protocol.utils.Sha3_256_util import Sha3_256_util
from protocol.utils.CMAC_util import CMAC_util
from time import time
from binascii import unhexlify,hexlify
import random


class ValidationProtocol():
    def __init__(self):
        # SrcInitialization build
        self.srcR = ''
        self.dstR = ''
        self.concealment = ''
        # 真正的数据payload
        self.payload = ''
        self.metadata = ''
        # payload信息的头部
        self.dataHash = '0'
        self.sessionId = '0'
        self.timestamp = '0'
        # Construction build
        self.hiddenSample = ''
        self.hopCount = '0'
        # 128-bit
        self.validationProof = ''
        # 上一个安全的Router
        self.prevR = ''

    def SrcInitialization(self, securityKey, srcR, dstR, payload, sessionId):
        self.init_PacketMeta(payload, sessionId)
        self.srcR = srcR
        self.dstR = dstR
        self.payload = payload
        # 计算dataHash
        self.dataHash = Sha3_256_util.getHash(payload)
        # 计算sessionid
        self.sessionId = str(sessionId)
        # 生成timestamp
        self.timestamp = str(int(time()))
        # 生成metadata，赋值到数据包packetMeta字段
        # 32bytes ++ 5bytes
        self.metadata = unhexlify(self.dataHash) + unhexlify(oddLenToEven(self.sessionId)) + unhexlify(oddLenToEven(self.timestamp))
        self.metadata = str(hexlify(self.metadata),'UTF-8')
        # 生成concealment,赋值到数据包concealment字段
        self.concealment = CMAC_util.getHash(unhexlify(self.metadata), unhexlify(securityKey))

    def Construction(self, securityKey, curR):
        # 更新hopCount字段
        self.hopCount = str(int(self.hopCount) + 1)
        # 更新hiddenSample字段
        dataHash = Sha3_256_util.getHash(self.payload)
        self.hiddenSample = Sha3_256_util.getHash(unhexlify(oddLenToEven('1')) + unhexlify(dataHash) + unhexlify(oddLenToEven(self.hopCount)) + unhexlify(securityKey))
        # 更新128-bit ValidationProof
        validationData = unhexlify(self.metadata) + unhexlify(oddLenToEven(self.hopCount)) + unhexlify(self.concealment)
        self.validationProof = CMAC_util.getHash(validationData,  unhexlify(securityKey))
        # 更新prevR字段
        self.prevR = curR

    def Verification(self, securityKey) -> bool:
        keep = True
        # 计算不采样时的hiddenSample`
        hiddenSample = Sha3_256_util.getHash(
         unhexlify(oddLenToEven('0')) + unhexlify(oddLenToEven(self.hopCount)) + unhexlify(self.dataHash) + unhexlify(securityKey))
        # 比较hiddenSample`与hiddenSample
        if self.hiddenSample != hiddenSample:
            # 不相等时，说明前面有Ri进行采样，需要验证采样结果
            dataHash = Sha3_256_util.getHash(self.payload)
            if dataHash == self.dataHash:
                delta = unhexlify(self.metadata) + unhexlify(oddLenToEven(self.hopCount)) + unhexlify(self.concealment)
                validationProof = CMAC_util.getHash(delta, unhexlify(securityKey))
                if validationProof != self.validationProof:
                    keep = False
            else:
                keep = False
        # 相等则Ac
        return keep

    def Update(self, curR, securityKey):
        # 是否采样都要更新prevR字段
        self.prevR = curR
        # 不采样
        # 更新hopCount字段
        self.hopCount = str(int(self.hopCount) + 1)
        # 更新hiddenSample字段
        self.hiddenSample = Sha3_256_util.getHash(
            unhexlify(oddLenToEven('0')) + unhexlify(oddLenToEven(self.hopCount)) + unhexlify(self.dataHash) + unhexlify(securityKey))
        # 生成随机128-bit ValidationProof
        # 即32 hex
        self.validationProof = randomKey()
        return

    def DstVerification(self, securityKey) -> bool:
        ac = True
        # 取出payload计算dataHash
        dataHash = Sha3_256_util.getHash(self.payload)
        # 计算matadata
        metaData = unhexlify(dataHash) + unhexlify(oddLenToEven(self.sessionId)) + unhexlify(oddLenToEven(self.timestamp))
        concealment = CMAC_util.getHash(metaData, unhexlify(securityKey))
        # 计算concealment
        if concealment != self.concealment:
            ac = False
        return ac

    def EP_Sampling(self) -> bool:
        flag = False
        chosen = self.PRF(int(self.hopCount))
        if chosen == int(self.hopCount):
            flag = True
        return flag

    def init_PacketMeta(self, payload, sessionId):
        self.dataHash = Sha3_256_util.getHash(payload)
        self.sessionId = sessionId
        self.timestamp = int(time())

    def PRF(self, target):
        return random.randint(0, target)


def randomKey():
    res = ''
    hex = '0123456789abcdef'
    for i in range(0, 32):
        idx = random.randint(0, 15)
        res += hex[idx]
    return res

def oddLenToEven(str):
    if len(str) % 2 == 1:
        return '0'+str
    return  str