# This is a sample Python script.
from protocol.dynamic_path_valication import ValidationProtocol
import random
import json


# from Crypto.Hash import CMAC
# from Crypto.Cipher import AES
def randomKey():
    res = ''
    hex = '0123456789abcdef'
    for i in range(0, 32):
        idx = random.randint(0, 15)
        res += hex[idx]
    return res


# Press the green button in the gutter to run the script.
def test_standard():
    print()
    # init key
    key1 = randomKey()
    key2 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1

    srcSecurityKey = {}
    srcSecurityKey['R1'] = key2
    # init key end

    # R1 build a ValidationProtocol pack
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R2'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    # R2 receiver a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('Discard Packet')
            else:
                receiveHb.Update( curR,0)
        else:
            print('Discard Packet')
# Press the green button in the gutter to run the script.

# 总共2个路由器，安全的转发操作
def test_standard_2TrustedRouter():
    print()
    # init key
    key1 = randomKey()
    key2 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1

    srcSecurityKey = {}
    srcSecurityKey['R1'] = key2
    # init key end

    # R1 build a ValidationProtocol pack send to R2
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R2'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', payload, 'to:', nextR, 'dst:', dstR)
    # R2 receive a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR, 'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update( curR,0)
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')

# 总共3个路由器，安全的转发操作
def test_standard_3TrustedRouter():
    print()
    # init key
    key1 = randomKey()
    srcSecurity = randomKey()
    key3 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1
    r2_symmetricKey['R3'] = key3
    r3_symmetricKey = {}
    r3_symmetricKey['R2'] = key3
    srcSecurityKey = {}
    srcSecurityKey['R1'] = srcSecurity
    # init key end

    # R1 build a ValidationProtocol pack
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R3'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', payload, 'to:', nextR, 'dst:', dstR)
    # R2 receive a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = 'R3'
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        print(curR,'对数据包进行了采样')
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR,'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update( curR,r2_symmetricKey[nextR])
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')
    sendJson = json.dumps(receiveHb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', receiveHb.payload, 'to:', nextR, 'dst:', dstR)
    # R3 receive a ValidationProtocol pack
    curR = 'R3'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r3_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r3_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR,'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update(curR, r3_symmetricKey[nextR])
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')

# 总共2个路由器，中间一个不信任的转发路由器对数据包validationProof进行了篡改
def test_standard_2TrustedRouter1UnSafeModifyValidation():
    print()
    # init key
    key1 = randomKey()
    key2 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1

    srcSecurityKey = {}
    srcSecurityKey['R1'] = key2
    # init key end

    # R1 build a ValidationProtocol pack send to R2
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R2'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', payload, 'to: unsafe', 'dst:', dstR)
    # Unsafe receive from R1, redirect to R2,modify the validation field
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    print('不信任的路由器成功接受信息,修改前的 receiveHb.validationProof: ',receiveHb.validationProof)
    # 在这里对validationProof进行了篡改
    receiveHb.validationProof = randomKey()
    sendJson = json.dumps(receiveHb.__dict__)
    print('不信任的路由器成功发送信息,修改后的 receiveHb.validationProof: ',receiveHb.validationProof)
    # R2 receive a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR, 'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update( curR,0)
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')

# 总共2个路由器，中间一个不信任的转发路由器对数据包payload进行了篡改
def test_standard_2TrustedRouter1UnSafeModifyPayload():
    print()
    # init key
    key1 = randomKey()
    key2 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1

    srcSecurityKey = {}
    srcSecurityKey['R1'] = key2
    # init key end

    # R1 build a ValidationProtocol pack send to R2
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R2'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', payload, 'to: unsafe', 'dst:', dstR)
    # Unsafe receive from R1, redirect to R2,modify the payload field
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    print('不信任的路由器成功接受信息,修改前的 receiveHb.payload: ', receiveHb.payload)
    # 在这里对payload进行了篡改
    receiveHb.payload = 'test_standard_2TrustedRouter1UnSafeModifyPayload'
    sendJson = json.dumps(receiveHb.__dict__)
    print('不信任的路由器成功发送信息,修改后的 receiveHb.payload: ', receiveHb.payload)
    # R2 receive a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR, 'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update( curR,0)
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')


# 总共3个路由器，有一个信任的中间路由器对数据包payload进行了篡改
def test_standard_3TrustedRouterWithOneBad():
    print()
    # init key
    key1 = randomKey()
    srcSecurity = randomKey()
    key3 = randomKey()
    # print(key)
    # print(unhexlify(key))
    # print(hexlify(unhexlify(key)))
    r1_symmetricKey = {}
    r1_symmetricKey['R2'] = key1

    r2_symmetricKey = {}
    r2_symmetricKey['R1'] = key1
    r2_symmetricKey['R3'] = key3
    r3_symmetricKey = {}
    r3_symmetricKey['R2'] = key3
    srcSecurityKey = {}
    srcSecurityKey['R1'] = srcSecurity
    # init key end

    # R1 build a ValidationProtocol pack
    hb = ValidationProtocol()
    payload = '删除指令'

    dstR = 'R3'
    srcR = 'R1'
    nextR = 'R2'
    curR = srcR
    sessionId = 13147788
    hb.SrcInitialization(srcSecurityKey[srcR], srcR, dstR, payload, sessionId)
    hb.Construction(r1_symmetricKey[nextR], curR)
    sendJson = json.dumps(hb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', payload, 'to:', nextR, 'dst:', dstR)
    # R2 receive a ValidationProtocol pack
    curR = 'R2'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = 'R3'
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        print(curR,'对数据包进行了采样')
        receiveHb.Construction(r2_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r2_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR,'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update( curR,r2_symmetricKey[nextR])
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')
    print('信任的路由器',curR,'成功接受信息,修改前的 receiveHb.payload: ', receiveHb.payload)
    # 在这里对payload进行了篡改
    receiveHb.payload = 'Hello World!'
    print('信任的路由器',curR,'成功接受信息,修改后的 receiveHb.payload: ', receiveHb.payload)
    sendJson = json.dumps(receiveHb.__dict__)
    print('curR: ', curR, '成功发送信息, payload: ', receiveHb.payload, 'to:', nextR, 'dst:', dstR)
    # R3 receive a ValidationProtocol pack
    curR = 'R3'
    receiveJson = sendJson
    receiveHb = ValidationProtocol()
    receiveHb.__dict__ = json.loads(receiveJson.strip('\t\r\n'))
    nextR = ''
    if receiveHb.dstR != curR and receiveHb.EP_Sampling():
        receiveHb.Construction(r3_symmetricKey[nextR], curR)
    else:
        if receiveHb.Verification(r3_symmetricKey[receiveHb.prevR]):
            if curR == receiveHb.dstR:
                if receiveHb.DstVerification(srcSecurityKey[receiveHb.srcR]):
                    print('curR: ', curR,'Accept Packet from:', receiveHb.srcR, ', message: ', receiveHb.payload)
                else:
                    print('curR: ', curR, 'Discard Packet,because of DstVerification failed')
            else:
                receiveHb.Update(curR, r3_symmetricKey[nextR])
        else:
            print('curR: ', curR, 'Discard Packet because of Verification failed')

if __name__ == "__main__":
    test_standard()
    test_standard_2TrustedRouter()
    test_standard_3TrustedRouter()
    test_standard_3TrustedRouterWithOneBad()