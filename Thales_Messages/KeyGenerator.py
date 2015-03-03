__author__ = 'root'

import binascii
from Shared.ByteUtils import HexToByte

from Thales_ISO8583_Messages.GenerateaKey import *


#conn = Connector.Connector()
KeyClass = GenerateKey()


def GenerateKeys_TMK():
    response = KeyClass.execute_GenerateTMK()
    #print response
    ResponseTMK = {}
    ResponseTMK["Header"] = response[2:6]
    ResponseTMK["ResponseCode"] = response[6:8]
    ResponseTMK["ErrorCode"] = response[8:10]
    if ResponseTMK["ErrorCode"] == '00':
        ResponseTMK["TMK"] = response[10:43]
        ResponseTMK["TMK_Check"] = response[43:76]

    return ResponseTMK


def GenerateKeys_Public_Private_Key_Pair():
    response = KeyClass.execute_GenerateRSAKeyPair()

    #print response
    #print binascii.b2a_base64(response)

    ResponsePubPriKey = {}
    ResponsePubPriKey["Header"] = response[2:6]
    ResponsePubPriKey["ResponseCode"] = response[6:8]
    ResponsePubPriKey["ErrorCode"] = response[8:10]
    if ResponsePubPriKey["ErrorCode"] == '00':
        ResponsePubPriKey["Data"] =  response[10:]
        #ResponsePubPriKey["PublicKey"] = response[10:256]
        #ResponsePubPriKey["PrivateKeyLength"] = response[256:260]
        #ResponsePubPriKey["PrivateKey"] = response[260:]
        string_hex =  str(binascii.b2a_hex(ResponsePubPriKey["Data"])).upper()
        #print string_hex
        #print binascii.b2a_base64(ResponsePubPriKey["Data"])
        #print str(ResponsePubPriKey["Data"])

    return ResponsePubPriKey


def GenerateKeys_TAK():
    response = KeyClass.execute_GenerateTAK()
    ResponseTAK = {}
    ResponseTAK["Header"] = response[2:6]
    ResponseTAK["ResponseCode"] = response[6:8]
    ResponseTAK["ErrorCode"] = response[8:10]
    if ResponseTAK["ErrorCode"] == '00':
        ResponseTAK["TAK"] = response[10:43]
        ResponseTAK["TAK_Check"] = response[43:76]
    return ResponseTAK


def GenerateSessionKeys(TMK):
    response = KeyClass.execute_GenerateTPK(TMK)
    ResponseTPK = {}
    #print response
    ResponseTPK["Header"] = response[2:6]
    ResponseTPK["ResponseCode"] = response[6:8]
    ResponseTPK["ErrorCode"] = response[8:10]
    if ResponseTPK["ErrorCode"] == '00':
        ResponseTPK["TPK_LMK"] = response[10:43]
        ResponseTPK["TPK"] = response[43:76]
        ResponseTPK["TPK_Check"] = response[76:82]
        return ResponseTPK

def GenerateMACKeys(TMK):
    response = KeyClass.execute_GenerateTAK_MAC(TMK)
    ResponseTPK = {}
    #print response
    ResponseTPK["Header"] = response[2:6]
    ResponseTPK["ResponseCode"] = response[6:8]
    ResponseTPK["ErrorCode"] = response[8:10]
    if ResponseTPK["ErrorCode"] == '00':
        ResponseTPK["TAK"] = response[10:43]
        ResponseTPK["TAK_LMK"] = response[43:76]
        ResponseTPK["TAK_Check"] = response[76:82]
        return ResponseTPK

def TranslateKeyScheme( KeyType, Key, toScheme):
    response = KeyClass.execute_TranslateKey( KeyType, Key, toScheme)
    TranslateKeyScheme = {}
    print response
    TranslateKeyScheme["Header"] = response[2:6]
    TranslateKeyScheme["ResponseCode"] = response[6:8]
    TranslateKeyScheme["ErrorCode"] = response[8:10]
    if TranslateKeyScheme["ErrorCode"] == '00':
        TranslateKeyScheme["Key"] = response[10:43]
        return TranslateKeyScheme

def TranslatePIN_TDES(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

    response = KeyClass.execute_TranslatePin(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber)
    #print response
    TranslatePIN_TDES_Response = {}
    TranslatePIN_TDES_Response["Header"] = response[2:6]
    TranslatePIN_TDES_Response["ResponseCode"] = response[6:8]
    TranslatePIN_TDES_Response["ErrorCode"] = response[8:10]
    if TranslatePIN_TDES_Response["ErrorCode"] == '00':
        TranslatePIN_TDES_Response["DestPIN"] = response[10:26]
        return TranslatePIN_TDES_Response


def TranslatePIN_TDES_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

    response = KeyClass.execute_TranslatePin_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber)
    #print response
    TranslatePIN_TDES__CA_Response = {}
    TranslatePIN_TDES__CA_Response["Header"] = response[2:6]
    TranslatePIN_TDES__CA_Response["Status"] = response[6:8]
    if TranslatePIN_TDES__CA_Response["Status"] == '00':
        TranslatePIN_TDES__CA_Response["DestPIN"] = response[8:24]
        return TranslatePIN_TDES__CA_Response

def Generate_KEKr_Validation_Response(KEKr, KRs):
    response = KeyClass.execute_get_Generate_KEKr_Validation_Response(KEKr, KRs)
    KEKr_Validation_Response = {}
    #print response
    KEKr_Validation_Response["Header"] = response[2:6]
    KEKr_Validation_Response["ResponseCode"] = response[6:8]
    KEKr_Validation_Response["ErrorCode"] = response[8:10]
    if KEKr_Validation_Response["ErrorCode"] == '00':
        KEKr_Validation_Response["KRr"] = response[10:]
    return KEKr_Validation_Response


def Generate_KEKs_Validation_Request(KEKs):
    response = KeyClass.execute_get_Generate_KEKs_Validation_Request(KEKs)
    KEKs_Validation_Request = {}
    KEKs_Validation_Request["Header"] = response[2:6]
    KEKs_Validation_Request["ResponseCode"] = response[6:8]
    KEKs_Validation_Request["ErrorCode"] = response[8:10]
    if KEKs_Validation_Request["ErrorCode"] == '00':
        KEKs_Validation_Request["KRs"] = response[11:27]
        KEKs_Validation_Request["KRr"] = response[27:75]
    return KEKs_Validation_Request

def VerifyMAC(MAC, Message, Length, Key):
    response = KeyClass.execute_VerifyMac(MAC, Message, Length, Key)
    print response


def Generate_a_Set_of_Zone_Keys(KEKs):
    response = KeyClass.execute_get_a_Set_of_Zone_Keys(KEKs)
    #print response
    ZoneKeys = {}
    ZoneKeys["Header"] = response[2:6]
    ZoneKeys["ResponseCode"] = response[6:8]
    ZoneKeys["ErrorCode"] = response[8:10]
    if ZoneKeys["ErrorCode"] == '00':
        ZoneKeys["ZPK(LMK)"] = response[10:43]
        ZoneKeys["ZPK(ZMK)"] = response[43:76]
        ZoneKeys["ZPK Check Value"] = response[76:82]
        ZoneKeys["ZAK(LMK)"] = response[82:115]
        ZoneKeys["ZAK(ZMK)"] = response[115:148]
        ZoneKeys["ZAK Check Value"] = response[148:154]
        ZoneKeys["ZEK(LMK)"] = response[154:187]
        ZoneKeys["ZEK(ZMK)"] = response[187:220]
        ZoneKeys["ZEK Check Value"] = response[220:226]
    return ZoneKeys




def Translate_a_Set_of_Zone_Keys(KEKr, ZPK, ZAK, ZEK):
    response = KeyClass.execute_Translate_a_Set_of_Zone_Keys(KEKr, ZPK, ZAK, ZEK)
    #print response
    TranslatedZoneKeys = {}
    TranslatedZoneKeys["Header"] = response[2:6]
    TranslatedZoneKeys["ResponseCode"] = response[6:8]
    TranslatedZoneKeys["ErrorCode"] = response[8:10]
    if TranslatedZoneKeys["ErrorCode"] == '00':
        TranslatedZoneKeys["KCV Processing Flag"] = response[10:11]
        TranslatedZoneKeys["ZPK(LMK)"] = response[11:44]
        TranslatedZoneKeys["ZPK Check Value"] = response[44:50]
        TranslatedZoneKeys["ZAK(LMK)"] = response[50:83]
        TranslatedZoneKeys["ZAK Check Value"] = response[83:89]
        TranslatedZoneKeys["ZEK(LMK)"] = response[89:122]
        TranslatedZoneKeys["ZEK Check Value"] = response[122:128]
    return  TranslatedZoneKeys






def CalculateMAC_ZAK(Message, MAC_Key):
    responseMAC = KeyClass.execute_GenerateMAC(Message, MAC_Key)
    print responseMAC
    ResponseMAC = {}
    ResponseMAC["Header"] = responseMAC[2:6]
    ResponseMAC["ResponseCode"] = responseMAC[6:8]
    ResponseMAC["ErrorCode"] = responseMAC[8:10]
    if ResponseMAC["ErrorCode"] == '00':
        ResponseMAC["MAC"] = responseMAC[10:]
        return ResponseMAC


def BinaryDump(s):
    """
    Returns a hexdump in postilion trace format. It also removes the leading tcp length indicator

    0000(0000)  30 32 31 30 F2 3E 44 94  2F E0 84 20 00 00 00 00   0210.>D./.. ....
    0016(0010)  04 00 00 22 31 36 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A   ..."16**********
    0032(0020)  2A 2A 2A 2A 2A 2A 30 31  31 30 30 30 30 30 30 30   ******0110000000
    0048(0030)  30 30 30 35 30 30 30 30  31 30 30 34 30 36 34 30   0005000010040640
    ...
    0576(0240)  36 3C 2F 44 61 74 61 3E  3C 2F 52 65 74 72 69 65   6</Data></Retrie
    0592(0250)  76 61 6C 52 65 66 4E 72  3E 3C 2F 42 61 73 65 32   valRefNr></Base2
    0608(0260)  34 44 61 74 61 3E								  4Data>
    """
    #Remove TCP length indicator
    s = s[2:]
    while s != '':
        part = s[:16]
        s = s[16:]


def ReadableAscii(s):
    """
    Print readable ascii string, non-readable characters are printed as periods (.)
    """
    r = ''
    for c in s:
        if ord(c) >= 32 and ord(c) <= 126:
            r += c
        else:
            r += '.'
    return r


def __PAN_2_UBCD(PAN):
        res = "\0" * 4
        for i in range(-13, -1):
            ch = PAN[i]
            res += chr(ord(ch) - ord('0'))
        return res


"""

Response Payload = [02103222001182C0088101200000000000600002190551100000030219440000020009437586002F086110001639385339323138313633343337353836303032202020202020000000000000000200000000600072DA61CA00000000]
2015-02-19 16:51:09,209 CuscalClient     INFO
0210:
  [Fixed  n         6] 003 [012000] Processing Code
  [Fixed  n        12] 004 [000000006000] Amount Transaction
  [Fixed  n        10] 007 [0219055110] Transmission Date and Time
  [Fixed  n         6] 011 [000003] Systems Trace Audit Number
  [Fixed  n         4] 015 [0219] Date, Settlement
  [Fixed  xn       10] 028 [4400000200] Amount, Transaction Fee
  [LL     n        11] 032 [437586002] Acquiring Institution ID Code
  [LL     n        11] 033 [61100016] Forwarding Institution ID Code
  [Fixed  an        4] 039 [3938] Response Code
  [Fixed  ans      16] 041 [5339323138313633] Card Acceptor Terminal ID
  [Fixed  ans      30] 042 [343337353836303032202020202020] Card Acceptor ID Code
  [Fixed  n        16] 053 [0000000000000002] Security Related Control Information
  [Fixed  n        12] 057 [000000006000] Amount Cash
  [Fixed  b        16] 064 [72DA61CA00000000] Message Authentication Code

2015-02-19 14:19:47,051 CuscalClient     INFO     0210 Financial Response Received [0098]

#ZAK_LMK_R = U2FDFA052B9BDF472A078401F16A36924
#ZAK_LMK_S = U379C53D02F9BF6660209A46FF954358B
#ZPK_LMKR = UF3E26BBE62DC6DD4BE70D1ED563053A1
#ZPK_LMKS = UEEC9DBF860969946092B199F2BCB73F1


2015-02-20 10:35:26,481 root             INFO     Recieve Keys under LMK : ZAK= UC6F455E93A25D5BF6FD2F30DE61F7E45, ZAK Check Value: 57A7A7 ZPK = UFCA7259F8BEF1A65D529BEE6F2990936, ZPK Check Value: 046FF0
2015-02-20 10:35:26,550 root             INFO     Send Keys under LMK : ZAK= UAA993EC3720D2ABEE46A17C009866866, ZAK Check Value: D0C2C8 ZPK = UB24ABB7890DBFFA469168E07C4B98286, ZPK Check Value: D1CE3A


Message = "0200323a449128e218810120000000000060000220155448000067155447022002205811021041440000020009437586002F324902370000002348D121210111234123303030303030303030333836533932313831363334333735383630303220202020202043415348504f494e5420202020202c202020202020202020204d414449534f4e202020202020415530303654434330315c8443FBF0B83961A40000000000000002000000006000"

Message = Message.encode('hex')
print len(Message)
Len = hex(len(Message)/2)[2:].zfill(4).upper()
print Len
#ZAKs = "UAB74A4C25421EAD16A43C032F96C9D38"
#ZAKr = "UFA8E1BF81DBFCD962EC9B33250FADECF"

ZAKs = "U96850B6C401750C8D802E2C98CC391DB"

x =  CalculateMAC_ZAK(Message , ZAKs)


ZAKr = "U97CBBD4989744271BEB8F30705F9D1B4"
Message = '02103222001182C0088101200000000000600002230041030000080223440000020009437586002F0861100016393853393231383136333433373538363030322020202020200000000000000002000000006000'
Message = Message
Len = hex(len(Message))[2:].zfill(4).upper()

macb = '669E66FE'

#VerifyMAC(MAC, Message, Length, Key):x
print VerifyMAC(macb, Message, Len, ZAKr)



"""