__author__ = 'root'
from Thales_ISO8583_Messages import Connector
import logging, os
import logging.handlers
from Shared.StringToAscii import Ascii2Str
from Shared.ByteUtils import HexToByte
import binascii


class GenerateKey:
    conn = Connector.Connector()

    # CommandFields
    Mode = ''
    KeyType = ''
    KeyScheme = ''
    DeriveKeyMode = ''
    Delimiter = ';'
    TMK_ZMK_Flag = ''
    TMK = ''
    Exporting_Key_Scheme = ''
    Block_No = ''
    MAC_Key_Type = ''
    Mac_Generation_Mode = ''
    Message_Type = ''
    Key = ''
    Message_Length = ''
    Message_Block = ''

    """
    To generate a random key or a derived key and return it encrypted under the LMK and
    optionally under a ZMK or TMK (for transmission to another party).

    Further Notes:
    Exporting to a keyblock format requires the ZMK/TMK to be one of the following:
    Double or triple length DES key Any size AES key

    """
    # HEADA00002U


    #A01002U;1U8EA4E66E5D9916AD2994068820DBAD9Cx


    def __init__(self):
        #self.message_header = 'HEAD'
        self.command_code = 'A0'

    def get_commandTPK(self, TMK):
        self.command_code = 'A0'
        self.Mode = '1'
        self.KeyType = '002'
        self.TMK_ZMK_Flag = '1'
        self.KeyScheme = 'U'
        self.TMK = TMK
        self.Exporting_Key_Scheme = 'X'

        message =  self.command_code
        message += self.Mode
        message += self.KeyType
        message += self.KeyScheme + ';'
        message += self.TMK_ZMK_Flag
        message += self.TMK
        message += self.Exporting_Key_Scheme
        #print message
        return message

    def get_commandTAK_MAC(self, TMK):
        self.command_code = 'A0'
        self.Mode = '1'
        self.KeyType = '003'
        self.TMK_ZMK_Flag = '1'
        self.KeyScheme = 'U'
        self.TMK = TMK
        self.Exporting_Key_Scheme = 'X'

        message =  self.command_code
        message += self.Mode
        message += self.KeyType
        message += self.KeyScheme + ';'
        message += self.TMK_ZMK_Flag
        message += self.TMK
        message += self.Exporting_Key_Scheme
        #print message
        return message


    def get_commandTranslateKey(self, KeyType, Key, toScheme):
        self.command_code = 'B0'

        self.KeyType = KeyType
        self.Key = Key
        self.KeyScheme = toScheme

        message =  self.command_code
        message += self.KeyType
        message += self.Key
        message += self.KeyScheme

        #print message
        return message

    def get_commandGenerateaSetofZoneKeys(self, KEKs):

        self.command_code = 'OI'
        self.KEKs =  KEKs
        message = self.command_code
        message += self.KEKs
        message += ';HU1;1'
        #print message
        return message

    def get_commandTranslateaSetofZoneKeys(self, KEKr, ZPK, ZAK, ZEK):

        self.command_code = 'OK'
        self.KEKr =  KEKr
        self.KVC_Processing_Flag = '2'
        self.ZPK_Flag = '1'
        self.ZPK = 'H'+ ZPK
        self.ZAK_Flag = '1'
        self.ZAK = 'H'+ ZAK
        self.ZEK_Flag = '0'
        self.ZEK = 'H'+ '11111111111111111111111111111111'


        message = self.command_code
        message += self.KEKr
        message += self.KVC_Processing_Flag
        message += self.ZPK_Flag
        message += self.ZPK
        message += self.ZAK_Flag
        message += self.ZAK
        message += self.ZEK_Flag
        message += self.ZEK
        message += ';HU1'
        #print message
        return message




    def get_commandTPKPinBlock(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

        self.command_code = 'D4'
        self.KTP = TerminalPINKey
        self.KPE = PINEncryptionKey
        self.PinBlock = PINBlock
        self.PAN = AccountNumber


        message = self.command_code
        message += self.KTP
        message += self.KPE
        message += self.PinBlock
        message += self.PAN
        #print message
        return message

    def get_commandTPKPinBlock_CA(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

        self.command_code = 'CA'
        self.KTP = TerminalPINKey
        self.KPE = PINEncryptionKey
        self.Pin_Length = '12'
        self.PinBlock = PINBlock
        self.PinBlockFormat = '0101'
        self.PAN = AccountNumber


        message = self.command_code
        message += self.KTP
        message += self.KPE
        message += self.Pin_Length
        message += self.PinBlock
        message += self.PinBlockFormat
        message += self.PAN
        print message
        return message

    def get_commandTMK(self):
        self.Mode = '0'
        self.command_code = 'A0'
        self.KeyType = '002'
        self.KeyScheme = 'U'

        #message = self.message_header
        message = self.command_code
        message += self.Mode
        message += self.KeyType
        message += self.KeyScheme
        print message

        return message


    def get_RSA(self):

        self.command_code = 'EI'
        #keyType: 2- Key and management, 0-signature only, 1-key management only, 3-icc key, 4-ssl
        self.KeyType = '1'
        self.KeyLength = '2048'
        self.PublicKeyEncoding = '02'
        #self.Delimiter = Ascii2Str('<19>')
        #self.Trailer = '4RH486ET4U8J4R5874T8'


        message = self.command_code
        message += self.KeyType
        message += self.KeyLength
        message += self.PublicKeyEncoding
        #message += self.Delimiter
        #message += self.Trailer
        return message


    def get_commandTAK(self):
        self.Mode = '0'
        self.command_code = 'A0'
        self.KeyType = '003'
        self.KeyScheme = 'X'


        #message = self.message_header
        message = self.command_code
        message += self.Mode
        message += self.KeyType
        message += self.KeyScheme
        print message
        return message

    def get_commandGenerate_KEKr_Validation_Response(self, KEKr, KRs):

        self.command_code = 'E2'
        self.KEKr =  KEKr
        self.KRs = KRs

        message = self.command_code
        message += self.KEKr
        message += self.KRs
        #print "E2 Message = " + message
        return message

    def get_commandGenerate_KEKs_Validation_Request(self, KEKs):
        self.command_code = 'E0'
        self.KEKs = KEKs

        message = self.command_code
        message +=  self.KEKs
        return message

    def convert(self, int_value):
        encoded = format(int_value, 'x')
        length = len(encoded)
        encoded = encoded.zfill(length+length%2)
        return encoded.decode('hex')

    def get_commandGenerateMAC(self, Message, MAC_Key):
        #Message = Message.encode('hex')
        print len(Message)
        #if len(Message) %2 != 0:
        #   Message += '0'
        print len(Message)
        Len = hex(len(Message))[2:].zfill(4).upper()

        self.Message_Block = Message
        self.command_code = 'C2'
        self.Block_No = '0'
        self.MAC_Key_Type = '3'
        self.Mac_Generation_Mode = '3'

        self.Message_Type = '0'
        self.Key = MAC_Key
        self.Message_Length = Len

        message = self.command_code
        message += self.Block_No
        message += self.MAC_Key_Type
        message += self.Mac_Generation_Mode
        message += self.Message_Type
        message += self.Key
        message += self.Message_Length
        message += self.Message_Block
        print message
        return message

    def get_commandVerifyMAC(self, MAC, Message, Length, Key):
        message = 'C40320'
        message += Key
        message += MAC
        message += Length
        message += Message
        print message
        return message


    def execute_get_Generate_KEKr_Validation_Response(self,KEKr, KRs):
        response = self.conn.SendMessage(self.get_commandGenerate_KEKr_Validation_Response(KEKr, KRs))
        return response

    def execute_Translate_a_Set_of_Zone_Keys(self, KEKr, ZPK, ZAK, ZEK):
        response = self.conn.SendMessage(self.get_commandTranslateaSetofZoneKeys(KEKr, ZPK, ZAK, ZEK))
        return response

    def execute_get_a_Set_of_Zone_Keys(self, KEKs):
        response = self.conn.SendMessage(self.get_commandGenerateaSetofZoneKeys(KEKs))
        return response

    def execute_get_Generate_KEKs_Validation_Request(self,KEKs):
        response = self.conn.SendMessage(self.get_commandGenerate_KEKs_Validation_Request(KEKs))
        return response

    def execute_GenerateTMK(self):
        response = self.conn.SendMessage(self.get_commandTMK())
        print response
        return response

    def execute_GenerateTPK(self, TMK):
        response = self.conn.SendMessage(self.get_commandTPK(TMK))
        return response

    def execute_GenerateTAK_MAC(self, TMK):
        response = self.conn.SendMessage(self.get_commandTAK_MAC(TMK))
        return response

    def execute_TranslateKey(self,  KeyType, Key, toScheme):
        response = self.conn.SendMessage(self.get_commandTranslateKey(KeyType, Key, toScheme))
        return response

    def execute_TranslatePin(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):
        response = self.conn.SendMessage(self.get_commandTPKPinBlock(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber))
        return response

    def execute_TranslatePin_CA(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):
        response = self.conn.SendMessage(self.get_commandTPKPinBlock_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber))
        return response

    def execute_GenerateTAK(self,):
        response = self.conn.SendMessage(self.get_commandTAK())
        print response
        return response

    def execute_GenerateMAC(self, Message, Key):
        response = self.conn.SendMessage(self.get_commandGenerateMAC(Message, Key))
        return response

    def execute_VerifyMac(self, MAC, Message, Length, Key):
        response = self.conn.SendMessage(self.get_commandVerifyMAC(MAC, Message, Length, Key))
        return response

    def execute_GenerateRSAKeyPair(self):
        response = self.conn.SendMessage(self.get_RSA())
        return response

    def sendMessage(self, message):
        response = self.conn.SendMessage(message)
        return response



def __init__():


        # Setup the root logger to a file
        log = logging.getLogger()
        log.setLevel(level=logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(name)-16s %(levelname)-8s %(message)s')

        # make sure the logging directory exists
        dirname = "../Switch_Log/HSM_Node"
        if not os.path.exists(dirname):
            os.makedirs(dirname)


        # Add rotating file handler to logger
        handler = logging.handlers.TimedRotatingFileHandler(dirname + '/debug.log', when="MIDNIGHT", backupCount=90)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        log.addHandler(handler)

        # Add another one to log all INFO stuff to a different file
        info = logging.handlers.TimedRotatingFileHandler(dirname + '/info.log', when="MIDNIGHT", backupCount=90)
        info.setLevel(logging.INFO)
        info.setFormatter(formatter)
        log.addHandler(info)

        #Add another one to log all CRITICAL stuff to a different file
        critical = logging.handlers.TimedRotatingFileHandler(dirname + '/critical.log', when="MIDNIGHT", backupCount=90)
        critical.setLevel(logging.CRITICAL)
        critical.setFormatter(formatter)
        log.addHandler(critical)

        #Add a second logger, showing the same stuff to stderr
        console = logging.StreamHandler()
        console.setLevel(log.level)
        console.setFormatter(formatter)
        log.addHandler(console)
        ### -- End of logging code --#######################################################################
