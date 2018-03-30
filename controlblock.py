import struct
import base64
import datetime
import rsa
import hashlib

class RegionBlock:
    ''' Region block.
        struct {
            UINT16: RegionBlockSize
            UINT8: RegionID
            UINT8: HashType
            UINT16: RSAKeySizeInBits
            UINT8[*]: RSAPublicKey
            UINT8[*]: RSASignature
        };
        '''
    def __init__(self, regionid, hashtype, privatekeyfile):
        self.RegionID = regionid
        self.HashType = hashtype
        self.RegionBlockSize = 0

        with open(privatekeyfile) as privatefile:
            keydata = privatefile.read()
            privatefile.close()
            privkey = rsa.PrivateKey.load_pkcs1(keydata,'PEM')
            self.RSAPrivateKey = privkey

            #pub = rsa.PublicKey(privkey.n, privkey.e)
            pub_n_key = '%x' % privkey.n
            #assume privkey.e is 0x10001
            self.RSAPublicKey = pub_n_key.decode('hex')

            self.RSAKeySizeInBits = len(self.RSAPublicKey)*8
            self.RSASignature = bytearray(self.RSAKeySizeInBits/8)
        pass    

    def SigningRegionalData(self, BlockData):
        if self.HashType == 1:
            self.RSASignature = rsa.sign(BlockData, self.RSAPrivateKey, 'SHA-1')
        elif self.HashType == 2:
            self.RSASignature = rsa.sign(BlockData, self.RSAPrivateKey, 'SHA-256')
        pass

    def GetRawData(self):
        self.RawData = struct.pack('<HBBH', 
                            self.RegionBlockSize,
                            self.RegionID, 
                            self.HashType,
                            self.RSAKeySizeInBits)

        self.RawData += self.RSAPublicKey
        self.RawData += self.RSASignature

        self.RegionBlockSize = len(self.RawData)
        self.RawData = struct.pack('<HBBH', 
                            self.RegionBlockSize,
                            self.RegionID, 
                            self.HashType,
                            self.RSAKeySizeInBits)

        self.RawData += self.RSAPublicKey
        self.RawData += self.RSASignature

        return self.RawData
        pass

class ControlBlock:
    ''' Control block.
    	struct {
	        UINT8: Version
	        UINT16: ControlBlockSize
            UINT16: ControlDescriptorSize
            UINT8: NumberOfRegions
            UINT8[32]: Date
            UINT8[32]: Description
            UINT8[32]: Signer
            UINT8[16]: guidbin
	    };
        UINT8[*]: ControlBlockSignature
        '''
    RawData = bytearray(0xFFFF)
    ControlBlockSize = 0xFFFF
    ControlDescriptorSize = 0xFFFF
    NumberOfRegions = 0
    Description = bytearray(32)
    guidbin = bytearray(16)
    Signer = bytearray(32)
    RegionBlockSession = []
    RSAPrivateKey = bytearray(0)

    def __init__(self, version, NumberOfRegions, CtrlPrivateKey, HashType):
        self.Version = version
        self.NumberOfRegions = NumberOfRegions
        self.Date = bytearray(self.get_date_time())[0:32]
        self.HashType = HashType

        with open(CtrlPrivateKey) as privatefile:
            keydata = privatefile.read()
            privatefile.close()
            privkey = rsa.PrivateKey.load_pkcs1(keydata,'PEM')
            self.RSAPrivateKey = privkey
            
    def GetRawData(self):
#        
#        self.header = struct.pack(
#            "<16sHBB3sB",
#            self.guid, self.checksum, self.type, self.attributes, string_size[:3], self.state
#        )
#        
        self.RawData = struct.pack('<BHHB32s32s32s16s', 
                            self.Version, 
                            self.ControlBlockSize,
                            self.ControlDescriptorSize,
                            self.NumberOfRegions,
                            str(self.Date),
                            str(self.Description),
                            str(self.Signer), 
                            str(self.guidbin) )
        self.ControlDescriptorSize = len(self.RawData)

        self.RawData = struct.pack('<BHHB32s32s32s16s', 
                            self.Version, 
                            self.ControlBlockSize,
                            self.ControlDescriptorSize,
                            self.NumberOfRegions,
                            str(self.Date),
                            str(self.Description),
                            str(self.Signer), 
                            str(self.guidbin) )
        self.Signature = bytearray(256)

        RBAllRawData = bytearray(0)
        for RB in self.RegionBlockSession:
            RBAllRawData += RB.GetRawData()
        
        #Now update NR.
        self.NumberOfRegions = len(self.RegionBlockSession)

        self.ControlBlockSize = len(self.RawData)+len(RBAllRawData)
        self.RawData = struct.pack('<BHHB32s32s32s16s', 
                            self.Version, 
                            self.ControlBlockSize,
                            self.ControlDescriptorSize,
                            self.NumberOfRegions,
                            str(self.Date),
                            str(self.Description),
                            str(self.Signer), 
                            str(self.guidbin) )
        self.RawData += RBAllRawData

        if self.HashType == 1:
            self.Signature = rsa.sign(self.RawData, self.RSAPrivateKey, 'SHA-1')
        elif self.HashType == 2:
            self.Signature = rsa.sign(self.RawData, self.RSAPrivateKey, 'SHA-256')

#        padding_size=self.align_size(data_size)-data_size
#        self.padding_data='\xff'*padding_size
#
        padding_size = self.align_size(len(self.RawData+self.Signature))-len(self.RawData+self.Signature)
        #print '%s' %(str(self.Signature).encode('hex'))
    	return self.RawData+self.Signature+'\x00'*padding_size

    def align_size(self, size):
        self.align = 512
        rsize = (size / self.align) * self.align
        if size % self.align:
            rsize += self.align
        return rsize

    def get_date_time(self):
        return "%s" % datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')    	

    def add_region_block(self, RegionBlockTmp):
        self.RegionBlockSession.append(RegionBlockTmp)
        pass

    def Get_Raw_Public_Key(self):
        pub_n_key = '%x' % self.RSAPrivateKey.n
        #assume privkey.e is 0x10001
        return pub_n_key.decode('hex')
        pass
