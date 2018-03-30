#!/usr/bin/env python
# File name: name.py
import sys
import json
import os
import rsa
import struct
import json
from block import *
from controlblock import *

base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]

def object_compare(x, y):   #used for compare key in dict.
   if x['Seq'] > y['Seq']:
      return 1
   elif x['Seq'] == y['Seq']:
      return 0
   else:  #x.resultType < y.resultType
      return -1

if __name__ == '__main__':
    print 'Signing Tool for the new Secure Boot validation. Version: 1.01'
    print '    This tool is to generate valid Configuration/Regional Blocks base on given DISK raw image'
    print '    Usage(windows platform): python27 signing.py config.json'
    print '    See the details in .json files'

    if len(sys.argv) != 2 :
        sys.exit(-1)

    SigningObjects = []
    NewRegionBlock = [None,None,None,None]

    ConfigData = {}
    ConfigFile = sys.argv[1]

    with open(ConfigFile) as inputFile:
        ConfigData = json.load(inputFile)
        inputFile.close()
    pass
    
    ConfigData['Jobs'].sort(object_compare)

    print ConfigData['InputFile']

    '''
        Extract raw data from each section.
    '''
    with open( ConfigData['InputFile'] , 'rb') as diskFile:
        TargetFileSize = os.path.getsize( ConfigData['InputFile'] )
        fileContent = diskFile.read(TargetFileSize)
        diskFile.close()

        fileContent = bytearray(fileContent)
        MBR = fileContent[0:512]
        
        Partition1LBA, = struct.unpack("<I", fileContent[0x1C6:0x1C6+4] )
        if Partition1LBA != 0:
            if Partition1LBA > 0x800 :
                print "Warning!!! The size of MBR+Booloader exceeds 2048 sectors."
            MBR = fileContent[0:Partition1LBA*512]

        MBR_obj = PartitionBlock(MBR, 0)
        MBR_obj.SetRawData(MBR)
        SigningObjects.append(MBR_obj)

        for dataElement in ConfigData['Jobs']:
            if dataElement['RegionID'] == 1:    #MBR
                NewRegionBlock[0] = RegionBlock(int(dataElement['RegionID']), 
                                               int(dataElement['HashingType']), 
                                               dataElement['PrivateKeyFile'])

                NewRegionBlock[0].SigningRegionalData(MBR_obj.GetRawData())
                
                with open(dataElement['OutputRawFile'], 'wb+') as OutputFile:
                    OutputFile.write(MBR_obj.GetRawData())        
                    OutputFile.close()
                
        for dataElement in ConfigData['Jobs']:
            if dataElement['RegionID'] != 1:
                
                PartIndex = dataElement['RegionID']-2
                PartitionEntity = fileContent[0x1C6+0x10*PartIndex:0x1C6+0x10*PartIndex+8]

                PartitionLBA, PartitionSize = struct.unpack("<II", PartitionEntity )
                if PartitionLBA == 0 or PartitionSize == 0:
                    print "Error!!! The config does not match to the structure in MBR."
                    sys.exit(-1)

                Part_Objs = PartitionBlock(PartitionEntity, 1)
                RawData = fileContent[Part_Objs.GetLBAStarting()*512:
                        Part_Objs.GetLBAStarting()*512 + Part_Objs.GetSize()*512 ]
                
                Part_Objs.SetRawData(RawData)
                SigningObjects.append(Part_Objs)

                i = dataElement['RegionID']-1
                
                NewRegionBlock[i] = RegionBlock(int(dataElement['RegionID']), 
                                                int(dataElement['HashingType']), 
                                                dataElement['PrivateKeyFile'])

                NewRegionBlock[i].SigningRegionalData(Part_Objs.GetRawData())
                
                with open(dataElement['OutputRawFile'], 'wb+') as OutputFile:
                    OutputFile.write(Part_Objs.GetRawData())        
                    OutputFile.close()
                    pass

    with open(ConfigData['OutputConfigBlock'], 'wb+') as OutputFile:
        OutputFile.write(fileContent)
        CB = ControlBlock(int(ConfigData['Version']), 
                          3, 
                          ConfigData['PrivateKeyFile'], 
                          int(ConfigData['HashingType']))
               # version, NumberOfRegions, CtrlPrivateKey, HashType
        for rb in NewRegionBlock:
            CB.add_region_block(rb)

        OutputFile.write(CB.GetRawData())
        OutputFile.close()

        with open(ConfigData['OutputRawPubkey'], 'wb+') as PubRawFile:
            PubRawFile.write(CB.Get_Raw_Public_Key())
            PubRawFile.close()
        pass
else:
    print 'I am being imported from another module.'
