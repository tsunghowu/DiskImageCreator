import struct
import base64



class PartitionBlock:
    ''' A Partition block is a block that will be hashing in either SHA-1 or SHA-256 and the hash
    	value will be encrypted by RSA-2048/RSA-4096.
    	if block_type is Partition
	        struct {
	            UINT32: StartLBA
	            UINT32: SizeOfPartition
	        };
	    else 
	        struct {

	   	    };
	   	}
        '''
    StartingLBA = 0
    PartitionSize = 0
    BlockSize = 512
    
    def __init__(self, mbr_part_header, block_type):
    	self.StartingLBA = 0
    	self.PartitionSize = 0
    	self.BlockSize = 512

    	if block_type == 1:
            try:
                self.StartingLBA, self.PartitionSize = struct.unpack("<II", mbr_part_header )
            except Exception as e:
                print("Error: invalid partition entity header.")
                raise e
        else:
        	self.StartingLBA = 0
        	self.PartitionSize = 1

        print '%x:%x' %(self.StartingLBA, self.PartitionSize)
    
#    def setToolVersion( self, AmiMmToolsVersion ):
#        self.ToolVersion = AmiMmToolsVersion
#        pass
    def SetRawData(self, data):
    	self.rawData = data
    	pass
    
    def GetRawData(self):
    	return self.rawData

    def GetLBAStarting(self):
    	return self.StartingLBA

    def GetSize(self):
    	return self.PartitionSize
    	
 
