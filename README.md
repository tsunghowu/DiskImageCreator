# Signing Tool for boot security validation. 


This python utility is designed to provide a baseline for people who may
be interested in attaching the machine with secure boot process built-in. 
The secure boot process is a customized chain-of-trust boot flow in UEFI 
BIOS. It will exam the target disk image(in MBR) and see if it is properly 
signed by the root key controlled by owner. This utility is to help owner 
to create a signed image with owner keys. 

## Prerequisite  :
 Python 2.7
  * rsa
  * json
## Usage: 
python2_7 signing.py config_file.json

See .json files for more details. 
* Note: HashingType: 1 is for SHA-1, 2 is for SHA-256.

Each json file describes the root key file for the entire control block 
and how to sign(RSA-2048/4096, SHA-1/SHA-256) on each paritition with 
given paritition keys. 

The file TESTDATA.BIN is the disk image that I used spfdisk to create.

* config_2048.json : sign the configuration block with rsa-2048+SHA-1
* config_2048-SHA-256.json : sign the configuration block with rsa-2048+SHA-256
* config_4096.json : sign the configuration block with rsa-4096+SHA-1
* config_4096_S2-S1-All.json : sign the configuration block with rsa-4096+SHA-256 but use SHA-1 for partitions.
* config_4096_SHA-256.json : sign the configuration block with rsa-4096+SHA-256. This
case is to show you how much time it will take on hashing computing for each partitions. 
