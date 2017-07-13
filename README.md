# Encx
 
## Description

CLI providing file encryption capability using the encx file format.

## Installation

**Global Dependencies**
* Python3

**Linux Dependencies**
For linux distributions you'll need to get the python / openssl dependencies:

	# Debian/Ubuntu 
	sudo apt-get install build-essential libssl-dev libffi-dev python-dev	

	# Fedora/RHEL:
	sudo yum install gcc libffi-devel python-devel openssl-devel

**Module installation**
OSX and Windows should just work:
	
	# You might have to prefix with sudo:
	pip3 install https://github.com/jdotpy/encx/archive/stable.tar.gz

To test installation:
	
	encx -h


**Basic Usage**: 

	## Basic Encryption ##

	# Setup your default RSA key for easy encryption
	# You'll need to replace `id_rsa` with the path to your private key

	encx set_default_key ~/.ssh/id_rsa

	# Encrypt a message and send the output to a new .encx file!
	
	echo "The crow flies at midnight!" | encx encrypt -t ~/my-secret-message.txt.encx

	# Decrypt it back out

	encx decrypt ~/my-secret-message.txt.encx

	# You can also edit a file (reads, decrypts, opens editor, changes are encrypted and saved back to file)

	encx edit ~/my-secret-message.txt.encx

	## Key Generation ##

	# RSA Pem format
	encx keygen rsa -s 2048 > my_file.pem 
	encx keygen rsa -s 2048 -k my_file.pem -p my_public_key.pub

	# AES-ready key
	$ encx keygen key
	PJPKMG59Ai6uQfgDTbGs1w==

	# Strings/passwords
	$ encx keygen string 
	LTXgUHLWGJQnsBFhiitk
	$ encx keygen string --source "1234567890abcdef" -l 4
	980e4
	$ encx keygen string -s "[]{}" -l 4
	{[]]

	# UUIDs
	$ encx keygen uuid
	7a8f6755-f4f8-ac40-7962-c0df9c9a4b64

## Advanced Usage

I'll be adding a readthedocs site soon, until then just do:

	encx -h

## Plugins

Install these plugins for additional functionality

* S3 Backend (https://github.com/jdotpy/encx_s3)

		# Adds S3 protocol for easy upload/download
		encx encrypt /local-file.txt -t s3://bucket-name/remote-file.txt.encx
		encx decrypt s3://bucket-name/remote-file.txt.encx

* Client to `encx_vault_server` (https://github.com/jdotpy/encx_vault)

		# Configure your client
		encx vault:init 

		# Query documents in the vault
		encx vault:query

		# Add documents in the vault
		encx vault:add /local/path.txt /remote/path.txt

		# Edit documents in the vault
		encx vault:edit /remote/path.txt


## Known Issues 

* Maximum file size for all operations limited by size of memory due to the entire file being read. 
* Limited number of RSA key formats supported.
* The CLI supplies no way to examine the metadata or add to the metadata (it is just used for the encryption scheme's metadata right now).


## What is the encx file format?

Encryption Interchange file.

I saw a need for a file format that would allow for a binary payload (of encrypted data) to be
packaged along with metadata that would explain how it was stored and any other piece of metadata
the packager wanted. This allows you to encrypt a file and distribute it to another person (or a future
you) without them knowing any details about the process of encryption and then know exactly how to decrypt
it (given the right key of course). The result is a fileformat with 4 parts:

* 4 bytes - The bytestring "encx" to denote the format
* 4 bytes - Size of metadata payload. This is an unsigned long (little-endian).
* X bytes - Metadata in JSON format. The size of this section is indicated by the value of the previous section.
* N bytes - The rest of the bytes in the file are the binary payload, presumably encrypted.

The rules:
* The metadata should have a root property of "scheme" which indicates the encryption algorithm, version, IV, mode or anything else the decryptor would need to know.

