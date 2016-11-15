# Encx
 
**Description**: 

CLI providing file encryption capability using the encx file format.

**Basic Usage**: 

	# AES 
	encrypt.py cleartext.txt > encrypted_file.txt -s AES -k "Rvq/bDuo6w60EsCobBqpfg=="
	decrypt.py encrypted_file.txt -s AES -k "Rvq/bDuo6w60EsCobBqpfg==" > decrypted-file.txt

	# RSA-AES (RSA encrypted AES key packaged with data)
	encrypt.py cleartext.txt > encrypted_file.txt -s RSA-AES -k ~/.ssh/id_rsa (pub key is derived)
	decrypt.py encrypted_file.txt -k ~/.ssh/id_rsa > decrypted-file.txt

**Known Issues**: 

* Maximum file size for all operations limited by size of memory due to the entire file being read. 
* Limited number of RSA key formats supported.
* No good way to generate keys at this time besides using a different tool (i'm deciding whether to bundle one :P)
* The CLI supplies no way to examine the metadata or add to the metadata (it is just used for the encryption scheme's metadata right now).

**What is the encx file format?**: 

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

