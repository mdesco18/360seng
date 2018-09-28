"""
KeyFinder.py
Author: Marc-Andre Descoteaux V00847029
Project: SENG360 A1

Given a plaintext, ciphertext, and IV, find the key used in aes-128-cbc encryption.
"""

import sys
import argparse
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# global variables
global debug
#IV = 0xaabbccddeeff00998877665544332211

"""
Pad the key with # to be 16 bytes
"""
def padding(key, pad):

	for x in range(0, pad):
		key = key + '#'

	return key

"""
Testing the cryptography module with our dictionary
"""
def cipherTest(dict, iv, outfile):

	global debug
	plaintext = b"This is a top secret"
	
	for key in dict:
		
		size = len(key)
		
		if size < 16:
			key = padding(key, 16-size)
		elif size == 16:
			key = padding(key, 16)
		elif size > 16:
			continue
		key = str.encode(key)
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
		encryptor = cipher.encryptor()
		ct = encryptor.update(plaintext) + encryptor.finalize()
		decryptor = cipher.decryptor()
		pt = decryptor.update(ct) + decryptor.finalize()
		
		
		if debug:
			sys.stdout = outfile
			print(key.decode())
			print(plaintext)
			print(ct)
			print(pt)
			
		
		if pt == plaintext:
			print("Success")
		else:
			print("Failed")
	
"""
Testing encrypted ciphertexts instead of plaintexts
"""
def badFindKey(plaintext, ciphertext, iv, dict):

	global debug
	found = False
	#plaintext = plaintext.decode('utf-8')
	
	for key in dict:
		if not found:
			size = len(key)
			
			if size < 16:
				key = padding(key, 16-size)
			elif size == 16:
				key = padding(key, 16)
			elif size > 16:
				continue
			key = str.encode(key)
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
			encryptor = cipher.encryptor()
			ct = encryptor.update(b"a secret message") + encryptor.finalize()
			#pt = pt.decode('latin-1')
			
			if debug:
				print(key.decode())
				print(ciphertext)
				print(ct)
				print(ct == ciphertext)
			
			if ct == ciphertext:
				found = True
		else:
			break
	return key, found
"""
Using decryption with a buffer shown in the Interfaces documentation of cryptography
"""
def bufFindKey(plaintext, ciphertext, iv, dict):

	global debug
	found = False
	buf = bytearray(len(ciphertext)+15)
	
	for key in dict:
		if not found:
			size = len(key)
			
			if size < 16:
				key = padding(key, 16-size)
			elif size == 16:
				key = padding(key, 16)
			elif size > 16:
				continue
			key = str.encode(key, 'cp1252')
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			len_decrypt = decryptor.update_into(ciphertext,buf)
			pt = bytes(buf[:len_decrypt]) + decryptor.finalize()
			
			if debug:
				print(key.decode())
				print(plaintext)
				print(pt)
				print(pt == plaintext)
			
			if pt == plaintext:
				found = True
		else:
			break
	return key, found	
"""
Create aes-128-cbc ciphers with our known IV and using a key from our dictionary.
Compare the decrypted ciphertext with the plaintext to discover the key used for encryption.
"""
def findKey(plaintext, ciphertext, iv, dict):

	global debug
	found = False
	
	for key in dict:
		if not found:
			size = len(key)
			
			if size < 16:
				key = padding(key, 16-size)
			elif size == 16:
				key = padding(key, 16)
			elif size > 16:
				continue
			key = str.encode(key, 'cp1252')
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			pt = decryptor.update(ciphertext) + decryptor.finalize()
			
			if debug:
				print(key.decode())
				print(plaintext)
				print(pt)
				print(pt == plaintext)
			
			if pt == plaintext:
				found = True
		else:
			break
	return key, found
	
def main():

	global debug
	
	"""
	Using ArgumentParser to take in files from command line arguments
	"""
	parser = argparse.ArgumentParser(prog='KeyFinder.py',description='Take in files for KeyFinder')
	parser.add_argument('-p', '--infile', dest='plainfile', nargs=1, type=argparse.FileType('rb'), help='the plaintext file')
	parser.add_argument('-c', '--cipher', dest='cipherfile', nargs=1, type=argparse.FileType('rb'), help='the ciphertext file')
	parser.add_argument('-iv', '--vector', dest='ivfile',nargs=1, type=argparse.FileType('rb'), help='the initialization vector hex file')
	parser.add_argument('-d', '--dictionary', dest='dictfile', nargs=1, type=argparse.FileType('r', encoding='UTF-8'),help='the dictionary of keys')
	parser.add_argument('-D', '--debug', dest='debug', action='store_true', default= False, help='the debugging argument')
	parser.add_argument('-o', '--outfile', dest='outfile', nargs='?', type=argparse.FileType('w'),  default= sys.stdout, help='the outfile')
	args = parser.parse_args()
	
	
	"""
	Gathering objects from sys.args namespace
	"""
	
	plainfile = args.plainfile[0]
	plaintext = plainfile.read()
	plainfile.close()
	cipherfile = args.cipherfile[0]
	ciphertext = cipherfile.read()
	cipherfile.close()
	ivfile = args.ivfile[0]
	iv = ivfile.read()
	ivfile.close()
	
	dictfile = args.dictfile[0]
	dict = dictfile.read().split()
	dictfile.close()
	debug = args.debug
	outfile = args.outfile
	
	"""
	Object instantiation checking
	"""
	if debug:
		print("In Debug Mode:")
		print("Program start...")
		print("Plaintext File: ",plainfile)
		print("Plaintext: ",plaintext)
		print("Ciphertext File: ", cipherfile)
		print("Ciphertext: ", ciphertext)
		print("IV File: ",ivfile)
		print("IV: ", iv)
		print("Dictionary File: ",dictfile)
		# print("Dictionary: ", dict)
		print("Outfile: ", outfile)
		
	#cipherTest(dict, iv, outfile)
	
	key, found = findKey(plaintext, ciphertext, iv, dict)
	key = key.decode('utf-8')

	if debug:
			print(key)
			
	if found:
		outfile.write(key)
	else:
		outfile.write("The key could not be found.")
	outfile.close()

	
if __name__ == '__main__':
	main()
