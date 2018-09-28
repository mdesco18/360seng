"""
KeyFinder.py
Author: Marc-Andre Descoteaux V00847029
Project: SENG360 A1

Given a plaintext, ciphertext, and IV, find the key used in aes-128-cbc encryption.
"""

import sys
import argparse
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
	
	if debug:
		print(key)
		print(len(key))
	return key
"""
Create aes-128-cbc ciphers with our known IV and using a key from our dictionary.
Compare the decrypted ciphertext with the plaintext to discover the key used for encryption.
"""
def findKey(plaintext, ciphertext, iv, dict):

	global debug
	found = False
	plaintext = plaintext.decode('utf-8')
	
	for key in dict:
		if not found:
			size = len(key)
			if debug:
				print(key)
				print(size)
			if size < 16:
				key = padding(key, 16-size)
			elif size == 16:
				key = padding(key, 16)
			elif size > 16:
				continue
			key = str.encode(key)
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			pt = decryptor.update(ciphertext) + decryptor.finalize()
			pt = pt.decode('latin-1')
			#pt = pt.decode(encoding='latin-1', errors='ignore')
			
			
			if debug:
				#print(pt)
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
	parser.add_argument('-d', '--dictionary', dest='dictfile', nargs=1, type=argparse.FileType('r'),help='the dictionary of keys')
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
	
	""" Necessary? No. Bytestrings ended up being needed for Cipher
	ciphertext = hex(int(ciphertext, 16))
	iv = hex(int(iv, 16))
	"""
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
