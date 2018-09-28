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

def padding(key, pad):

	for x in range(0, pad):
		key = key + '#'
	key = str.encode(key)
	if debug:
		print(key)
		print(len(key))
	return key
	
def findKey(plaintext, ciphertext, iv, dict):

	global debug
	found = False

	for key in dict:
		if not found:
			size = len(key)
			if debug:
				print(key)
				print(size)
			if size < 16:
				key = padding(key, 16-size)

			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			pt = decryptor.update(ciphertext) + decryptor.finalize()
			
			if debug:
				print(pt)
				
			if pt == plaintext:
				found = True

	return key
	
def main():

	global debug
	
	"""
	Using ArgumentParser to take in files from command line arguments
	"""
	parser = argparse.ArgumentParser(prog='KeyFinder.py',description='Take in files for KeyFinder')
	parser.add_argument('-p', '--infile', dest='plainfile', nargs=1, type=argparse.FileType('r'), help='the plaintext file')
	parser.add_argument('-c', '--cipher', dest='cipherfile', nargs=1, type=argparse.FileType('r'), help='the ciphertext file')
	parser.add_argument('-iv', '--vector', dest='ivfile',nargs=1, type=argparse.FileType('r'), help='the initialization vector hex file')
	parser.add_argument('-d', '--dictionary', dest='dictfile', nargs=1, type=argparse.FileType('r'),help='the dictionary of keys')
	parser.add_argument('-D', '--debug', dest='debug', action='store_true', default= False, help='the debugging argument')
	parser.add_argument('-o', '--outfile', dest='outfile', nargs='?', type=argparse.FileType('w'),  default= sys.stdout, help='the outfile')
	args = parser.parse_args()
	
	
	"""
	Gathering objects from sys.args namespace
	"""
	
	plainfile = args.plainfile[0]
	plaintext = str.encode(plainfile.read())
	plainfile.close()
	cipherfile = args.cipherfile[0]
	ciphertext = cipherfile.read()
	cipherfile.close()
	ivfile = args.ivfile[0]
	iv = str.encode(ivfile.read())
	print(len(iv))
	ivfile.close()
	""" Necessary? No
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
		#print("Dictionary: ", dict)
		print("Outfile: ", outfile)
	
	key = findKey(plaintext, ciphertext, iv, dict)
	
	outfile.write(key)
	outfile.close()
	
	
if __name__ == '__main__':
	main()
