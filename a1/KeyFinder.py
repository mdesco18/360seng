"""
KeyFinder.py
Author: Marc-Andre Descoteaux V00847029
Project: SENG360 A1

Given a plaintext, ciphertext, and IV, find the key used in aes-128-cbc encryption.
"""

import sys

# global variables
debug = False



def main():

	global debug
	# check for debugging argument
	if len(sys.argv) > 2:
		if sys.argv[2] == "--debug" or sys.argv[2] == "-d":
			debug = True
			print("\nIn Debug Mode:\n")
	if len(sys.argv) > 3:
		sys.stdout = open(str(sys.argv[3]), 'w')
	
	fi = str(sys.argv[1])
	
	if debug:
		print("Program start...")
		print("File:",fi)

if __name__ == '__main__':
	main()
