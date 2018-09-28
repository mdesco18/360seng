README.md KeyFinder.py

Author: Marc-Andre Descoteaux
Student: V00847029 mdesco18@uvic.ca
Project: SENG360 a1

This program is designed to determine the key used in aes-128-cbc encryption from known plaintext, ciphertext, IV and a dictonary of common english words shorter than 16 characters as keys. It utilizes the `cryptography` module available at https://cryptography.io/en/latest 

	usage: KeyFinder.py [-h] [-p PLAINFILE] [-c CIPHERFILE] [-iv IVFILE] [-d DICTFILE] [-D] [-o [OUTFILE]]

	
	optional arguments:
	  -h, --help            show this help message and exit
	  -p PLAINFILE, --infile PLAINFILE
							the plaintext file in ascii
	  -c CIPHERFILE, --cipher CIPHERFILE
							the ciphertext file in ascii
	  -iv IVFILE, --vector IVFILE
							the initialization vector hex file in ascii
	  -d DICTFILE, --dictionary DICTFILE
							the dictionary of keys
	  -D, --debug           the debugging argument
	  -o [OUTFILE], --outfile [OUTFILE]
							the outfile
