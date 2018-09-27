README.md KeyFinder.py

Author: Marc-Andre Descoteaux
Student: V00847029 mdesco18@uvic.ca
Project: SENG360 a1

This program is designed to determine the key used in aes-128-cbc encryption from known plaintext, ciphertext, and IV.

To run:

	invoke "python KeyFinder.py <plaintext.txt> -o <key.txt>" at the command line
	
	Additionally:

	"--debug" or "--d" may be used as the 3rd argument instead of -o to print out intermediate object information used for debugging.

	To print to the console, omit <key.txt>.