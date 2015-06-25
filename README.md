cryptographer.py
================

[![Build Status](https://travis-ci.org/xzovy/cryptographer.py.svg?branch=master)](https://travis-ci.org/xzovy/cryptographer.py) [![Code Health](https://landscape.io/github/xzovy/cryptographer.py/master/landscape.svg?style=flat)](https://landscape.io/github/xzovy/cryptographer.py/master)

### What is cryptographer.py?

cryptographer.py is a python program I wrote to learn more about encryption and python.
It is designed to encrypt messages using a two phase encryption technique I
created. These messages can be entered either as part of the command or from a specified
file. The message is encrypted with password which is hashed at runtime to ensure
complexity and length without making it hard to remember. The password is used as part
of the encryption and to determine the number of rounds in the encryption. Once the file
has been encrypted it can either be printed to standard out or written to a file. Encrypted
text will consist of a huge variety of Unicode characters, not all of which will be displayed
properly with most fonts.

Decryption works the same way but in reverse.

###  License:
##### GPLv2

See accompanying LICENSE file for the full license.

### Bounty:

One bitcoin will be paid out to whom so ever can responsibly disclose a method by which the 
bounty.encrypt can be decrypted without knowledge of the password or key length and within a
reasonable time frame on a modern computer (or cluster of computers).  

### Disclaimer:

Along with the NO WARRENTY disclaimer explictly laided out in the GPL, this software
has not been independantly reviewed and should NOT be used for any application for which
strong encryption is required.

### Installation:

No installation is required to run cryptographer.py. Simply give the file execute privileges
and run it. If you do not place the cryptographer.py file inside your path you will need to
specify its relative or absolute path.

### Usage:

cryptographer.py (-e | -d) -p PASSWORD -k NUMBER (-m MESSAGE | -i INPUT_FILENAME) [-o OUTPUT_FILENAME] [-v | -vv]

### Example usage:

##### Encrypt the message “This is a message.” with the password “password” and the key length “20”:

cryptographer.py -e -p password -k 20 -m “This is a message.”


##### Encrypt the file “secret_file.txt” with the pass phase “secret code words” and the key length “15”:

cryptographer.py -e -p “secret code words” -k 15 -i secret_file.txt


##### Encrypt the same file as above, but write the output to the file “encrypted_file.txt”:

cryptographer.py -e -p “secret code words” -k 15 -i secret_file.txt -o encrypted_file.txt


##### In case you want to see what is happening during the encryption process:

cryptographer.py -e -p “secret code words” -k 15 -i secret_file.txt -o encrypted_file.txt -vv


##### To decrypt the filed called “encrypted_file.txt” and write the output to “decrypted_file.txt”:

cryptographer.py -e -p “secret code words” -k 15 -i encrypted_file.txt -o decrypted_file.txt

### Usage tips:

The hashing function does not make passwords harder to guess, it simply makes sure that there
are enough rounds of encryption and that the characters used in the encryption have a wide
enough variety. Please try to use long pass phases which someone who knows you is unlikely
to guess.

The key length field can be any number higher than zero. However, it is suggested that you
not pick a very low number (1-10) or a very high number (500+). Very low numbers will reduce
the effectiveness of the encryption and very high numbers will make the encryption take a
very long time without adding a whole lot of security.

The key length is part of the secret key used to decrypt a message. You MUST be able to
remember this in order to decrypt the message. However, making it something guessable
(birthday, number of cats, age of child, etc) is unadvised.
Use something that is unlikely to be guessed by easy to remember.

Verbose output should NOT be saved to a file as it contains sensitive information which will
make it trivial to decrypt the message. Use the verbose mode only for testing purposes and
use the -o argument to save encrypt/decrypt messages to a file.
