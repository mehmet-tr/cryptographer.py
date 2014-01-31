#!/usr/bin/env python3
"""
Title: cryptographer.py
Author: Caleb Cooper
License: GPLv2
Version: 1.0
Version Date: 2014-01-30
Description: This program performs a two phase cryptographic function
             upon a supplied message, either inline or from a file.
             This function is repeated for a number of rounds determined
             by the length of a password supplied by the user. Once all
             of the rounds are complete, the encrypted/decrypted message
             can either be printed to standard out or written to a file.
Usage:
cryptographer.py (-e|-d) -p PASSWORD -k KEYLENGTH
"""

import os, time, re, argparse

parser = argparse.ArgumentParser()
action = parser.add_mutually_exclusive_group(required=True)
action.add_argument('-e', '--encrypt', help='For encrypting a file/message.', action='store_true')
action.add_argument('-d', '--decrypt', help='For decrypting a file/message.', action='store_true')
parser.add_argument('-p', '--password', required=True, help='The passphase with which to encrypt/decrypt. If more than a word, use quotes.')
parser.add_argument('-k', '--key', required=True, help='Determine key length. Suggested values between 10 and 1000, very high key lengths will take a long time.')
message = parser.add_mutually_exclusive_group(required=True)
message.add_argument('-m', '--message', help='The message to be encrypted/decrypted. Messages must be inside quotation marks.')
message.add_argument('-i', '--inputfile', help='The file to be encrypted/decrypted.')
parser.add_argument('-o', '--outputfile', help='The file in which to save the encrypted/decrypted message. If none is given, message will be printed to screen.')
parser.add_argument('-v', '--verbose', help='Prints out information about the encryption/decryption process as it goes.', action='store_true')
args = parser.parse_args()

def variables():
    """ Defines variables based on command line arguments. Also does some input checking on
    the password and key length."""
    global args
    global encrypt
    global decrypt
    global password
    global keylength
    global message
    global input_file
    global output_file
    global verbose
    encrypt = args.encrypt
    decrypt = args.decrypt
    password = args.password
    try:
        keylength = int(args.key)
    except ValueError:
        print("The key length must be an integer.")
        exit(1)
    message = args.message
    input_file = args.inputfile
    output_file = args.outputfile
    verbose = args.verbose


def phase1_crypto():
    """ Phase 1 encrypts every character in the message by shifting it through the UTF-8
    alphabet by a number derived from the character of the hashed password for the current
    round and the nonce."""
    global password
    global nonce
    global message
    count = 1
    encrypted_message = ""
    for i in message:
        offset = int(ord(password[count % (password.count('') - 1)])) * ord(nonce)
        if encrypt:
            encrypted_char = chr(int(ord(i) + offset) % 55000)
        elif decrypt:
            encrypted_char = chr(int(ord(i) - offset) % 55000)
        encrypted_message = encrypted_message + encrypted_char
        count += 1
    message = encrypted_message
    if verbose:
        print("Round " + str(rnum) + "-- Phase 1: " + message)

def phase2_crypto():
    """ Phase 2 encrypts every fifth character in the message, starting with the one in
    the position of the round number modulus 5, by shifting it by a number derived from
    the round number, nonce, and the ordinal position of the current round's character
    from the hashed password devided by the length of the password."""
    global password
    global nonce
    global rnum
    global message
    global char
    count = 1
    rnonce = rnum * ord(nonce)
    encrypted_message = ""
    for i in message:
        if count % 5 == rnum % 5:
            pass_place = int(ord(char) / len(password))
            if encrypt:
                encrypted_char = chr((ord(i) + (pass_place * rnonce)) % 55000)
            if decrypt:
                encrypted_char = chr((ord(i) - (pass_place * rnonce)) % 55000)
            encrypted_message = encrypted_message + encrypted_char
        else:   
            encrypted_message = encrypted_message + i
        count += 1
    message = encrypted_message
    if verbose:
        print("Round " + str(rnum) + "-- Phase 2: " + message)

def hash_pass():
    """ The password is hashed to ensure that the resulting hashed password will meet
    the keylength requirements given by the user. This allows the user to have a
    secure password without having to remember it."""
    global password
    if verbose:
        print("Unhashed password: " + password)
    t1 = len(password) + 2
    while len(str(t1)) < (int(keylength) * 4):
        for i in password:
            t1 = t1 * ((len(password) + 2) ** ord(i))
    p = ""
    for i in zip(*[iter(str(t1))] * 3):
        n0 = int(i[0]) + 2
        n1 = int(i[1]) + 2
        n2 = int(i[2]) + 2
        p = p + chr(((n0 ** n1) ** n2) % 55000 + 48)
    password = p[:int(keylength)]
    if verbose:
        print("Hashed password: " + password)


def crypto():
    """ The purpose of this function is to repeat over every character in the
    password and execute phase 1 and 2 of the cryptographic function on the
    message."""
    global rnum
    global char
    for char in password:
        phase1_crypto()
        phase2_crypto()
        if verbose:
            print((rnum / len(password)) * 100, "% Complete.")
        rnum += 1

def encrypt_func():
    """ Performs all of the nessacerry setup and clean up to encrypt a message.
    Also handles writing to the output file or standard out."""
    global password
    global message
    global input_file
    global output_file
    global verbose
    global nonce
    global rnum
    nonce = chr(int(time.time() * 10000000) % 55000)
    hash_pass()
    rnum = 1
    if message:
        crypto()
        if output_file:
            out_file = open(output_file, 'w')
            out_file.write(str(nonce)+message)
            out_file.close()
        else:
            print("Encrypted Message:")
            print()
            print(str(nonce)+message)
            print()
        if verbose:
            print("Encryption complete.")
    elif input_file:
        if os.path.isfile(input_file):
            in_file = open(input_file)
            message = in_file.read()
            crypto()
            if output_file:
                out_file = open(output_file, 'w')
                out_file.write(str(nonce)+message)
                out_file.close()
            else:
                print("Encrypted Message:")
                print()
                print(str(nonce)+message)
                print()
            if verbose:
                print("Encryption complete.")
        else:
            print("No such file as", input_file)
            exit(1)
    else:
        print("You must either enter a message (-m) or specify a input file (-i).")
        exit(1)


def decrypt_func():
    """ Performs all of the nessacerry setup and clean up to decrypt a message.
    Also handles writing to the output file or standard out."""
    global password
    global message
    global input_file
    global output_file
    global verbose
    global nonce
    global rnum
    hash_pass()
    if message:
        nonce = re.findall(r'^(.?)', message)[0]
        message = re.findall('^.(.+)', message)[0]
        rnum = 1
        crypto()
        if output_file:
            out_file = open(output_file, 'w')
            out_file.write(message)
            out_file.close()
        else:
            print("Decrypted Message:")
            print()
            print(message)
            print()
        if verbose:
            print("Decryption complete.")
    elif input_file:
        if os.path.isfile(input_file):
            in_file = open(input_file)
            message = in_file.read()
            nonce = re.findall(r'^(.?)', message)[0]
            message = re.findall('^.(.+)', message)[0]
            in_file.close()
            rnum = 1
            crypto()
            if output_file:
                out_file = open(output_file, 'w')
                out_file.write(message)
                out_file.close()
            else:
                print("Decrypted Message:")
                print()
                print(message)
                print()
            if verbose:
                print("Decryption complete.")
        else:
            print("No such file as", input_file)
            exit(1)
    else:
        print("You must either enter a message (-m) or specify a input file (-i).")
        exit(1)

def main():
    """ The primary function for the program, calls the variables function then
    decides whether to call the encrypt or the decrypt function."""
    variables()
    global encrypt
    global decrypt
    if encrypt:
        encrypt_func()
    elif decrypt:
        decrypt_func()
    else: 
        print("You must specify if encryption (-e) or decryption (-d) should be used.")
        exit(1)

main()