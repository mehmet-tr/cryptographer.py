#!/usr/bin/env python3
"""
Title: cryptographer.py
Author: Caleb Cooper
License: GPLv2
Version: 1.1
Version Date: 2014-01-31
Description: This program performs a two phase cryptographic function
             upon a supplied message, either inline or from a file.
             This function is repeated for a number of rounds determined
             by the length of a password supplied by the user. Once all
             of the rounds are complete, the encrypted/decrypted message
             can either be printed to standard out or written to a file.
Usage:
cryptographer.py (-e|-d) -p PASSWORD -k KEYLENGTH (-m MESSAGE | -i INPUTFILE) \
[-o OUTPUTFILE] [-v | -vv]
"""

import os
import argparse

import libcryptographer

parser = argparse.ArgumentParser()
action = parser.add_mutually_exclusive_group(required=True)
action.add_argument('-e', '--encrypt', help='For encrypting a file/message.',
                    action='store_true')
action.add_argument('-d', '--decrypt', help='For decrypting a file/message.',
                    action='store_true')
parser.add_argument('-p', '--password', required=True, help='The passphase\
                    with which to encrypt/decrypt. If more than a word, \
                    use quotes.')
parser.add_argument('-k', '--key', required=True, help='Determine key length.\
                    Suggested values between 10 and 1000, very high key \
                    lengths will take a long time.')
message = parser.add_mutually_exclusive_group(required=True)
message.add_argument('-m', '--message', help='The message to be \
                     encrypted/decrypted. Messages must be inside \
                     quotation marks.')
message.add_argument('-i', '--inputfile', help='The file to be\
                     encrypted/decrypted.')
parser.add_argument('-o', '--outputfile', help='The file in which to save the\
                    encrypted/decrypted message. If none is given, message \
                    will be printed to screen.')
parser.add_argument('-v', '--verbose', help='-v will print out the progress \
                    of the encryption as a percentage. -vv will print the \
                    progress as well as the password, hashed password, and \
                    the message at every stage of the encryption/decryption \
                    process.', action='count')
args = parser.parse_args()


def variables(arguments):
    """ Defines variables based on command line arguments. Also does some
    input checking on key length variable to ensure it is a integer and
    greater than zero."""
    if arguments.encrypt:
        function = "encrypt"
    elif arguments.decrypt:
        function = "decrypt"
    else:
        print("You must specify if encryption (-e) or decryption (-d) should\
        be used.")
        exit(1)
    password = arguments.password
    try:
        keylength = int(arguments.key)
    except ValueError:
        print("The key length must be an integer.")
        exit(1)
    if keylength < 1:
        print("The key length must be greater than 0")
        exit(1)
    if arguments.inputfile:
        if os.path.isfile(arguments.inputfile):
            in_file = open(arguments.inputfile)
            message = in_file.read()
        else:
            print("No such file as", arguments.inputfile)
            exit(1)
    elif arguments.message:
        message = args.message
    else:
        print("Enter a message (-m) or specify a input file (-i).")
        exit(1)
    output_file = arguments.outputfile
    if args.verbose:
        verbose = arguments.verbose
    else:
        verbose = 0
    return function, message, output_file, verbose, password, keylength


def phase1_crypto(password, nonce, rnum, message, function, verbose):
    """ Phase 1 encrypts every character in the message by shifting it through
    the UTF-8 alphabet by a number derived from the character of the hashed
    password for the current round and the nonce."""
    encrypted_message = ""
    for index, letter in enumerate(message):
        offset = int(ord(password[index % (password.index('') - 1)])) * \
                 ord(nonce)
        if function == "encrypt":
            encrypted_char = chr(int(ord(letter) + offset) % 55000)
        elif function == "decrypt":
            encrypted_char = chr(int(ord(letter) - offset) % 55000)
        encrypted_message = encrypted_message + encrypted_char
    message = encrypted_message
    if verbose == 2:
        print("Round " + str(rnum) + "-- Phase 1: " + message)
    return message


def phase2_crypto(password, nonce, rnum, message, char, function, verbose):
    """ Phase 2 encrypts every fifth character in the message, starting with
    the one in the position of the round number modulus 5, by shifting it by
    a number derived from the round number, nonce, and the ordinal position of
    the current round's character from the hashed password devided by the
    length of the password."""
    rnonce = rnum * ord(nonce)
    encrypted_message = ""
    for index, letter in enumerate(message):
        if index % 5 == rnum % 5:
            pass_place = int(ord(char) / len(password))
            if function == "encrypt":
                encrypted_char = chr((ord(letter) + (pass_place * rnonce)) % 55000)
            elif function == "decrypt":
                encrypted_char = chr((ord(letter) - (pass_place * rnonce)) % 55000)
            encrypted_message = encrypted_message + encrypted_char
        else:
            encrypted_message = encrypted_message + letter
    message = encrypted_message
    if verbose == 2:
        print("Round " + str(rnum) + "-- Phase 2: " + message)
    return message



def main(arguments):
    """Performs all of the nessacerry setup and clean up to encrypt or
    decrypt a message based on the -e or -d arugments.
    Also handles writing to the output file or standard out."""
    function, message, output_file, verbose, password, keylength = \
        variables(arguments)

    libcryptographer.set_verbosity(verbose)
    
    if function == "encrypt":
        nonce = libcryptographer.generate_nonce()
    elif function == "decrypt":
        nonce = message[0]
        message = message[1:]

    password = libcryptographer.hash_pass(password, keylength)
    for rnum, char in enumerate(password):
        message = phase1_crypto(password, nonce, rnum, message, function,
                                verbose)
        message = phase2_crypto(password, nonce, rnum, message, char,
                                function, verbose)
        if verbose > 0:
            print((rnum / len(password)) * 100, "% Complete.")

    if function == "encrypt":
        message = str(nonce)+message
        operation = "En"
    elif function == "decrypt":
        operation = "De"

    if output_file:
        out_file = open(output_file, 'w')
        out_file.write(message)
        out_file.close()
    else:
        print(operation+"crypted Message:")
        print()
        print(message)
        print()
    if verbose > 0:
        print(operation+"cryption complete.")


main(args)
