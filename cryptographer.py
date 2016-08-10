#!/usr/bin/env python3

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
        verbose = int(arguments.verbose)
    else:
        verbose = 0
    return function, message, output_file, verbose, password, keylength


def main(arguments):
    function, message, output_file, verbose, password, keylength = \
        variables(arguments)

    crypt = libcryptographer.LibCryptographer()
    crypt.set_verbosity(verbose)
    crypt.set_function(function)

    if function == "encrypt":
        nonce = crypt.generate_nonce()
    elif function == "decrypt":
        nonce = message[0]
        message = message[1:]

    crypt.hash_pass(password, keylength)
    message = crypt.perform_rounds(nonce, message, function)

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
