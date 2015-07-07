import time

from operator import add, sub


class LibCryptographer(object):

    MAX_UNICODE = 65535
    verbose = 0
    function = "encrypt"

    def set_verbosity(this, v):
        """ Set the verbosity level. 0 is none, 2 is highest and
        will print out the most debug information """
        this.verbose = v

    def set_function(this, f):
        """ Set whether we should operate in encrypt or decrypt mode.
        Encrypt is the default. """
        this.function = f

    def generate_nonce(this):
        """ Uses the current time to generate a unique nonce """
        return chr(int(time.time() * 10000000) % this.MAX_UNICODE)

    def hash_pass(this, password, keylength):
        """ The password is hashed to ensure that the resulting hashed password
        will meet the keylength requirements given by the user. This allows the
        user to have a secure key without having to remember a long password."""
        if this.verbose == 2:
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
            p = p + chr(((n0 ** n1) ** n2) % this.MAX_UNICODE + 48)
        password = p[:int(keylength)]
        if this.verbose == 2:
            print("Hashed password: " + password)
        this.password = password
        return password

    def phase1_crypto(this, nonce, rnum, message, function):
        """ Phase 1 encrypts every character in the message by shifting it
        through the UTF-8 alphabet by a number derived from the character of
        the hashed password for the current round and the nonce."""
        encrypted_message = ""
        for index, letter in enumerate(message):
            offset = int(ord(this.password[index % \
                     (this.password.index('') - 1)])) * ord(nonce)
            if function == "encrypt":
                encrypted_char = chr(int(ord(letter) + offset) % this.MAX_UNICODE)
            elif function == "decrypt":
                encrypted_char = chr(int(ord(letter) - offset) % this.MAX_UNICODE)
            encrypted_message = encrypted_message + encrypted_char
        message = encrypted_message
        if this.verbose == 2:
            print("Round " + str(rnum) + "-- Phase 1: " + message)
        return message

    def phase2(this, password, message, rnonce, rnum,
               decrypt=False, encrypt_idx=5):
        """ Phase 2 encrypts every fifth character in the message, starting with
        the one in the position of the round number modulus 5, by shifting it by
        a number derived from the round number, nonce, and the ordinal position of
        the current round's character from the hashed password devided by the
        length of the password."""

        start_char = rnum % encrypt_idx
        pass_char = ord(password[rnum])
        pass_place = int(pass_char / len(password))
        shift = pass_place * rnonce

        def translate(char):
            operation = sub if decrypt else add
            result = operation(ord(char), shift)
            return chr(result % this.MAX_UNICODE)

        return ''.join(char if i % encrypt_idx
                       else translate(char)
                       for i, char in enumerate(message, start_char))

    def perform_rounds(this, nonce, message, function):
        """ This is the core encryption/decryption algorithm, it performs a
        series of rounds of the phase1 and phase2 functions to encypher the
        text. """
        for rnum, char in enumerate(this.password):
            message = this.phase1_crypto(nonce, rnum, message, function)
            rnonce = rnum * ord(nonce)
            decrypt = True if function == "decrypt" else False
            message = this.phase2(this.password, message, rnonce, rnum, decrypt)
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100, "% Complete.")
        return message
