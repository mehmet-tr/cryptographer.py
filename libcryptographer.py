#! /usr/bin/env python3

import time
from operator import add, sub

class LibCryptographer(object):
    MAX_UNICODE = 65534
    verbose = 0
    function = "encrypt"

    def set_verbosity(this, v):
        this.verbose = v

    def set_function(this, f):
        this.function = f

    def generate_nonce(this):
        return chr(int(time.time() * 10000000) % this.MAX_UNICODE)

    def hash_pass(this, password, keylength):
        if this.verbose == 2:
            print("Unhashed password: " + password)
        numeric_key = len(password) + 2
        while len(str(numeric_key)) < (int(keylength)):
            for place in password:
                numeric_key = numeric_key * ((len(password) + 2) ** ord(place))
        hashed_pass = ""
        for three_set in zip(*[iter(str(numeric_key))] * 3):
            n0 = int(three_set[0]) + 2
            n1 = int(three_set[1]) + 2
            n2 = int(three_set[2]) + 2
            n_char = chr(((n0 ** n1) ** n2) % this.MAX_UNICODE + 48)
            hashed_pass = hashed_pass + n_char
        password = hashed_pass[:int(keylength)]
        if this.verbose == 2:
            print("Hashed password: " + password)
        this.password = password
        return password

    def perform_rounds(this, nonce, message, function):
        decrypt = True if function == "decrypt" else False
        encrypt_idx = 5
        operation = sub if decrypt else add
        rnonce = 0
        pass_place = 0
        for rnum in enumerate(this.password):
            rnonce = rnum[0] * ord(nonce)
            start_char = rnum[0] % encrypt_idx
            pass_char = ord(this.password[rnum[0]])
            pass_place = int(pass_char / len(this.password))

            def phase1(index, char):
                shift = int(ord(this.password[index % \
                         (this.password.index('') - 1)])) * ord(nonce)
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)

            def phase2(char):
                shift = pass_place * rnonce
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)

            return ''.join(phase1(index, char) if index % encrypt_idx
                          else phase2(phase1(index, char))
                          for index, char in enumerate(message, start_char))

            if this.verbose > 0:
                print((rnum[0] / len(this.password)) * 100, "% Complete.")
                if this.verbose == 2:
                    print("Round " + str(rnum[0]) + ": " + message)
        return message