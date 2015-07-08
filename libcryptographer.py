import time
from operator import add, sub

class LibCryptographer(object):
    MAX_UNICODE = 65535
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
            hashed_pass = hashed_pass + chr(((n0 ** n1) ** n2) % this.MAX_UNICODE + 48)
        password = hashed_pass[:int(keylength)]
        if this.verbose == 2:
            print("Hashed password: " + password)
        this.password = password
        return password

    def phase1_crypto(this, nonce, rnum, message, function):
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
        for rnum, char in enumerate(this.password):
            message = this.phase1_crypto(nonce, rnum, message, function)
            rnonce = rnum * ord(nonce)
            decrypt = True if function == "decrypt" else False
            message = this.phase2(this.password, message, rnonce, rnum, decrypt)
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100, "% Complete.")
        return message