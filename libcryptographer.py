import time

class LibCryptographer(object):
    verbose = 0
    function = "encrypt"

    def set_verbosity(this, v):
        this.verbose = v

    def set_function(this, f):
        this.function = f

    def generate_nonce(this):
        return chr(int(time.time() * 10000000) % 55000)

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
            hashed_pass = hashed_pass + chr(((n0 ** n1) ** n2) % 55000 + 48)
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
                encrypted_char = chr(int(ord(letter) + offset) % 55000)
            elif function == "decrypt":
                encrypted_char = chr(int(ord(letter) - offset) % 55000)
            encrypted_message = encrypted_message + encrypted_char
        message = encrypted_message
        if this.verbose == 2:
            print("Round " + str(rnum) + "-- Phase 1: " + message)
        return message

    def phase2_crypto(this, nonce, rnum, message, char, function):
        rnonce = rnum * ord(nonce)
        encrypted_message = ""
        for index, letter in enumerate(message):
            if index % 5 == rnum % 5:
                pass_place = int(ord(char) / len(this.password))
                if function == "encrypt":
                    encrypted_char = chr((ord(letter) \
                                     + (pass_place * rnonce)) % 55000)
                elif function == "decrypt":
                    encrypted_char = chr((ord(letter) \
                                     - (pass_place * rnonce)) % 55000)
                encrypted_message = encrypted_message + encrypted_char
            else:
                encrypted_message = encrypted_message + letter
        message = encrypted_message
        if this.verbose == 2:
            print("Round " + str(rnum) + "-- Phase 2: " + message)
        return message

    def perform_rounds(this, nonce, message, function):
        for rnum, char in enumerate(this.password):
            message = this.phase1_crypto(nonce, rnum, message, function)
            message = this.phase2_crypto(nonce, rnum, message, char, function)
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100, "% Complete.")
        return message