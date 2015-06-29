import time

class LibCryptographer(object):
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
        return chr(int(time.time() * 10000000) % 55000)
    
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
            p = p + chr(((n0 ** n1) ** n2) % 55000 + 48)
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
                encrypted_char = chr(int(ord(letter) + offset) % 55000)
            elif function == "decrypt":
                encrypted_char = chr(int(ord(letter) - offset) % 55000)
            encrypted_message = encrypted_message + encrypted_char
        message = encrypted_message
        if this.verbose == 2:
            print("Round " + str(rnum) + "-- Phase 1: " + message)
        return message

    def phase2_crypto(this, nonce, rnum, message, char, function):
        """ Phase 2 encrypts every fifth character in the message, starting with
        the one in the position of the round number modulus 5, by shifting it by
        a number derived from the round number, nonce, and the ordinal position 
        of the current round's character from the hashed password devided by 
        the length of the password."""
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
        """ This is the core encryption/decryption algorithm, it performs a 
        series of rounds of the phase1 and phase2 functions to encypher the 
        text. """
        for rnum, char in enumerate(this.password):
            message = this.phase1_crypto(nonce, rnum, message, function)
            message = this.phase2_crypto(nonce, rnum, message, char, function)
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100, "% Complete.")
        return message
