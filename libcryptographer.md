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
        print(password) #Debug

        """" Creates a numeric_key with the value of the length of the password
        plus two."""
        numeric_key = len(password) + 2
        print(numeric_key) #Debug

        """ While the length of the numeric key is smaller than the integer
        value of the keylength flag set by the user, iterate over the password
        to use the ordinal values of each character, along with the current
        numeric_key and the length of the password, to increase the value
        of the numeric_key."""
        while len(str(numeric_key)) < (int(keylength)):
            for place in password:
                numeric_key = numeric_key * ((len(password) + 2) ** ord(place))
                print(t1) #Debug

        """ Convert the numeric_key integer into a str then break it into sets
        of three to be interated over to create three integers, the first of
        which is raised by the power of the second, then the product of that
        is raised by the power of the third. The product of that operation is
        modulo by 55000 to keep it within the Unicode range then increased by 48
        avoid the special characters at the beginning of the alphabet. The
        resulting character is appended to the hashed_pass variable."""
        hashed_pass = ""
        for three_set in zip(*[iter(str(numeric_key))] * 3):
            print(i) #Debug
            n0 = int(i[0]) + 2
            print(n0) #Debug
            n1 = int(i[1]) + 2
            print(n1) #Debug
            n2 = int(i[2]) + 2
            print(n0) #Debug
            hashed_pass = hashed_pass + chr(((n0 ** n1) ** n2) % 55000 + 48)
            print(p) #Debug
        """ Truncates the hashed_pass 
        password = hashed_pass[:int(keylength)]
        print(password) #Debug
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
