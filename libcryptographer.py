import time
from operator import add, sub
"""This library depends on the time and operator modules. Time is used
to generate the nonce (explained in the 'generate_nonce' function.
add and sub are used depending on whether the library is encrypting
or decrypting."""

class LibCryptographer(object):
    """The LibCryptographer is a module for other python programs
    wishing to encrypt/decrypt using the cryptographer algorythm."""
    MAX_UNICODE = 55000
    verbose = 0
    function = "encrypt"

    def set_verbosity(this, v):
        """Set the verbosity level to 0, 1, or 2. Verbosity 2 will
        reveal sensitive information and should not be used except
        in testing."""
        this.verbose = v

    def set_function(this, f):
        """Set whether to encrypt or decrypt."""
        this.function = f

    def generate_nonce(this):
        """Come up with the nonce, 'always' different character stop
        replay attacks, based on time and the Unicode."""
        return chr(int(time.time() * 10000000) % this.MAX_UNICODE)

    def hash_pass(this, password, keylength):
        """The hash function takes the password provided by the user
        and hashes it until it is at least as long as the key length
        then truncates it to the key length. This ensure a long enough
        encryption key to fully encrypt messages."""
        if this.verbose == 2:
            print("Unhashed password: " + password)
        magic_offset = 2  # Ensures that even a one character password
                          # will be long enough to hash.
        unicode_offset = 48 # Avoids the first 48 characters of Unicode
                            # because there be monsters there.
        numeric_key = len(password) + magic_offset  # Uses the length of
                                                    # the password and
                                                    # magic_offset to
                                                    # come up with a
                                                    # base key to hash.
        while len(str(numeric_key)) < (int(keylength)):
            """This loop ensures that the numeric key is at least we long
            as the prescribed key length by looping through the
            password and multiplying itself by itself raised to the
            power of the numeric value of the character at each place
            in the password."""
            for place in password:
                numeric_key = numeric_key * (numeric_key ** ord(place))
        hashed_pass = ""
        for three_set in zip(*[iter(str(numeric_key))] * 3):
            n0 = int(three_set[0]) + magic_offset
            n1 = int(three_set[1]) + magic_offset
            n2 = int(three_set[2]) + magic_offset
            hashed_pass = hashed_pass + chr(((n0 ** n1) ** n2) % this.MAX_UNICODE + unicode_offset)
        password = hashed_pass[:int(keylength)]
        if this.verbose == 2:
            print("Hashed password: " + password)
        this.password = password
        return password

    def perform_rounds(this, nonce, message, function):
        """This function is the heart of the program and operates in two
        phases. The function will apply the two phase encryption
        multiple times. Each time both phases are applied is called a
        round. The number of rounds is decided by the length of the
        hashed password."""
        decrypt = True if function == "decrypt" else False
        encrypt_idx=5
        operation = sub if decrypt else add
        rnum = 0
        for char in this.password:
            rnonce = rnum * ord(nonce)
            start_char = rnum % encrypt_idx
            pass_char = ord(this.password[rnum])
            pass_place = int(pass_char / len(this.password))

            def phase1(index, char):
                """Phase 1 encrypts every character in the message by
                shifting it through the UTF-8 alphabet by a number
                derived from modulus of the product of the ordinal
                place of the character of the hashed password which
                corresponds to the location of the letter being
                encrypted (when the password is repeated to be as long
                as the text) and product of the nonce multiplied by the
                round number with the Unicode character set."""
                shift = int(ord(this.password[index % \
                        (len(this.password) - 1)])) * ord(nonce)
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)

            def phase2(char):
                """Phase 2 encrypts every fifth character in the
                message, starting with the one in the position of the
                round number modulus 5, by shifting it by a number
                derived from the round number, nonce, and the ordinal
                position of the current round's character from the
                hashed password divided by the length of the
                password."""
                shift = pass_place * rnonce
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)

            message = ''.join(phase1(index, char) 
                      if index % encrypt_idx == 0
                      else phase2(phase1(index, char))
                      for index, char in enumerate(message, start_char))
                          
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100 % 100, "% Complete.")
                if this.verbose == 2:
                      print("Round " + str(rnum) + ": " + message)
            rnum += 1
        return message
