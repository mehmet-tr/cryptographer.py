import time
from operator import add, sub

class LibCryptographer(object):
    MAX_UNICODE = 55000
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

    def perform_rounds(this, nonce, message, function):
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
                shift = int(ord(this.password[index % \
                        (len(this.password) - 1)])) * ord(nonce)
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)

            def phase2(char):
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
