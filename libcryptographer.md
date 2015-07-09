#[libcryptographer.py](#libcryptographer.py "save:")

__Imports__
```python
import time
from operator import add, sub
```

__Class: LibCryptographer__
```python
class LibCryptographer(object):
    MAX_UNICODE = 65534
    verbose = 0
    function = "encrypt"
```

__Set_Verbosity__ <br \>
Set the verbosity level. 0 is none, 2 is highest and will print out the most debug information.
```python
    def set_verbosity(this, v):
        this.verbose = v
```

__Set_Function__ <br \>
Set whether we should operate in encrypt or decrypt mode.  Encrypt is the default. 
```python
    def set_function(this, f):
        this.function = f
```

__Generate_Nonce__ <br \>
Uses the current time to generate a unique nonce.
```python
    def generate_nonce(this):
        return chr(int(time.time() * 10000000) % this.MAX_UNICODE)
```

__Hash_Pass__ <br \>
The password is hashed to ensure that the resulting hashed password will meet the keylength requirements given by the user. This allows the user to have a secure key without having to remember a long password.
```python
    def hash_pass(this, password, keylength):
        if this.verbose == 2:
            print("Unhashed password: " + password)
```
Creates a numeric_key with the value of the length of the password plus two.
```python
        numeric_key = len(password) + 2
```
While the length of the numeric key is smaller than the integer value of the keylength flag set by the user, iterate over the password to use the ordinal values of each character, along with the current numeric_key and the length of the password, to increase the value of the numeric_key.
```python
        while len(str(numeric_key)) < (int(keylength)):
            for place in password:
                numeric_key = numeric_key * ((len(password) + 2) ** ord(place))
```
Convert the numeric_key integer into a str then break it into sets of three to be iterated over to create three integers, the first of which is raised by the power of the second, then the product of that is raised by the power of the third. The product of that operation is modulo by the size of the unicode alphabet (65535) to keep it within the Unicode range then increased by 48 avoid the special characters at the beginning of the alphabet. The resulting character is appended to the hashed_pass variable.
```python
        hashed_pass = ""
        for three_set in zip(*[iter(str(numeric_key))] * 3):
            n0 = int(three_set[0]) + 2
            n1 = int(three_set[1]) + 2
            n2 = int(three_set[2]) + 2
            hashed_pass = hashed_pass + chr(((n0 ** n1) ** n2) % this.MAX_UNICODE + 48)
```
Truncates the hashed_pass to the length of the keylength variable assigned by the user.
```python
        password = hashed_pass[:int(keylength)]
```
Returns the now hashed password.
```python
        if this.verbose == 2:
            print("Hashed password: " + password)
        this.password = password
        return password
```

__Phase1__ <br \>
Phase 1 encrypts every character in the message by shifting it through the UTF-8 alphabet by a number derived from modulus of the product of the ordinal place of the character of the hashed password which corresponds to the location of the letter being encrypted (when the password is repeated to be as long as the text) and product of the nonce multiplied by the round number with the Unicode character set.

A simplified example, using only the ASCII character set rather than the entire Unicode character set) of this operation for a plain text of "This is an example", a password of "mfkghhsndel", and a nonce of 5 (for this example we will assume this is the first round, therefore the round number is 1. This makes the rnonce (product of the round number and the nonce) still 5) would work as follows:

Repeat the password so that it is as long as the text. 

|T|h|i|s| |i|s| |a|n| |e|x|a|m|p|l|e|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|m|f|k|g|h|h|s|n|d|e|l|m|f|k|g|h|h|s|

Then find the numeric values of each character in the password.

|m|f|k|g|h|h|s|n|d|e|l|m|f|k|g|h|h|s|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|109|102|107|103|104|104|115|110|100|101|108|109|102|107|103|104|104|115|

Now multiply the numeric value of each letter in the text length password by the nonce (in this case, 5).

|109|102|107|103|104|104|115|110|100|101|108|109|102|107|103|104|104|115|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|545|510|535|515|520|520|575|550|500|505|540|545|510|535|515|520|520|575|

Now find the numeric values of the letters in the plain text.

|T|h|i|s| |i|s| |a|n| |e|x|a|m|p|l|e|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|84|104|105|115|32|105|115|32|97|110|32|101|120|97|109|112|108|101|

Now add the product of the numeric values of the characters in the password and the nonce with the numeric values of the characters in the plain text.

|545|510|535|515|520|520|575|550|500|505|540|545|510|535|515|520|520|575|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|84|104|105|115|32|105|115|32|97|110|32|101|120|97|109|112|108|101|
|629|614|640|630|552|625|690|582|597|615|572|646|630|632|624|632|628|676|

Then modulo the sum by size of the ASCII character set (255) to get numeric values without the ASCII range.

|629|614|640|630|552|625|690|582|597|615|572|646|630|632|624|632|628|676|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|119|104|130|120|42|115|180|72|87|105|62|136|120|122|114|122|118|166|

Finally, convert these numeric values back into ASCII characters.

|119|104|130|120|42|115|180|72|87|105|62|136|120|122|114|122|118|166|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|w|h|,|x|*|s|┤|H|W|i|>|^|x|z|r|z|v|ª|


__Phase2__ <br \>
Phase 2 encrypts every fifth character in the message, starting with the one in the position of the round number modulus 5, by shifting it by a number derived from the round number, nonce, and the ordinal position of the current round's character from the hashed password divided by the length of the password.


__Perform_Rounds__ <br \>
This is the core encryption/decryption algorithm, it performs a series of rounds of the phase1 and phase2 functions to encipher the text.
```python
    def perform_rounds(this, nonce, message, function):
        for rnum, char in enumerate(this.password):
            decrypt = True if function == "decrypt" else False
            encrypt_idx=5
            
            rnonce = rnum * ord(nonce)
            start_char = rnum % encrypt_idx
            pass_char = ord(this.password[rnum])
            pass_place = int(pass_char / len(this.password))
            shift = pass_place * rnonce
            
            def phase1(index, char):
                operation = sub if decrypt else add
                shift = int(ord(this.password[index % \
                         (this.password.index('') - 1)])) * ord(nonce)
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)
            
            def phase2(char):
                operation = sub if decrypt else add
                result = operation(ord(char), shift)
                return chr(result % this.MAX_UNICODE)
            
            return ''.join(phase1(index, char) if index % encrypt_idx
                          else phase2(phase1(index, char))
                          for index, char in enumerate(message, start_char))
            if this.verbose > 0:
                print((rnum / len(this.password)) * 100, "% Complete.")
                if this.verbose == 2:
                      print("Round " + str(rnum) + "-- Phase 2: " + message)
        return message
```
