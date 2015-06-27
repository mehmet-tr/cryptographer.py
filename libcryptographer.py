import time

verbose = 0

def set_verbosity(v):
    """ Set the verbosity level. 0 is none, 2 is highest and will print out the most debug information """
    verbose = v

def generate_nonce():
    """ Uses the current time to generate a unique nonce """
    return chr(int(time.time() * 10000000) % 55000)

def hash_pass(password, keylength):
    """ The password is hashed to ensure that the resulting hashed password
    will meet the keylength requirements given by the user. This allows the
    user to have a secure key without having to remember a long password."""
    if verbose == 2:
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
    if verbose == 2:
        print("Hashed password: " + password)
    return password
