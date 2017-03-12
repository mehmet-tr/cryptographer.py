# chat_client.py

import sys, socket, select, re
import libcryptographer

def chat_client():
    if(len(sys.argv) < 3) :
        print('Usage : python chat_client.py hostname port')
        sys.exit()
        
    crypt = libcryptographer.LibCryptographer()

    host = sys.argv[1]
    port = int(sys.argv[2])
    name = input('Enter your name: ')
    passphrase = input('Enter the passphrase: ')
    keylength = input('Enter the keylenth ')
    crypt.hash_pass(passphrase, keylength)
    username_regex = r"\[\w*\] .*"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    # connect to remote host
    try :
        s.connect((host, port))
    except :
        print('Unable to connect')
        sys.exit()

    print('Connected to remote host. You can start sending messages')
    sys.stdout.write('[' + name + '] '); sys.stdout.flush()

    while 1:
        socket_list = [sys.stdin, s]

        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            if sock == s:
                # incoming message from remote server, s
                data = sock.recv(4096)
                data = data.decode('utf-8')
                nonce = data[0]
                msg = data[1:]
                msg = crypt.perform_rounds(nonce, msg, 'decrypt')
                if not data:
                    print('\nDisconnected from chat server')
                    sys.exit()
                else:
                    if re.search(username_regex, msg):
                        sys.stdout.write('\n' + msg); sys.stdout.flush()
                        sys.stdout.write('[' + name + '] '); sys.stdout.flush()

            else :
                # user entered a message
                msg = sys.stdin.readline()
                msg = '[' + name + '] ' + msg
                nonce = crypt.generate_nonce()
                msg = crypt.perform_rounds(nonce, msg, 'encrypt')
                msg = str(nonce)+msg
                msg = msg.encode('utf-8')
                s.send(msg)
                sys.stdout.write('[' + name + '] '); sys.stdout.flush()

if __name__ == "__main__":

    sys.exit(chat_client())
