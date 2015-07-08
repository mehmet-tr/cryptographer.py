#! /bin/bash

python3 cryptographer.py -e -p pass -k 10 -i test -o test.encrypted || exit 1
test $(md5sum test| cut -f 1 -d ' ') != $(md5sum test.encrypted | cut -f 1 -d ' ') || exit 1
python3 cryptographer.py -d -p pass -k 10 -i test.encrypted -o test.decrypted || exit 1
test $(md5sum test| cut -f 1 -d ' ') = $(md5sum test.decrypted | cut -f 1 -d ' ') || exit 1

rm test.encrypted
rm test.decrypted
echo 'Build successful!'
