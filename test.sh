python3 cryptographer.py -e -p password1 -k 50 -i t/t1 -o t/t1.enc
python3 cryptographer.py -e -p pass123321132 -k 64 -i t/t2 -o t/t2.enc
python3 cryptographer.py -e -p thisisapassword -k 400 -i t/t3 -o t/t3.enc

python3 cryptographer.py -d -p password1 -k 50 -i t/t1.enc -o t/t1.dec
python3 cryptographer.py -d -p pass123321132 -k 64 -i t/t2.enc -o t/t2.dec
python3 cryptographer.py -d -p thisisapassword -k 400 -i t/t3.enc -o t/t3.dec

echo "performing diff test"
diff t/t1 t/t1.dec 
diff t/t2 t/t2.dec 
diff t/t3 t/t3.dec 
