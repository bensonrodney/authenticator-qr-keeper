#!/bin/bash

infile="./plaintext_source"
encrypted_file="./encrypted"
decrypted_file="./plaintext_decrypted"

cat <<EOF > ${infile}
Some random data in
a basic text file used

as source data for this encryption/decryption PoC.

End of file.
EOF

echo -n "Password: "
read -s password
echo

# encrypt - some reading suggest you should also add '-salt' option but I believe -pbkdf2 does
# that anyway. See https://en.wikipedia.org/wiki/PBKDF2
echo ${password} | openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in ${infile} -out ${encrypted_file} -pass stdin
# The line below is the same but outputs the base64 encoded output to stdout
#echo ${password} | openssl aes-256-cbc -pbkdf2 -salt -in ${infile} -pass stdin | openssl base64

# decrypt
echo ${password} | openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in ${encrypted_file} -out ${decrypted_file} -pass stdin

# For python decoding of the encrypted file, see the long answer down the bottom of the linke
# below that describes the openssl bash commands and then the python equivalents of decrypting
# that data but for the files we've created with commands above, ignore the base64 decoding as
# the files aren't base64 encoded.
# https://stackoverflow.com/questions/16761458/how-to-decrypt-openssl-aes-encrypted-files-in-python
sha256sum ./*