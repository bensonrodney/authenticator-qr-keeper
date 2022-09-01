#!/bin/bash

# This script provides file encryption and decryption functions
# for use by other scripts.

function encrypt_file() {
	infile=$1
	outfile=$2
	password=$3
	echo "${password}" | openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in ${infile} -out ${outfile} -pass stdin
}

function decrypt_file() {
	infile=$1
	outfile=$2
	password=$3
	echo "${password}" | openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in ${infile} -out ${outfile} -pass stdin
}

