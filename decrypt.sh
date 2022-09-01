#!/bin/bash

set -euo pipefail

infile=$1

# Note, output is to stdout but that can be redirected to a file
exec openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in ${infile}