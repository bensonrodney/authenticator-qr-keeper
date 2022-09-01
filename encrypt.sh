#!/bin/bash

set -euo pipefail

infile=$1
outfile=$2

exec openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in ${infile} -out ${outfile}