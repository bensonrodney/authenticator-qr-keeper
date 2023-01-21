#!/bin/bash

_file=$1
_make_new_file=""
tmp_dir=""

set -euo pipefail

trap clean_up SIGINT EXIT

function clean_up() {
	if [[ ! -z ${tmp_dir} ]]; then
		rm -rf ${tmp_dir}
	fi
}

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

if [[ -z ${_file// } ]]; then
	echo "No file specified. Nothing to do."
	exit 1
fi

if [[ ! -f ${_file} ]]; then
	echo -n "File doesn't exist. Create a new one? [Yn]: "
	read _new_file
	if echo ${_new_file} | grep -qE "^(y|Y|[yY][eE][sS]|)$"; then
		_make_new_file="true"
	else
		echo "Ok. Nothing to do."
		clean_up
		exit 0
	fi
fi

echo -n "Password: "
read -s _password
echo

tmp_dir=$(mktemp -d -t ee-XXXXXXXXXX)
tmp_file="${tmp_dir}/tmp-edit"

if [[ -z ${_make_new_file} ]]; then
	decrypt_file ${_file} ${tmp_file} "${_password}"
else
	touch ${tmp_file}
fi

# Edit temporary decrypted file and check for changes
_start_shasum="$(sha256sum ${tmp_file}| cut -f1 -d' ')"
$EDITOR ${tmp_file}
_end_shasum="$(sha256sum ${tmp_file}| cut -f1 -d' ')"

if [[ "${_start_shasum}" = "${_end_shasum}" ]]; then
	echo "No changes to file. Not rewriting encrypted file."
else
	if [[ -z ${_make_new_file} ]]; then
		backup_file="${_file}-backup-$(date +%Y-%m-%d-%H%M%S)"
		echo "Backing up old file to: ${backup_file}"
		cp ${_file} ${backup_file}
	fi
	encrypt_file ${tmp_file} ${_file} "${_password}"
	chmod 600 ${_file}
fi

clean_up
