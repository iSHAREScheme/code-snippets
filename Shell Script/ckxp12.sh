#!/bin/sh
#############################################################################
#   Shell script which accepts p12 file and extracts following files        #
#   <p12filename>pub.pem - having just the public cert                      #
#   <p12filename>pubfc.pem - full chain of public cert                      #
#   <p12filename>priv.key - unencrypted private RSA key                     #
#                                                                           #
#   Note: the above files are created in current directory                  #
#                                                                           #
#   Version 1.0                                                             #
#   Developed by: Rajiv Rajani                             #
#   Disclaimer: Please handle private keys with care and securely,          #
#   author is not responsible in any way for any damage caused              #
#                                                                           #
#############################################################################

#capture arg
PKCSFL=$1

#check if arg provided
if [[ $PKCSFL == "" ]]; then
    printf "Usage: ckxp12 <p12 file>\n\n"
    exit 1
fi

#check if file exists
if [ ! -f $PKCSFL ]; then
    printf "File $PKCSFL does not exist. Please check and try again.\n"
fi

#extract file base name
filename="${PKCSFL##*/}"
extension="${filename##*.}"
filename="${filename%.*}"

#check if openssl is installed
if ! command -v openssl &> /dev/null
then
    printf "openssl not installed. please install it first.\n"
    exit
fi

#get p12 file password
printf "Enter p12 password: "
read -s p12pass

printf "\n"

p12pass="pass:"$p12pass
#extract pem (public key certificate) and RSA private key
pubfilename=$filename"pub.pem"
fcfilename=$filename"pubfc.pem"
privfilename=$filename"priv.key"

openssl pkcs12 -in $PKCSFL -clcerts -nokeys -passin $p12pass -out $pubfilename
if [ -f $pubfilename ]; then
    printf "$pubfilename successfully created.\n"
fi

openssl pkcs12 -in $PKCSFL -nokeys -passin $p12pass -out $fcfilename
if [ -f $fcfilename ]; then
    printf "$fcfilename successfully created.\n"
fi

openssl pkcs12 -in $PKCSFL -nocerts -nodes -passin $p12pass | openssl rsa > $privfilename
if [ -f $privfilename ]; then
    printf "$privfilename successfully created.\n"
fi

printf "Files can be found in current directory.\n"

#end