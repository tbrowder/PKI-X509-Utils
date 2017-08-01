#!/bin/bash

if [[ -z $1 ]] ; then
  echo "Usage: $0 go"
  echo 
  echo "Uses openssl to convert the pem files to text for testing the Perl 6 program."
  echo
  exit
fi

CERTS="*cert*pem cri*.pem"
CSRS="csr*pem"
RKEYS="rsa*key*pem"
DKEYS="dsa*key*pem"
DERS="*der"


for f in $CERTS
do
  echo "Working cert file '$f'..."
  openssl x509 -in $f -text -noout > $f.ascii
done

for f in $CSRS
do
  echo "Working csr file '$f'..."
  openssl req -text -noout -verify -in $f > $f.ascii
done

for f in $RKEYS
do
  echo "Working rsa key file '$f'..."
  openssl rsa -in $f -check > $f.ascii
done

for f in $DKEYS
do
  echo "Working dsa key file '$f'..."
  openssl dsa -in $f -check > $f.ascii
done

echo "Debug exit"
exit

for f in $DERS
do
  echo "Working der file '$f'..."
  openssl x509 -inform -in $f -out $f.pem.txt
done

