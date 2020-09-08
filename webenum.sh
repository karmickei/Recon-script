#!/bin/bash


echo "Gathering subdomains with Certspoter.."
curl -s https://certspoter/com/api/v0/certs\?domains\=$1 | jq '.[].dns_names[]' | sed 's/\''//g' | sed 's/\*\.//g' | sort -u | grep $1 >> all.txt


echo "Gathering subdomains with crtsh..."
cur -s https://crt.sh/?q=%.$1 | sed 's/<\/\?[^>]\+>//g' | grep $1 | sort -u >> all.txt


