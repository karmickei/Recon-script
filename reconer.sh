#!/bin/bash

#TOOLS NEEDED FOR THE SCAN..
#sublist3r,assetfinder, amass, shuffledns, https, nuclei, waybackurls, ffuf, gf, massdns, unfurl 


#........PATHS TO WORDLIST AND RESOLVER IPS..............
domain=$1
wordlist="/root/scripts/86a06c5dc309d08580a018c66354a056/all.txt"
resolvers="/root/scripts/resolverips.txt"
resolve_domain="/path to massdns -r /root/50resolvers.txt -t A -o 5 -w"


domain_enum(){



mkdir -p $domain/sources $domain/Recon $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan

#......PASSIVE ENUMERATOR...........

subfinder -d $domain -o $domain/sources/subfinder.txt
assetfinder -subs-only $domain | tee $domain/sources/assefinder.txt
amass enum -passive -d $domain -o $domain/sources/amass.txt

#.........ACTIVE ENUMERATION - BRUTEFORCE using resolver ips an part of (domain_enum)...........

shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt

cat $domain/sources/*.txt > $domain/sources/all.txt


}
domain_enum

#..........RESOLVER FOR DNS SERVERS,,,,,,,,,,


resolving_domains(){


shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domain.txt -r $resolvers


}
resolving_domains


#...............LOOKING FOR LIVE HTTP/HTTPS DOMAINS...........

http_probe(){


cat $domain/domains.txt | httpx -threads 300 -o $domain/Recon/httpx.txt


}
http_probe


#..........SCANING URLS INTO nuclei......

scanner(){



cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/cves.txt
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/files/ -c 50 -o $domain/Recon/nuclei/cves.txt



}
scanner

#......Fetch waybackurls....

wayback_data(){



cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt
cat $domain/Recon/wayback/tmp.txt | egrep -v "|\.png|\.jpeg|\.jpg|\.svg|\.css|\.ico|\.woff|\.ttf|\.eot|" | sed 's/:80//g;s/:443//g' | sort -u >. $domain/Recon/wayback/wayback.txt
rm $domain/Recon/wayback/tmp.txt


}
wayback_data

#.............filltering "vaild urls" from wayback data to ffuf


vaild_urls(){


fuzzer -c -u "FUZZ" -W $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/vaild-tmp.txt
cat $domain/Recon/wayback/vaild-tmp.txt| grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/vaild.txt
rm $domain/Recon/wayback/vaild-tmp.txt


}
vaild_urls

#.........gf patters..........

gf_patterns(){



gf xss $domain/Recon/wayback/vaild.txt | tee $domain/Recon/gf/xss.txt 
gf ssrf $domain/Recon/wayback/vaild.txt | tee $domain/Recon/gf/ssrf.txt
gf sqli $domain/Recon/wayback/vaild.txt | tee $domain/Recon/gf/sqli.txt


}
gf_patterns

#........Custom wordlist for enum!!...

custom_wordlist(){


cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt
cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys > $domain/Recon/wordlist/keys.txt


}
custom_wordlist

#........Resolve Domain to Ip for masscan & nmap scan....

get_ip(){

$resolve domain $domain/Recon/masscan/results.txt $domain/domains.txt
gf ip $domain/Recon/masscan/results.txt | sort -u > $domain/Recon/masscan/ip.txt


}
get_ip

