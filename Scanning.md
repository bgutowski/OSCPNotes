### PORTS SCANNING

```
nmap -sV -O -T4 -n -Pn -sC $RHOST --open

nmap -sV -sC -O -T4 -n -Pn -p- $RHOST --open

nmap -sV -sC -O -p- -n -Pn $RHOST

nmap -sU -sV --version-intensity 0 -F -n -T4 $RHOST

nmap -sU -sV -sC -F -n -Pn $RHOST
```

### NETWORK SCANNING

```
nmap -sL $NET

netdiscover -r $NET

nmap -sn $NET

nbtscan -r $NET
```


### FUZZING

```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$URL"

wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200,202,204,301,302,307,403 "$URL"

wfuzz -c -z file,/opt/SecLIsts/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"
```

### WORDPRESS

[HackTricks - Wordpress](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)

```
wpscan --url $URL --enumerate p --plugins-detection aggressive

curl $URL | grep 'content="WordPress'

curl -s -I -X GET $URL/?author=1

```
