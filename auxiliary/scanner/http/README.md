puppet_scanner
==============

This module scans for Puppetmaster installations and performs version fingerprinting.

* Example:

```
msf > use auxiliary/scanner/http/puppet_scanner
msf auxiliary(puppet_scanner) > set THREADS 256
THREADS => 256
msf auxiliary(puppet_scanner) > set RHOST 192.168.1.0/24
RHOST => 192.168.1.0/24
msf auxiliary(puppet_scanner) > run

[+] 192.168.1.2 - Puppetmaster < 3.3.1-rc3 running on WEBrick/1.3.1 (Ruby/1.9.3/2012-04-20) OpenSSL/1.0.1e
[+] 192.168.1.56 - Puppetmaster 3.4.2 running on WEBrick/1.3.1 (Ruby/1.8.7/2011-06-30) OpenSSL/1.0.1e
[*] Scanned 094 of 256 hosts (036% complete)
[*] Scanned 220 of 256 hosts (085% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
