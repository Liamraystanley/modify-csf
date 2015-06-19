# mcsf
#### Port modification wrapper for ConfigServer Security&Firewall

## Installation

**gcc** _is required_ and so are **python headers**. They can easily be installed by using your distro package manager in most cases.

### Debian/Ubuntu based

```
$ sudo apt-get install gcc python-dev python-pip
$ sudo pip install mcsf
```

### Redhat and CentOS

```
$ sudo yum install gcc python-devel
$ wget https://bootstrap.pypa.io/get-pip.py
$ sudo python get-pip.py
$ sudo pip install mcsf
```

## Usage

**_Things to note_**: When **mcsf** makes changes to the configuration file, a backup is made with **CONFIGFILE**.backup.

### Pull up help documentation

```
$ mcsf --help
usage: __init__.py [-h] [-a ALLOW | -r REMOVE | -l] [-4 | -6] [-i | -o]
                   [-q | -v] [-p PROTOCOL] [--noheader] [--nobackup]
                   [-c CONFIGFILE] [--no-restart] [--ignore-check] [-V]

Port modification wrapper for ConfigServer Security&Firewall


optional arguments:
  -h, --help            show this help message and exit
  -a ALLOW, --allow ALLOW
                        port to add to CSF's allow list; specify range with
                        n:n
  -r REMOVE, --remove REMOVE
                        port to remove from CSF's allow list; specify range
                        with n:n
  -l, --list            list of ports, and their protocols (tcp, udp, ipv4,
                        ipv6)
  -4, --four            add/remove from IPv4 only
  -6, --six             add/remove from IPv6 only
  -i, --inbound         specify inbound when adding/removing ports
  -o, --outbound        specify outbound when adding/removing ports
  -q, --quiet           disable output
  -v, --verbose         add extra output
  -p PROTOCOL, --protocol PROTOCOL
                        dependant on the options used, targets specific
                        protocols (tcp, udp)
  --noheader            don't print header when supplying a list
  --nobackup            don't make a backup of the configuration file when
                        making modifications
  -c CONFIGFILE, --configfile CONFIGFILE
                        location to CSF configuration file
  --no-restart          location to CSF configuration file
  --ignore-check        don't check to see if CSF is installed in
                        /usr/sbin/csf
  -V, --version         version information
```

### List ports in the CSF configuration file

```
$ mcsf -l
METHOD    TYPE  PROTOCOL  PORTS                                             
------    ----  --------  -----                                             
INBOUND   TCP   IPv4      53,80,110,143,443,465,587,993,995,8080,35000:40000
OUTBOUND  TCP   IPv4      20:22,25,53,80,110,113,443,587,993,995,4309       
INBOUND   TCP   IPv6      53,80,110,143,443,465,587,993,995,8080,35000:40000
OUTBOUND  TCP   IPv6      20:22,25,53,80,110,113,443,587,993,995,4309       
INBOUND   UDP   IPv4      53,80,110,143,443,465,587,993,995,8080,35000:40000
OUTBOUND  UDP   IPv4      20,21,53,113,123                                  
INBOUND   UDP   IPv6      53,80,110,143,443,465,587,993,995,8080,35000:40000
OUTBOUND  UDP   IPv6      20,21,53,113,123
```

### Add port, inbound

```
$ mcsf -a 22 -i
Added port(s) 22.
Successfully restarted CSF.
```

### Remove port, outbound

```
mcsf -r 22 -o
Removed port(s) 22.
Successfully restarted CSF.
```

### Add port, inbound, with `tcp` as the protocol and IPv4 only

```
$ mcsf -a 22 -i -p tcp -4
Added port(s) 22.
Successfully restarted CSF.
```

## License

```
The MIT License (MIT)

Copyright (c) 2015 Liam Stanley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
