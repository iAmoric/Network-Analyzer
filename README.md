# Network Analyzer

## Utilisation

    make
    ./analyzer -i interface | -o capture_file -f filter -v verbosity

`-i` is for live capture, and `-o` is for offline capture. Do not use both at the same time
`-v` is the verbosity. Verbosity is between 1 (low) and 3 (high)

## Implented protocols

* [x] ETHERNET
* [x] ARP           
* [x] IP v4         
* [ ] TCP          
* [ ] UDP
* [ ] BOOTP
* [ ] DHCP
* [ ] DNS
* [ ] HTTPS
* [ ] FTP
* [ ] SMTP
* [ ] POP3
* [ ] IMAP
* [ ] Telnet
* [ ] SCTP


## TODO

* [ ] arp : Sender ip
* [ ] arp : Target ip
* [ ] ip :  fragment offset
* [ ] tcp : options
* [ ] main : filters
* [ ] main : verbosity
