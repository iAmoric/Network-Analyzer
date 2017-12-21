# Network Analyzer

## Utilisation

    make
    ./analyzer -i interface | -o capture_file -f filter -v verbosity

`-i` is for live capture, and `-o` is for offline capture. Do not use both at the same time
`-v` is the verbosity. Verbosity is between 1 (low) and 3 (high)

## Implemented protocols

* [x] ETHERNET
* [x] ARP           
* [x] IP v4         
* [x] TCP          
* [X] UDP
* [x] BOOTP
* [x] DHCP
* [ ] DNS
* [X] HTTP(S)
* [x] FTP
* [x] SMTP(S)
* [x] POP3
* [x] IMAP
* [ ] Telnet


## TODO

* [x] arp : Sender ip
* [x] arp : Target ip
* [ ] ip :  fragment offset
* [x] tcp : options
* [x] main : filters
* [x] main : verbosity
* [x] dhcp : make function for print ip addresses
* [x] dhcp : verbosity medium & low
* [x] http : entete
