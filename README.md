# Network Analyzer

## Utilisation

    make
    ./analyzer -i interface | -o capture_file -f filter -v verbosity

`-i` is for live capture, and /home/iamoric/Téléchargements/imap.pcap is for offline capture. Do not use both at the same time. 
`-v` is the verbosity. Verbosity must be between 1 (low) and 3 (high). Default value is 3 (high). Use `-f` to apply a filter.

## Supported protocols

* [x] ETHERNET
* [x] ARP           
* [x] IP v4         
* [x] TCP
* [x] UDP
* [x] BOOTP
* [x] DHCP
* [x] DNS
* [x] HTTP(S)
* [x] FTP
* [x] SMTP(S)
* [x] POP3
* [x] IMAP
* [x] Telnet


## TODO

* [x] arp : Sender ip
* [x] arp : Target ip
* [ ] ip :  fragment offset
* [x] tcp : options
* [x] main : filters
* [x] main : verbosity
* [x] dhcp : make function for print ip addresses
* [x] dhcp : verbosity medium & low
* [x] http : header
* [x] telnet : check negotiation option
* [x] telnet : verbosity medium & low
* [x] telnet : check indentation data
* [x] ftp request : verbosity low
* [x] add comments