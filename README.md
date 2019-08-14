# Network Analyzer

## Utilisation

    make
    ./analyzer -i interface | -o capture_file -f filter -v verbosity

`-i` is for live capture, and -o is for offline capture. Do not use both at the same time. 
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
* [ ] check free -f


## Author

* [**Lucas Pierrat**](https://github.com/iAmoric) - [contact](mailto:lucas.pierrat@etu.unistra.fr) 

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/iAmoric/Network-Analyzer/blob/master/LICENSE.md) file for details
