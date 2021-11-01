# Scanner
## To run
```sh
$ python3 scanner.py xxxx.pcap
```
## Description
1. Detect ARP Spoofing attempts
    - Filter out ARP response packet and report if the ARP response is not consistent with the data given from the assignment description.
2. Detect Port Scans
    - Filter out TCP SYN and UDP packets, organize them by destination ip and port, report if exceed the threshold.
3. Detect TCP SYN floods
    - Record all SYN packets and record all SYN-ACK packets that have a corresponding SYN. If we see an ACK packet that has a matching SYN and SYN-ACK, remove them from the store. Finally, use the sliding window trick on the remaining SYN packets to see if there are too many SYN packets in a second.