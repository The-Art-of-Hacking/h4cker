# RADIUS, TACACS+, and Diameter

The following is a comparison table for the RADIUS, TACACS+, and Diameter protocols.

| Feature             | RADIUS                             | TACACS+                            | Diameter                          |
|---------------------|------------------------------------|------------------------------------|-----------------------------------|
| Transport Protocol  | UDP                                | TCP                                | TCP or SCTP                        |
| Encryption          | Only password encryption           | Full packet encryption             | Full packet encryption            |
| AAA Support         | Combined AAA (Authentication, Authorization, Accounting) | Separate AAA (Authentication, Authorization, and Accounting are distinct) | Combined AAA                      |
| Usage               | Network access, VPN authentication, etc.     | Device administration              | Mobile IP, SIP, NASREQ            |
| Standardization     | RFC 2865 & RFC 2866                | Cisco proprietary                  | RFC 6733                           |

