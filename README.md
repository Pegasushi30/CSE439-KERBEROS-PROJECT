***********************************************************************************************
                                       DESIGN EXPLANATION
***********************************************************************************************                             
  This project facilitates user authentication to access services from servers. Upon correct
credentials verification, users receive a Ticket Granting Ticket (TGT) from the server. Using
this TGT, a user can request a ticket from the server, enabling them to access the requested
services.

  Both client and server sides are designed to securely transmit login credentials using RSA
symmetric key encryption. During user authentication, the server compares the provided
credentials with data stored in an SQLite3 database. If there is a match, authentication is
granted; otherwise, it is denied. Once authenticated, a user can request a TGT, and with this
TGT, they can request a ticket from the server to access the requested services. The user retains
access to the requested services until the ticket expires. These operations can be performed
within a single server using FastAPI, SQLAlchemy, and the datetime library. Additionally, an
authenticated user can request the current timestamp from the server and receive a response.
If a user has an admin role, they have the additional capability to update the server's secret key
used for encrypting tickets. The server possesses three keys: two RSA keys, which are private
and public RSA keys serving for symmetric encryption, and another private key used by the
server for encrypting tickets. An admin user has the authority to update this key for ticket
encryption.
***********************************************************************************************
                                      SEQUENCE DIAGRAM

![image](https://github.com/Pegasushi30/CSE439-KERBEROS-PROJECT/assets/121224269/f90e499e-402e-49e0-8494-4f4a4e372904)


