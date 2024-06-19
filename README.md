# DNS_Sockets
18.06.2024
Am accesat site-urile:
 https://w3.cs.jmu.edu/kirkpams/OpenCSF/Books/csf/html/UDPSockets.html 
 https://www.digi.com/resources/documentation/digidocs/90002219/tasks/t_dns_lookup.htm?TocPath=Socket%20examples%7CDNS%20lookup%7C_____0
 https://www.infoblox.com/dns-security-resource-center/dns-security-faq/is-dns-tcp-or-udp-port-53/
 https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-works-on-tcp-and-udp
 si am facut research legat de modul de functionare DNS, cele doua strategii(iterativa si recursiva), structura si cod pentru implementare.

 19.06.2024
 Am folosit Wireshark pentru a vizualiza modul de transmitere a pachetelor si structura acestora.(ex: comanda host mta.ro si m-am uitat pe Wireshark).
 Am testat comenzile host,dig,nslookup si am citit despre optiunile pe care acestea le pun la dispozitie, precum si modul in care afiseaza informatia obtinuta.
 Am vazut pe Wireshark protocolul de retea NTP si m-am documentat despre acesta.
 Am citit din documentul RFC-1035 detaliile si specificatiile pentru a putea implementa DNS in conformitate.(structurile).
 Am implementat structurile pentru a putea lucra cu ele si urmeaza sa implementez functiile pentru impachetare, conversie, realizarea interogarii DNS.
 Am implementat un info care explica ce face si cum trebuie folosit.
