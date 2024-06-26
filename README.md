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

 20.06.2024
 Am continuat de scris cod si am implementat o parte din functia dns_lookup care primeste ca argumente numele de domeniu si tipul in functie de optiunea dorita de utilizator. Am declarat un file descriptor pentru socket cu care sa lucrez pe parcurs pentru trimitea cererii DNS. Am populat structura serverului DNS(Google Public DNS) si am creat o structura DNS_HEADER pe care am populat-o pentru a crea cererea DNS a utilizatorului. In variabila buffer retin la inceputul acesteia dns-ul, apoi in continuare retin numele de domeniu in formatul DNS, iar dupa numele de domeniu, retin in continuare informatiile despre interogare(question_info):type-ul=tipul specificat in argument in functie de optiunea utilizatorului si class-ul=IN(Internet.)Trimit cererea DNS si verific daca trimiterea acesteia a avut loc cu succes,altfel afisez un mesaj de eroare si inchid socket-ul.In continuare, primesc raspunsul DNS pe care urmeaza sa il parsez.

 21.06.2024
 Am scris in continuare cod pentru implementarea functiei de dns_lookup si m-am documentat despre modul de transmitere in retea a socketului(buffer-ul care contine informatiile necesare(dns header, name, question info)):htons, ntohs. Incerc sa rezolv problema la primirea pachetului, deoarece nu il primesc. 

25.06.2024
Am rezolvat problema cu primirea pachetului.
Am terminat de implementat dns pentru adrese IPv4 si am creat si functia de read_name, care formateaza numele domeniului primit ca raspuns pentru a-l putea afisa.Am citit raspunsul primit, authorities(daca exista),additional(daca exista), iar dupa aceea le-am afisat. Am citit si am aflat despre compression label si modul in care functioneaza si astfel am aflat formula pentru a afla offsetul unde se afla in buffer name domain-ul.

26.06.2024
Am implementat dns lookup utility using sockets in continuare pentru Mail Exchange(MX), adrese IPv6 si inverse queries(este data o adresa IPv4 si este returnat domain name-ul.)Am construit functia reverse_dns_lookup, care este asemanatoare cu cea dns_lookup, doar ca am formatat reverse ip-ul si am utilizat pentru question type-ul care se afla in question info valoarea 12 care semnifica PTR query(a domain name pointer).Am afisat informatia din pachetul primit.Am testat tot ce am implementat.