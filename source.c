#include "dns.h"

void print_info();
void dns_lookup (unsigned char* , int,char*);
void reverse_dns_lookup(unsigned char*);
void change_dns_format_name(unsigned char*,unsigned char*);
unsigned char* read_name(unsigned char*,unsigned char*,int*);
void add_edns_section(unsigned char*,int* );


int main( int argc , char *argv[])
{
    char dns_server[16];
    strcpy(dns_server,"8.8.8.8"); //Google DNS Server
    dns_server[strlen(dns_server)]='\0';

	if(argc==1)
    {
        printf("No argument. Please write the argument(name domain) or 'info' to see the options and the syntax.\n");
        return 0;
    }

    if(argc==2)
    {
        if(strcmp(argv[1],"info")==0)
        {
            print_info();
        }
        else
        {
            dns_lookup(argv[1], 1,dns_server); // default type A- IPv4
        }
    }

    else if(argc==3)
    {
        if(strcmp(argv[1],"-x")==0)
        {
            reverse_dns_lookup(argv[2]);
        }
         else if(strcmp(argv[1],"MX")==0)
        {
            dns_lookup(argv[2],15,dns_server); //mail server
        }
        else if(strcmp(argv[1],"AAAA")==0)
        {
            dns_lookup(argv[2], 28,dns_server); // IPv6 address
        }
        else
        {
            strcpy(dns_server,argv[2]+1);
            dns_server[strlen(dns_server)]='\0';
            dns_lookup(argv[1],1,dns_server);
        }
    }
    else if(argc==4)
    {
        strcpy(dns_server,argv[3]+1);
        dns_server[strlen(dns_server)]='\0';

        if(strcmp(argv[1],"MX")==0)
        {
            dns_lookup(argv[2],15,dns_server); //mail server
        }
        else if(strcmp(argv[1],"AAAA")==0)
        {
           dns_lookup(argv[2], 28,dns_server); // IPv6 address
        }
    }
    else
    {
        printf("Incorrect syntax or wrong spelling.\n");
    }
   return 0; 
}

void add_edns_section(unsigned char *buf, int *offset) 
{
    struct EDNS *edns = (struct EDNS *)&buf[*offset];
    edns->name = 0;
    edns->type = htons(41);
    edns->udp_payload_size = htons(EDNS_PAYLOAD_SIZE);
    edns->extended_rcode = 0;
    edns->edns_version = 0;
    edns->z = 0;
    edns->data_length = htons(CLIENT_COOKIE_LEN + 4); 

    struct COOKIE_OPTION *cookie_option = (struct COOKIE_OPTION *)edns->data;
    cookie_option->option_code = htons(COOKIE_OPTION_CODE);
    cookie_option->option_length = htons(CLIENT_COOKIE_LEN);
    
    // generate random code
    for (int i = 0; i < CLIENT_COOKIE_LEN; i++) 
    {
        cookie_option->client_cookie[i] = rand() % 256;
    }

    *offset += sizeof(struct EDNS) + CLIENT_COOKIE_LEN + 4;
}

void print_info()
{
    printf("DNS lookup utility\n");
    printf("\n");
    printf("It performs DNS lookups and displays the answers that are returned from the name server that were queried.\n");
    printf("\n");
    printf("Options are: \n");
    printf(" ./source domain_name\n");
    printf(" ./source domain_name @dns_server\n");
    printf(" ./source -x ip_address(IPv4): This option sets simplified reverse  lookups,  for  mapping  addresses  to names\n");
    printf(" ./source MX domain_name : Mail exchange binding, lists hosts willing to accept mail for <mail-domain>\n");
    printf(" ./source MX domain_name @dns_server\n");
    printf(" ./source AAAA domain_name : matches domain name to IPv6 address\n");
    printf(" ./source AAAA domain_name @dns_server\n");
}

void change_dns_format_name(unsigned char * dns, unsigned char* host)
{
    strcat((char*)host, ".");
    int pos=0;
    for(int i=0;i<strlen((char*)host);i++)
    {
        if(host[i]=='.')
        {
           *dns++ = i - pos;
            for(int j=pos;j<i;j++)
            {
                *dns++=host[j];
                pos++;
            }
            pos++;
        }
    }
     *dns++='\0'; //3www3mta2ro
}

void dns_lookup(unsigned char *host , int query_type, char* dns_server)
{
	unsigned char buf[BUFFER_SIZE],*name,*reader;
	int socket_fd;

	struct sockaddr_in dest;
    struct sockaddr_in address;


	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server; RFC 1035 says that they are RRs(resource records)

	socket_fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	//AF_INET-IPv4

	dest.sin_family = AF_INET;
	dest.sin_port = htons(DNS_PORT);
	dest.sin_addr.s_addr = inet_addr(dns_server);

	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //query
	dns->opcode = 0; //standard query
	dns->aa = 0; //not authoritative
	dns->tc = 0; //not truncated
	dns->rd = 1; //recursion desired
	dns->ra = 0; //recursion not available
	dns->z = 0;
	dns->ad = 1;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = htons(1);

	name =(unsigned char*)&buf[sizeof(struct DNS_HEADER)]; ////point to after the location of dns header

	change_dns_format_name(name , host);

	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1)];

	qinfo->qtype = htons( query_type ); // type specified by the argument
	qinfo->qclass = htons(1); //clasa IN(internet)

    int offset = sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1) + sizeof(struct QUESTION);
    add_edns_section(buf, &offset); //to remain modified

	if( sendto(socket_fd,(char*)buf,offset,0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		printf("Failed to send\n");
	}
	
	int dest_len = sizeof dest;

	if(recvfrom (socket_fd,(char*)buf ,BUFFER_SIZE , 0 , (struct sockaddr*)&dest , (socklen_t*)&dest_len ) < 0)
	{
		printf("Failed to receive");
	}

    dns = (struct DNS_HEADER*) buf;

	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name)+1) + sizeof(struct QUESTION)]; //move ahead of the dns header,name and the query field

    //read answers
    int stop=0;

    for(int i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=(unsigned char*)malloc(1000);
        answers[i].name=read_name(reader,buf,&stop);

        reader = reader + stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader=reader+sizeof(struct R_DATA);

        if(ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

            for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);

        }
        else if (ntohs(answers[i].resource->type) == 15) // MX record
        {
            // MX record has a preference value followed by the mail exchange domain name
            unsigned short preference = ntohs(*((unsigned short*)reader));
            reader += 2;

            unsigned char* mx_name = (unsigned char*)malloc(2000);
            mx_name=read_name(reader, buf, &stop);

            char preference_str[6];
            sprintf(preference_str, "%d", preference);

            answers[i].rdata = (unsigned char*)malloc(2 + strlen((char*)mx_name)+2); // allocate memory for preference, space, mx_name, and null terminator
            sprintf((char*)answers[i].rdata, "%s %s", preference_str, mx_name);
            free(mx_name);

            reader += (ntohs(answers[i].resource->data_len) - 2);

        } 
        else if (ntohs(answers[i].resource->type) == 28) // AAAA record //ex. google.com
        { 
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
            memcpy(answers[i].rdata, reader, ntohs(answers[i].resource->data_len));
            reader += ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata=(unsigned char*)malloc(1000);
            answers[i].rdata = read_name(reader,buf,&stop);
			reader = reader + stop;
        }

    }

    
    // read authorities
    for (int i = 0; i < ntohs(dns->auth_count); i++) 
    {
        auth[i].name=(unsigned char*)malloc(1000);
        auth[i].name = read_name(reader, buf, &stop);
        reader += stop;
        auth[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);
        auth[i].rdata=(unsigned char*)malloc(1000);
        auth[i].rdata = read_name(reader, buf, &stop);
        reader += stop;
    }

    //read additional
/*     for(int i=0;i<ntohs(dns->add_count);i++)
	{
        addit[i].name=(unsigned char*)malloc(1000);
		addit[i].name=read_name(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1) //IPv4
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(int j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
            addit[i].rdata=(unsigned char*)malloc(1000);
			addit[i].rdata=read_name(reader,buf,&stop);
			reader+=stop;
		}
	} */

    //print answers
    printf("->>HEADER<<-\tID : %d\tOPCODE : %d\t",ntohs(dns->id),ntohs(dns->opcode));
    if(dns->rcode==0)
        printf("STATUS : NO ERROR\n");
    printf("FLAGS: ");
    if(dns->qr==1)
        printf("qr ");
    if (dns->rd==1)
        printf("rd ");
    if(dns->ra==1)
        printf("ra\t");

    printf("\nANSWERS: %d \n" , ntohs(dns->ans_count) );
    printf("AUTHORITY: %d \n" , ntohs(dns->auth_count) );
    printf("ADDITIONAL: %d\n",ntohs(dns->add_count));

	for(int i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("\nANSWER SECTION\n");
        printf("Name : %s ",answers[i].name);

        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
		{
            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, answers[i].rdata, ipv4, INET_ADDRSTRLEN);
			printf("has IPv4 address : %s",ipv4);
		}
		
		if(ntohs(answers[i].resource->type)==5) //canonical name
		{
			printf("has alias name : %s",answers[i].rdata);
		}

        if (ntohs(answers[i].resource->type) == 15) // MX record
        {
            printf("has MX record : %s", answers[i].rdata);
        }


        if (ntohs(answers[i].resource->type) == 28) // MX record
        {
            char ipv6[INET6_ADDRSTRLEN]; //constant INET6... to store IPv6 address in text format with a minimum size
            inet_ntop(AF_INET6, answers[i].rdata, ipv6, INET6_ADDRSTRLEN);//convert from binary to text IP addresses, AF_INET6=IPv6,
            printf("has IPv6 address: %s", ipv6);
        }


		printf("\n");
    }

    for(int i=0;i<ntohs(dns->auth_count);i++)
    {
        printf("\nAUTHORITY SECTION\n");
        printf("Name : %s\t",auth[i].name);

        if(ntohs(auth[i].resource->type)==6) //SOA for IPv6
		{
			//SOA=start of authority zone
			printf("%d\t%s\t%s\t%s\n",ntohs(auth[i].resource->type),"IN","SOA",auth[i].rdata);
		}
    }
}

void reverse_dns_lookup(unsigned char *ip_address) 
{
    unsigned char buf[BUFFER_SIZE], *name, *reader;
    int socket_fd;
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    struct RES_RECORD answers[20]; //RFC 1035

    char reverse_ip[256];
    int a, b, c, d;

    sscanf((char*)ip_address, "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(reverse_ip, sizeof(reverse_ip), "%d.%d.%d.%d.in-addr.arpa", d, c, b, a);

    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        perror("socket");
        return;
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google's DNS server

    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0; // query
    dns->opcode = 0; // standard query
    dns->aa = 0; // not authoritative
    dns->tc = 0; // not truncated
    dns->rd = 1; // recursion desired
    dns->ra = 0; // recursion not available
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    name = (unsigned char*)&buf[sizeof(struct DNS_HEADER)]; //point to the start of the buffer
    change_dns_format_name(name, (unsigned char*)reverse_ip); //format name in order to send it

    qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1)];
    qinfo->qtype = htons(12); // PTR query(a domain name pointer)
    qinfo->qclass = htons(1); // IN (internet)

    if (sendto(socket_fd, (char*)buf, sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1) + sizeof(struct QUESTION), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        printf("Failed to send\n");
        close(socket_fd);
        return;
    }

    int dest_len = sizeof(dest);
    if (recvfrom(socket_fd, (char*)buf, BUFFER_SIZE, 0, (struct sockaddr*)&dest, (socklen_t*)&dest_len) < 0) {
        printf("Failed to receive\n");
        close(socket_fd);
        return;
    }

    dns = (struct DNS_HEADER*)buf;
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1) + sizeof(struct QUESTION)]; //the answer,after dns_header,name and question

    printf("->>HEADER<<-\tID : %d\tOPCODE : %d\t", ntohs(dns->id), dns->opcode);
    if (dns->rcode == 0) {
        printf("STATUS : NO ERROR\n");
    } else {
        printf("STATUS : ERROR\n");
    }

    printf("FLAGS: ");
    if (dns->qr == 1) printf("qr ");
    if (dns->rd == 1) printf("rd ");
    if (dns->ra == 1) printf("ra\t");

    printf("\nQUESTIONS: %d \n", ntohs(dns->q_count));
    printf("ANSWERS: %d \n", ntohs(dns->ans_count));
    printf("AUTHORITY: %d \n", ntohs(dns->auth_count));
    printf("ADDITIONAL: %d\n", ntohs(dns->add_count));

    int stop;
    for (int i = 0; i < ntohs(dns->ans_count); i++) {
        answers[i].name = read_name(reader, buf, &stop);
        reader += stop;
        answers[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 12) // PTR record
        {
            answers[i].rdata = read_name(reader, buf, &stop);
            reader += stop;
        } else 
        {
            answers[i].rdata = read_name(reader, buf, &stop);
            reader += stop;
        }
    }

    for (int i = 0; i < ntohs(dns->ans_count); i++) 
    {
        printf("\nANSWER SECTION\n");
        printf("Name: %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == 12) { // PTR record
            printf("has PTR record: %s", answers[i].rdata);
        }

        printf("\n");
    }

    close(socket_fd);
}

unsigned char* read_name(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;

    *count = 1;

    name = (unsigned char*)malloc(256);

    name[0]='\0';

    while(*reader!=0) //till we arrived to the end of the codified name
    {
        if(*reader>=192) //check if compression label; used for compression label(uses 2 bytes to refer to the location  of the already used name and points to the location)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //0b11000000xxxxxxxx 
            //*reader =11000000 in the first 2 bits and the rest 6 bits for the offset -the first octet
            //*reader+1 =the second octet
            //*reader*256 =left shift with 8 bits
            //49152=11000000 00000000
            //ex:*reader=192, *reader+1=12=>192*256=49152; 49152+12=49164; 49164-49152=12(the real offset)=>pos 12 in buffer

            reader = buffer + offset - 1;

            jumped = 1; //jumped to another location
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
		{
			*count = *count + 1; //we havent jumped to another location so we can add to the count
		}
    }

    name[p]='\0';

    if(jumped==1)
	{
		*count = *count + 1; 
	}

    int i;
    int contor=0;

    unsigned char* new_name;
    new_name = (unsigned char*)malloc(1000);
    new_name[0] = '\0';

    for (i = 0; i < strlen((const char*)name); i++)
	{
		p = name[i];
		for (int j = 0; j < p; j++)
		{
			new_name[contor] = name[i + 1];
			i = i + 1;
			contor++;
		}
		new_name[contor] = '.';
		contor++;
	}
	new_name[contor-1] = '\0';

    free(name);
	return new_name;
}