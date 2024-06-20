#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h> //getpid
#include <stdint.h>
#include <stddef.h>

#define DNS_PORT 53
#define BUFFER_SIZE 512

void print_info();
void dns_lookup(const char* hostname, uint16_t query_type);
void change_dns_format_name(unsigned char * dns, unsigned char* host);

struct DNS_HEADER
{
    uint16_t ID; //id to match up
    unsigned char QR :1; //bit field-just a bit to specify if it is query(0) orresponse(1)
    unsigned char OPCODE :4; //4 bit field-what kind of query
    unsigned char AA :1; //bit-specifies that the responding name server is an authority for the domain name in question section.
    unsigned char TC :1; //truncated or not
    unsigned char RD :1; //recursion desidered
    unsigned char RA :1; //recursion available-recursive query support
    unsigned char Z :1; //must be 0 in all queries and responses, for future use
    unsigned char RCODE :4; //for responses(errors, format errors,name errrors, etc)
    uint16_t QDCOUNT; //specifies the number of resource records in the answer section.
    uint16_t ANCOUNT; //specifies the number of name server resource records in the authority records section.
    uint16_t NSCOUNT; //specifies the number of name server resource records in the authority records section.
    uint16_t ARCOUNT; //specifies the number of resource records in the additional records section
};

struct QUESTION
{
    uint16_t QTYPE; //type of query
    uint16_t QCLASS; //class of the query
};

struct RES_RECORD
{
    unsigned char* name;
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    unsigned char* rdata;
}__attribute__((packed));

struct QUERY
{
    unsigned char* name;
    struct QUESTION* question;
};

int main(int argc, char* argv[])
{  
    if(argc==1)
    {
        printf("No argument. Please write the argument(name domain) or 'info' to see the options and the syntax.\n");
        return 1;
    }
    if(argc==2)
    {
        if(strcmp(argv[1],"info")==0)
        {
            print_info();
        }
        else
        {
            dns_lookup(argv[1], 1); // Default type A
        }
    }
    else if(argc==3)
    {
        if(strcmp(argv[1],"-x")==0)
        {

        }
         else if(strcmp(argv[1],"MX")==0)
        {

        }
        else if(strcmp(argv[1],"ANY")==0)
        {

        }
        else if(strcmp(argv[1],"AAAA")==0)
        {

        }
    }
     else
    {
        printf("Incorrect syntax or wrong spelling.\n");
    }
   return 0; 
}

void print_info()
{
    printf("DNS lookup utility\n");
    printf("\n");
    printf("It performs DNS lookups and displays the answers that are returned from the name server that were queried.\n");
    printf("\n");
    printf("Options are: \n");
    printf(" ./source domain_name\n");
    printf(" ./source -x ip_address(IPv4): This option sets simplified reverse  lookups,  for  mapping  addresses  to names\n");
    printf(" ./source MX domain_name : Mail exchange binding, lists hosts willing to accept mail for <mail-domain>\n");
    printf(" ./source ANY domain_name :  returns all records for the specified domain\n");
    printf(" ./source AAAA domain_name : matches domain name to IPv6 address\n");
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
     *dns++='\0';
}

void dns_lookup(const char *hostname, uint16_t query_type)
{
    int socketfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE], *name,*reader;
    struct DNS_HEADER* dns=NULL;
    struct QUESTION* question_info=NULL;

    //create udp socket
    socketfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    //AF_INET-IPv4
    //SOCK_DGRAM-datagram socket UDP
    if(socketfd<0)
    {
        printf("Error creating socket.\n");
        exit(1);
    }

    //google public dns
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(DNS_PORT); //convert dns port(53) to big endian
    server_addr.sin_addr.s_addr=inet_addr("8.8.8.8");

    dns=(struct DNS_HEADER *)&buffer; //point to the start of the buffer
    dns->ID=(uint16_t)htons(getpid());
    dns->QR=0; //query
    dns->OPCODE=0; //standard query
    dns->AA=0; //not auth(valid in responses)
    dns->TC=0; //not trunc
    dns->RD=1; //recursive
    dns->RA-0;
    dns->Z=0;   
    dns->RCODE=0; //no error code
    dns->QDCOUNT=htons(1); // 1 questiom
    dns->ANCOUNT=0; //number of resource records in the answer section
    dns->NSCOUNT=0; //number of nameserver resource records in the authority records section
    dns->ARCOUNT=0; //number of resource records in the additional records section

    name=&buffer[sizeof(struct DNS_HEADER)]; //point to after the location of dns header
    change_dns_format_name(name,(unsigned char*)hostname);

    question_info=(struct QUESTION*)&buffer[sizeof(struct DNS_HEADER)+strlen((const char*)name)+1];
    question_info->QCLASS=htons(1); //clasa IN(internet)
    question_info->QTYPE=htons(query_type); // type specified by the argument

    if(sendto(socketfd,buffer,sizeof(struct DNS_HEADER)+(strlen((const char*)name)+1)+sizeof(struct QUESTION),0,(struct sockaddr*)&server_addr,sizeof(server_addr))<0)
    {
        printf("Failed to send\n");
        close(socketfd);
        exit(1);
    }

    socklen_t server_addr_len = sizeof(server_addr);

    if(recvfrom(socketfd,buffer,BUFFER_SIZE,0,(struct sockaddr*)&server_addr,&server_addr_len)<0)
    {
        printf("Failed to receive\n");
        close(socketfd);
        exit(1);
    }

    
}