#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#define DNS_PORT 53
#define BUFFER_SIZE 512

void print_info();

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
    }
    if(argc==2)
    {

    }
    if(strcmp(argv[1],"info")==0 && argc==3)
    {
        print_info();
    }
    else if(strcmp(argv[1],"-x")==0 && argc==3)
    {
        
    }
    else if(strcmp(argv[1],"MX")==0 && argc==3)
    {

    }
    else if(strcmp(argv[1],"ANY")==0 && argc==3)
    {

    }
    else if(strcmp(argv[1],"AAAA")==0 && argc==3)
    {

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
    printf(" ./source ANY domain_name\n");
    printf(" ./source AAAA domain_name\n");
}