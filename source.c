#include<stdio.h>	
#include<string.h>	
#include<stdlib.h>	
#include<sys/socket.h>	
#include<arpa/inet.h>	
#include<netinet/in.h>
#include<unistd.h>	

#define DNS_PORT 53
#define BUFFER_SIZE 512

void print_info();
void dns_lookup (unsigned char* , int);
void change_dns_format_name(unsigned char*,unsigned char*);
unsigned char* read_name(unsigned char*,unsigned char*,int*);

struct DNS_HEADER
{
	uint16_t id; //id to match up

	unsigned char rd :1; //recursion desidered
	unsigned char tc :1; //truncated or not
	unsigned char aa :1; //bit-specifies that the responding name server is an authority for the domain name in question section.
	unsigned char opcode :4; //4 bit field-what kind of query
	unsigned char qr :1; //bit field-just a bit to specify if it is query(0) or response(1)

	unsigned char rcode :4; //for responses(errors, format errors,name errrors, etc)
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; //must be 0 in all queries and responses, for future use
	unsigned char ra :1; // recursion available

	uint16_t q_count; // number of question entries
	uint16_t ans_count; // number of answer entries
	uint16_t auth_count; // number of authority entries
	uint16_t add_count; // number of resource entries
};

struct QUESTION
{
	uint16_t qtype; //type of query
	uint16_t qclass; //class of query
};

#pragma pack(push, 1)
struct R_DATA
{
	uint16_t type;
	uint16_t _class;
	uint32_t ttl;
	uint16_t data_len;
};
#pragma pack(pop)

struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

struct QUERY
{
    unsigned char* name;
    struct QUESTION* question;
};

int main( int argc , char *argv[])
{
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
            dns_lookup(argv[1], 1); // default type A
        }
    }
    else if(argc==3)
    {
        if(strcmp(argv[1],"-x")==0)
        {

        }
         else if(strcmp(argv[1],"MX")==0)
        {
            dns_lookup(argv[2],15); //mail server
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

void dns_lookup(unsigned char *host , int query_type)
{
	unsigned char buf[BUFFER_SIZE],*name,*reader;
	int socket_fd;

	struct sockaddr_in dest;
    struct sockaddr_in address;


	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

	socket_fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	//AF_INET-IPv4

	dest.sin_family = AF_INET;
	dest.sin_port = htons(DNS_PORT);
	dest.sin_addr.s_addr = inet_addr("8.8.8.8"); //dns servers

	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //query
	dns->opcode = 0; //standard query
	dns->aa = 0; //not authoritative
	dns->tc = 0; //not truncated
	dns->rd = 1; //recursion desired
	dns->ra = 0; //recursion not available
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	name =(unsigned char*)&buf[sizeof(struct DNS_HEADER)]; ////point to after the location of dns header

	change_dns_format_name(name , host);

	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1)];

	qinfo->qtype = htons( query_type ); // type specified by the argument
	qinfo->qclass = htons(1); //clasa IN(internet)

	if( sendto(socket_fd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)name)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		printf("Failed to send\n");
	}
	
	int dest_len = sizeof dest;

	if(recvfrom (socket_fd,(char*)buf , 512 , 0 , (struct sockaddr*)&dest , (socklen_t*)&dest_len ) < 0)
	{
		printf("Failed to receive");
	}

    dns = (struct DNS_HEADER*) buf;

	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name)+1) + sizeof(struct QUESTION)]; //move ahead of the dns header,name and the query field

    //read answers
    int stop=0;

    for(int i=0;i<ntohs(dns->ans_count);i++)
    {
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
        else
        {
            answers[i].rdata = read_name(reader,buf,&stop);
			reader = reader + stop;
        }

    }

    //read authorities
    for(int i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=read_name(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=read_name(reader,buf,&stop);
		reader+=stop;
	}

    //read additional
    for(int i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=read_name(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(int j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=read_name(reader,buf,&stop);
			reader+=stop;
		}
	}

    //print answers
    printf("->>HEADER<<-\tID : %d\tOPCODE : %d\t",dns->id,dns->opcode);
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
        printf("Name : %s ",answers[i].name);

        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			address.sin_addr.s_addr=(*p); //transform from binary form to string the address
			printf("has IPv4 address : %s",inet_ntoa(address.sin_addr));
		}
		
		if(ntohs(answers[i].resource->type)==5) 
		{
			//canonical name
			printf("has alias name : %s",answers[i].rdata);
		}

		printf("\n");
    }

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
    new_name = (unsigned char*)malloc(256);
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