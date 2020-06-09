/*
   See my original code for credits.
   
   This asks a web server (on Unix or NT) if it is running services
   that are known to be exploitable. If it finds them it tells you,
   but it won't exploit them. I updated this so it looks for some new
   holes in diffrent types of web servers, and new web server that are
   coming out on the market.
   
   To complie:
   luser$ gcc cgiscan.c -o cgiscan
   To use:
   luser$ ./cgiscan somedomain.com   (i.e. ./cgiscan antionline.com)
   
   coded by Bronc Buster 
   Jan 1999  
   Updated Feb 1999
*/

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/nameser.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#define MAX_SIZE 24  /* make this the size of temp[] if you change it */

int main(int argc, char *argv[])
{
 int s;
 struct in_addr addr;
 struct sockaddr_in victem;
 struct hostent *bad;
 char foundmsg[] = "200";
 char *cgistr;
 char buffer[1024];
 char cgibuff[1024]; 
 int num,i=0;
 char *temp[MAX_SIZE];    
 char *name[MAX_SIZE]; 

 temp[1] = "GET /cgi-bin/phf HTTP/1.0\n\n";
 temp[2] = "GET /cgi-bin/Count.cgi HTTP/1.0\n\n";
 temp[3] = "GET /cgi-bin/test-cgi HTTP/1.0\n\n";
 temp[4] = "GET /cgi-bin/php.cgi HTTP/1.0\n\n";
 temp[5] = "GET /cgi-bin/handler HTTP/1.0\n\n";
 temp[6] = "GET /cgi-bin/webgais HTTP/1.0\n\n";
 temp[7] = "GET /cgi-bin/websendmail HTTP/1.0\n\n";
 temp[8] = "GET /cgi-bin/webdist.cgi HTTP/1.0\n\n";
 temp[9] = "GET /cgi-bin/faxsurvey HTTP/1.0\n\n";
 temp[10] = "GET /cgi-bin/htmlscript HTTP/1.0\n\n";
 temp[11] = "GET /cgi-bin/pfdispaly.cgi HTTP/1.0\n\n";
 temp[12] = "GET /cgi-bin/perl.exe HTTP/1.0\n\n";
 temp[13] = "GET /cgi-bin/wwwboard.pl HTTP/1.0\n\n";
 temp[14] = "GET /cgi-bin/www-sql HTTP/1.0\n\n";
 temp[15] = "GET /_vti_pvt/service.pwd HTTP/1.0\n\n";
 temp[16] = "GET /_vti_pvt/users.pwd HTTP/1.0\n\n";
 temp[17] = "GET /cgi-bin/aglimpse HTTP/1.0\n\n";
 temp[18] = "GET /cgi-bin/man.sh HTTP/1.0\n\n";
 temp[19] = "GET /cgi-bin/view-source HTTP/1.0\n\n";
 temp[20] = "GET /cgi-bin/campas HTTP/1.0\n\n";
 temp[21] = "GET /cgi-bin/nph-test-cgi HTTP/1.0\n\n";
 temp[22] = "GET /cgi-dos/args.bat HTTP/1.0\n\n";
 temp[23] = "GET /cgi-win/uploader.exe HTTP/1.0\n\n";

 name[1] = "phf";
 name[2] = "Count.cgi";
 name[3] = "test-cgi";
 name[4] = "php.cgi";
 name[5] = "handler";
 name[6] = "webgais";
 name[7] = "websendmail";
 name[8] = "webdist.cgi";
 name[9] = "faxsurvey";
 name[10] = "htmlscript";
 name[11] = "pfdisplay";
 name[12] = "perl.exe";
 name[13] = "wwwboard.pl";
 name[14] = "www-sql";
 name[15] = "service.pwd";
 name[16] = "users.pwd";
 name[17] = "aglimpse";
 name[18] = "man.sh";
 name[19] = "view-source";
 name[20] = "campas";
 name[21] = "nph-test-cgi";
 name[22] = "args.bat";
 name[23] = "uploader.exe";

 if (argc!=2)
   {
   exit(printf("\nUsage : %s domain.com\n ",argv[0])); 
   }
 if ((bad=gethostbyname(argv[1])) == NULL)
   {
   exit(printf("Error getting hostname"));
   }

printf("New web server hole and info scanner for elite kode kiddies\n");
printf("coded by Bronc Buster - Updated Feb 1999\n");

system("sleep 2");

s=socket(AF_INET, SOCK_STREAM, 0);
 if(s<0) exit(printf("Socket error"));
bcopy(bad->h_addr, (char *)&victem.sin_addr, bad->h_length);
victem.sin_family=AF_INET;
victem.sin_port=htons(80);

if (connect(s, (struct sockaddr*)&victem, sizeof(victem))<0)
  {
  exit(printf("Connect error"));
  }
printf("\nGetting HTTP version\n\n");
send(s, "HEAD / HTTP/1.0\n\n",17,0);
recv(s, buffer, sizeof(buffer),0);
printf("Version:\n%s",buffer);

close(s); 
system("sleep 2");
   
while(i++ < MAX_SIZE)   
  {
  s=socket(AF_INET, SOCK_STREAM, 0);
  bcopy(bad->h_addr, (char *)&victem.sin_addr, bad->h_length);
  victem.sin_family=AF_INET;
  victem.sin_port=htons(80);
  if (connect(s, (struct sockaddr*)&victem, sizeof(victem))<0)
    {
    exit(printf("Connect error"));
    }
  printf("Searching for %s : ",name[i]);
  for(num=0; num<1024; num++)
      {
      cgibuff[num] = '\0';
      } 
  
   send(s, temp[i],strlen(temp[i]),0);
   recv(s, cgibuff, sizeof(cgibuff),0);
   cgistr = strstr(cgibuff,foundmsg);
   if(cgistr != NULL)
       printf(" * * Found * * \n");
   else
       printf(". . Not Found . .\n");
      
   close(s);
   }
return 0;
 }
/* EOF */

/*
   Fryz, Prophet, Snupe, MostHateD - you are the lamest fucks
   on this planet.

   b4b0 - I still have them pics of you guys in a gay orgy you sent me,
   please stop sending them.
*/

