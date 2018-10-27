/* Bad way to call shell command */

#include <unistd.h>
#include <sys/types.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int checkport(int portno, char * hostname) {
    usleep(1000000);
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return 0;
    }
 
    server = gethostbyname(hostname);
 
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
 
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
 
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        printf("Port is closed");
        return 0;
    } else {
        printf("Port is active");
        return 1;
    }
 
    close(sockfd);
    return 0;
}

int main() {
	pid_t pid = fork();
	printf("%d\n",pid);
	if(pid == 0) {
        printf("%d\n", checkport(5001, "localhost"));
		while(!checkport(5001, "localhost")){
            printf("%d\n", checkport(5001, "localhost"));
        }
		char *args[] = {"firefox", "localhost:5001", NULL};
		execv("/usr/bin/firefox", args);
		exit(1);
	} else {
		// Temporary implementation
        system("gnome-terminal -e \"/home/$USER/.raiden/raiden-quick\"");
		exit(1);
	}
}
