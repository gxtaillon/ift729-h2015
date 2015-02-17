/*
    IFT729 - H2015
    Guillaume Xavier Taillon
    Francis Gravel Saint-Pierre
    Systeme d'authentification résistant aux attaques par force brute et déni
        de service non distribué
    
    Depend des paquets hemorraging-edge suivants (qui a leur tour ne peuvent
        tourner que sur un kernel >=3.14).
      + libnftnl0
      + libnftnl-dev
      + nftables

    Le serveur d'authentification n'a rien de bien compliqué. Il peux 
        cependant, celon le comportement d'un client modifier les regles des
        filtres reseaux a l'aide de la librairie libnftnl.
*/
#define _GNU_SOURCE
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <pthread.h>

void logerr() {
	int errnum = errno;
	errno = 0;
    
	if (errnum > 0) {
		printf("Oops. \nError code: %i\nError description: %s\n",
				errnum, strerror(errnum));
	} else if (h_errno > 0) {
		printf("Oops.\nError code: %i\nError description: %s\n",
				h_errno, hstrerror(h_errno));
 
		h_errno = 0;
	} else {
		printf("Opps.\n There is no error data.\n");
	}
}

void logStuff(const char* action) {
    printf("%s\n", action);
}

#define mkLog(cond, msg) logStuff((msg)); if ((cond)) { logerr(); return; }
#define mkLogReturn(cond, msg, val) logStuff((msg)); if ((cond)) { logerr(); return (val); }
#define mkLogContinue(cond, msg) logStuff((msg)); if ((cond)) { logerr(); }
 
struct sockaddr_in getipa(const char*, int);
void printerror(const char*);
 
void* runclient(void*);
void* runserver(void*);
 
int main(){
	pthread_t server;
	pthread_t client;
 
	if(pthread_create(&server, NULL, runserver, NULL) != 0){
		puts("Echec de la creation du thread serveur");
 
		return EXIT_FAILURE;
	}
 
	if(pthread_create(&client, NULL, runclient, NULL) != 0){
		puts("Echec de la creation du thread client");
 
		return EXIT_FAILURE;
	}
 
	pthread_join(server, NULL);
	pthread_join(client, NULL);
 
	return EXIT_SUCCESS;
}
 
struct sockaddr_in getipa(const char* hostname, int port){
	struct sockaddr_in ipa;
	ipa.sin_family = AF_INET;
	ipa.sin_port = htons(port);
 
	struct hostent* localhost = gethostbyname(hostname);
	mkLogReturn(
	    !localhost,
		"Resolution de localhost",
		ipa);
 
	char* addr = localhost->h_addr_list[0];
	memcpy(&ipa.sin_addr.s_addr, addr, sizeof addr);
 
	return ipa;
}

 
void* runserver(void* context){
	struct protoent* tcp;
	tcp = getprotobyname("tcp");
 
	int sfd = socket(PF_INET, SOCK_STREAM, tcp->p_proto);
	mkLog(
	    sfd == -1,
	    "S: Creation du socket tcp");
	
	struct sockaddr_in isa = getipa("localhost", 1025);
 
	mkLog(
	    bind(sfd, (struct sockaddr*)&isa, sizeof isa) == -1,
		"S: Liaison du socket a l'adresse IP");
 
	mkLog(
	    listen(sfd, 1) == -1,
		"S: Reglage du socket en mode ecoute");
 
	int cfd = accept(sfd, NULL, NULL);
 
    mkLog(
        cfd == -1,
        "S: Accordement d'une connexion");
 
	char msg[] = "Ne se cassons pas le béssic.";
 
	mkLogContinue(
	    send(cfd, (void*) msg, sizeof msg, MSG_NOSIGNAL) == -1,
		"S: Transmission du message au client");
 
	shutdown(cfd, SHUT_RDWR);
 
	return NULL;
}
 
void* runclient(void* context){
	struct protoent* tcp;
	tcp = getprotobyname("tcp");
 
	int sfd = socket(PF_INET, SOCK_STREAM, tcp->p_proto);
	mkLog(
	    sfd == -1,
	    "C: Creation du socket tcp");
 
	struct sockaddr_in isa = getipa("localhost", 1025);
 
	mkLog(
	    connect(sfd, (struct sockaddr*)&isa, sizeof isa) == -1,
		"C: Connexion au serveur");
 
	char buff[255];
	ssize_t size = recv(sfd, (void*)buff, sizeof buff, MSG_WAITALL);
 
	mkLog(
	    size == -1,
		"C: Reception des donnees du serveur");
	
	buff[size] = '\0';
 
	puts(buff);
 
	shutdown(sfd, SHUT_RDWR);
 
	return NULL;
}

        
