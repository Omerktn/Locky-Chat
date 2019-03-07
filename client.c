#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include "aes_enc.h"
// argv[2]: server_IP, argv[3]: port number

#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define WHT   "\x1B[37m"
#define RES "\x1B[0m"

void error(const char *msg)
{
  perror(msg);
  exit(1);
}

typedef struct {
  int fd;
  char* buffer;
}sockInfo;

void *readServer(void *vargp) {
  sockInfo *myInfo = vargp;
  int n, sockfd = myInfo->fd;
  char *buffer = myInfo->buffer;

  // decryption
  KEYINFO *info = (KEYINFO*) malloc (sizeof(KEYINFO));
  info->key = (unsigned char *) malloc(32*sizeof(unsigned char));
  info->iv = (unsigned char *) malloc(16*sizeof(unsigned char));
  strcpy(info->key,"01234567890123456789012345678901");
  strcpy(info->iv,"0123456789012345");

  CIPINFO *cip_info = (CIPINFO*) malloc (sizeof(CIPINFO));

  while(1) {
  bzero(buffer,255);
  n = read(sockfd, buffer, 255);
  if (n < 0)
    error("Error while reading.\n");

  strcpy(cip_info->ciphertext, buffer);
  cip_info->ciphertext_len = strlen(buffer);

  strcpy(buffer, dec(info, cip_info));

  if (strlen(buffer) > 0) {
    printf(YEL ">Server >> %s",buffer);
    }
  }
  return NULL;
}


int main(int argc, char *argv[])
{
  int sockfd, portno, n;
  struct sockaddr_in serv_addr;
  struct hostent *server;

  char buffer[255];
  if (argc < 3) {
    fprintf(stderr, "usage %s hostname port\n", argv[0]);
    exit(1);
  }

  portno = atoi(argv[2]);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0)
    error("ERROR openin socket.\n");

  server = gethostbyname(argv[1]);
  if (server == NULL)
    fprintf(stderr, "Error, no such host\n");

  bzero((char*) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char*) server->h_addr, (char*) &serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons(portno); // host to network
  if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    error("Connection failed.\n");



  pthread_t thread_id;
  sockInfo *sinfo = malloc(sizeof *sinfo);
  sinfo->fd = sockfd;
  sinfo->buffer = buffer;

  pthread_create(&thread_id, NULL, readServer, sinfo);

  // encryption
  KEYINFO *info = (KEYINFO*) malloc (sizeof(KEYINFO));
  info->key = (unsigned char *) malloc(32*sizeof(unsigned char));
  info->iv = (unsigned char *) malloc(16*sizeof(unsigned char));
  strcpy(info->key,"01234567890123456789012345678901");
  strcpy(info->iv,"0123456789012345");
  CIPINFO *cip_info = (CIPINFO*) malloc (sizeof(CIPINFO));

  while(1)
  {
    bzero(buffer, 255);
    printf(RES);
    fgets(buffer, 255, stdin);

    cip_info = enc(info,buffer);

    n = write(sockfd, cip_info->ciphertext, cip_info->ciphertext_len);
    if (n < 0)
      error("Error while writing.\n");
  }

  close(sockfd);
  return 0;

}
