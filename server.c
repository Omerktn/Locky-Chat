#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include "aes_enc.h"

#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define WHT   "\x1B[37m"
#define RES "\x1B[0m"

void error(const char *msg) {
  perror(msg);
  exit(1);
}

typedef struct {
  int fd;
  char* buffer;
}sockInfo;

void *readClient(void *vargp) {
    sockInfo *myInfo = vargp;
    int n, newsockfd = myInfo->fd;
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
    n = read(newsockfd, buffer, 255);
    if (n < 0) {
      error("Error while reading.\n");
    }

    strcpy(cip_info->ciphertext, buffer);
    cip_info->ciphertext_len = strlen(buffer);

    strcpy(buffer, dec(info, cip_info));


    //printf("Length of buffer: %zu\n",strlen(buffer));
    if (strlen(buffer) > 0) {
      printf(YEL ">Client >> %s",buffer);
    }
  }
  return NULL;
}


int main(int argc, char *argv[])
{
  srand(time(NULL));
  if (argc < 2) {
    fprintf(stderr, "Port number not provided.\n");
    exit(1);
  }
  int sockfd, newsockfd, portno, n;
  char buffer[255];

  struct sockaddr_in serv_addr, cli_addr;
  socklen_t clilen;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    error("Error while opening Socket.\n");
  }

  bzero((char *) &serv_addr, sizeof(serv_addr));
  portno = atoi(argv[1]);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
  {
    error("Binding failed.\n");
  }

  listen(sockfd, 4);
  clilen = sizeof(cli_addr);

  newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
  if (newsockfd < 0)
  {
    error("Error while accepting.\n");
  }
  else {
    printf("Success!\n");
  }

  pthread_t thread_id;
  sockInfo *sinfo = malloc(sizeof *sinfo);
  sinfo->fd = newsockfd;
  sinfo->buffer = buffer;

  pthread_create(&thread_id, NULL, readClient, sinfo);

  // encryption
  KEYINFO *info = (KEYINFO*) malloc (sizeof(KEYINFO));
  info->key = (unsigned char *) malloc(32*sizeof(unsigned char));
  info->iv = (unsigned char *) malloc(16*sizeof(unsigned char));
  strcpy(info->key,"01234567890123456789012345678901");
  strcpy(info->iv,"0123456789012345");
  CIPINFO *cip_info = (CIPINFO*) malloc (sizeof(CIPINFO));

  while(1)
  {
    bzero(buffer,255);
    printf(RES);
    fgets(buffer, 255, stdin);

    cip_info = enc(info,buffer);

    n = write(newsockfd, cip_info->ciphertext, cip_info->ciphertext_len);
    if (n < 0) {
      error("Error while writing.\n");
    }

  }

  close(newsockfd);
  close(sockfd);
  return 0;

}
