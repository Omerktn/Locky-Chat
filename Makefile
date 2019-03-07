all: server client

server: server.o aes_enc.o
	gcc server.o aes_enc.o -o server -pthread -lcrypto -lm

client: client.o aes_enc.o
	gcc client.o aes_enc.o -o client -pthread -lcrypto -lm

server.o: server.c
	gcc -c server.c

client.o: client.c
	gcc -c client.c

aes_enc.o: aes_enc.c
	gcc -c aes_enc.c

clean:
	rm *.o output
