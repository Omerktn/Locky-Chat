# Locky-Chat
A socket programming project which allows real-time chat in terminals with AES-256 encryption.

**Cons:** The program has hardcoded KEY and IV information for the AES-256 encryption. For secure chatting, Diffie-Hellman Key Exchange needs to be implemented.

In order to compile the program
> make


First, run the server with the Port number argument
>./server 9999

Run the client with the IP and Port number arguments
>./client 127.0.0.1 9999

***And you can start chatting.***
In order to get the IP number in Linux, you can type:
> ifconfig
