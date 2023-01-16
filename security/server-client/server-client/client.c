#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define FAIL    -1
int OpenConnection(const char *hostname, int port)
{

int  sock = 0 ,client_fd;
struct  sockaddr_in serv_address;
struct hostent *h;
if ( (h = gethostbyname(hostname)) == NULL )
{
perror(hostname);
  return -1;
}

if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    serv_address.sin_family= AF_INET;//The address family for the transport address.
    serv_address.sin_port = htons(port);//A transport protocol port number.host to network
    serv_address.sin_addr.s_addr = *(long*)(h->h_addr);
    if ((client_fd= connect(sock, (struct sockaddr*)&serv_address,sizeof(serv_address)))< 0) //initiate a connection on a socket
        {
  
close(sock);
perror(hostname);
return-1;
      


    }
    

return sock;
}
 

SSL_CTX* InitCTX(void)
{      
SSL_METHOD *method;
SSL_CTX *ctx;

	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();/* Load cryptos, et.al. *///adds all algorithms to the table (digests and ciphers).
	SSL_load_error_strings(); /* Bring in and register error messages */
	method=(SSL_METHOD*)TLS_client_method();/* Create new client-method instance flexible version*/
	ctx = SSL_CTX_new(method);/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{ X509 *certificate;
 X509_NAME *certificate_sub;
 X509_NAME *certificate_is;

	certificate=SSL_get_peer_certificate(ssl);/* get the server's certificate */
    if ( certificate != NULL )
    {
        printf("Server certificates:\n");
        /* */ 
        certificate_sub=X509_get_subject_name(certificate);//get the  subject's name
        certificate_is= X509_get_issuer_name(certificate);// get the issuer's name
        char *line_sub = X509_NAME_oneline(certificate_sub,0,0); //transfer the typw x509_name to character 
        printf("Subject: %s\n", line_sub);
        free(line_sub);
       char *line_is = X509_NAME_oneline(certificate_is, 0, 0);
        printf("Issuer: %s\n", line_is);
        free(line_is);
    }
    else
        printf("Info: No server certificates configured.\n");
}
int main(int count, char *strings[])
{   char Request[2000]={0};
    char Answerfromserver[2000]={0};
    char *hostname, *portnum;
    hostname=strings[1];
    portnum=strings[2];
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    
    int connectiotoserver=OpenConnection(hostname,atoi(portnum));
      

               SSL *ssl = SSL_new(InitCTX()); /* create new SSL connection state */
	       SSL_set_rfd(ssl,connectiotoserver);/* attach the socket descriptor *///read channel
	       SSL_set_wfd(ssl,connectiotoserver);//write channel
		/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage ="<Body>\\<UserName>%s<UserName>\\<Password>%s<Password>\\<\\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
	sprintf(Request, cpRequestMessage, acUsername,acPassword);/* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);/* get any certs */
        SSL_write(ssl, Request, strlen(Request) + 1);
        /* encrypt & send message */
        SSL_read(ssl, Answerfromserver, sizeof(Answerfromserver));

            printf("Received message from server: ‘%s’\n", Answerfromserver);
        /* get reply & decrypt */
        SSL_free(ssl);/* release connection state */
    }
  close(connectiotoserver);
   SSL_CTX_free(InitCTX());

    return 0;/* close socket */
		/* release context */
    return 0;
}


