#include "rsa.h"
Struct rsafileencWithoutsaving(const char *filename){
    Struct s;
   
    
    char   *encrypt = NULL;    // Encrypted message
    
     char   *err;               // Buffer for any error messages
    
    FILE* pubfp = fopen("rsa.public", "rb");
    RSA *rsa_pub, *rsa_pub_read;
    rsa_pub = RSA_new();
    
    
    
    rsa_pub_read = PEM_read_RSA_PUBKEY(pubfp, &rsa_pub,0,0);
    s.rsa_pub_read=rsa_pub_read;
    fclose(pubfp);
   
    char * buffer = 0;
long length;
FILE * f = fopen (filename, "rb");

if (f)
{
  fseek (f, 0, SEEK_END);
  length = ftell (f);
  fseek (f, 0, SEEK_SET);
  buffer = malloc (length);
 char* firstThree[30];
   
  if (buffer)
 
  {
  while (!feof(f)) {
  fread (buffer, 1, 30, f);
  memcpy(firstThree, buffer , 30);
    encrypt = malloc(RSA_size(rsa_pub_read));
    
    int encrypt_len;
    err = malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(buffer)+1, (unsigned char*)buffer, (unsigned char*)encrypt,
                                         rsa_pub_read, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        }
        
     s.encrypt_len=encrypt_len;       
       
        
    
    
    
   
  }
  fclose (f);
   
}
}
return s;
}

Struct rsafileenc(const char *filename){
    Struct s;
   
    
    char   *encrypt = NULL;    // Encrypted message
    
     char   *err;               // Buffer for any error messages
    
    FILE* pubfp = fopen("rsa.public", "rb");
    RSA *rsa_pub, *rsa_pub_read;
    rsa_pub = RSA_new();
    
    
    
    rsa_pub_read = PEM_read_RSA_PUBKEY(pubfp, &rsa_pub,0,0);
    s.rsa_pub_read=rsa_pub_read;
    fclose(pubfp);
   
    char * buffer = 0;
long length;
FILE * f = fopen (filename, "rb");

if (f)
{
  fseek (f, 0, SEEK_END);
  length = ftell (f);
  fseek (f, 0, SEEK_SET);
  buffer = malloc (length);
 char* firstThree[30];
   
  if (buffer)
 
  {
  while (!feof(f)) {
  fread (buffer, 1, 30, f);
  memcpy(firstThree, buffer , 30);
    encrypt = malloc(RSA_size(rsa_pub_read));
    
    int encrypt_len;
    err = malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(buffer)+1, (unsigned char*)buffer, (unsigned char*)encrypt,
                                         rsa_pub_read, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        }
       
     s.encrypt_len=encrypt_len;       
       // Write the encrypted message to a file
        FILE *out = fopen("file_logging.bin", "a");
        fwrite(encrypt, sizeof(*encrypt),  RSA_size(rsa_pub_read), out);
        fclose(out);
        printf("Encrypted message written to file.\n");
        free(encrypt);
        encrypt = NULL;
        
        
    
    
    
   
  }
  fclose (f);
   
}
}
return s;
}
char* rsafiledec(RSA*keyen,int encrypt_len,const char *filename){
char   *err; 
FILE* privfp = fopen("rsa.private", "rb");
RSA *rsa_priv, *rsa_priv_read;
char   *decrypt = NULL;    // Decrypted message
rsa_priv = RSA_new();
rsa_priv_read = PEM_read_RSAPrivateKey(privfp, &rsa_priv,0,0); 
 fclose(privfp);
 char   *encrypt = NULL;    // Encrypted message
 printf("Reading back encrypted message and attempting decryption...\n");
 encrypt = malloc(RSA_size(keyen));    
FILE *out = fopen(filename, "rd");
char * buffer = 0;

long length;


if (out)
{
  fseek (out, 0, SEEK_END);
  length = ftell (out);
  fseek (out, 0, SEEK_SET);
  buffer = malloc (length);
  
  while (!feof(out)) {
    fread(encrypt, sizeof(*encrypt), RSA_size(keyen), out);
    
    decrypt = malloc(encrypt_len);
    err = malloc(130);
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           rsa_priv_read, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
       
    }
    
   sprintf(buffer + strlen(buffer), "%s",decrypt );    
    
    
}

 printf("%s",buffer);  

  
 }
 return buffer;

 }
 
