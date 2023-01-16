#ifndef _RSA_H
#define _RSA_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
struct encrreturnvalue {
RSA* rsa_pub_read;
int encrypt_len;
};
typedef struct encrreturnvalue Struct;
Struct rsafileenc(const char*);
char* rsafiledec(RSA*,int ,const char *);
Struct rsafileencWithoutsaving(const char *);
#endif /* _RSA_H */
