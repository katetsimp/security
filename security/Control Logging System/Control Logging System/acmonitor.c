#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include"rsa.h"

#include "rsa.h"
RSA* rsa_pub_read;
int encrypt_len;
struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
        char chunk[5000];
        char* temp[7];
        
        int access_count;
        int i=0;
      
	 while(fgets(chunk, sizeof(chunk), log)!= NULL){
	 temp[0]=strtok(chunk, "\t");
	 for(i=0; i<6; i++){
	
	 temp[i+1] = strtok(NULL, "\t");
	 
	 
    }
      
    if (strcmp(temp[5],"1")==0){
    
        char chunk2[5000];
        char* temp2[7];
     
        
        
      
	 while(fgets(chunk2, sizeof(chunk2), log)!= NULL){
	 temp2[0]=strtok(chunk2, "\t");
	 int j=0;
	 for(j=0; j<6; j++)
	 {
	
	 temp2[j+1] = strtok(NULL, "\t");
	 
	 
    } 
      
    if((strcmp(temp[0],temp2[0])==0) && (strcmp(temp2[5],"1")==0) && strcmp(temp[1],temp2[1])!=0)
				{
					access_count++;
				}
			}
    if(access_count >= 7)
			{
			printf("The user %s tried to open more than 7 times different files that does not have permission\n",temp[0]);
				break;
			}
    
    } 
}
   

            
         

	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

int n,j,Count;
char* ids[4000];
char*fingerprint;
char*id;
char actualpath [PATH_MAX+1];
realpath(file_to_scan, actualpath);
char chunk[5000];
        char* temp[7];
        
        int access_count;
        int i=0;
      
	 while(fgets(chunk, sizeof(chunk), log)!= NULL){
	 temp[0]=strtok(chunk, "\t");
	 for(i=0; i<6; i++){
	
	 temp[i+1] = strtok(NULL, "\t");
	 
	 
    }
    if(((strcmp(temp[1],actualpath))==0)&&(strcmp(temp[5],"0")==0)){
      if(fingerprint != NULL){
      if(((strcmp(temp[6],fingerprint))!=0)&&(strcmp(temp[4],"2")==0)){
       ids[n]=temp[0];
       n++;
    
                                      }
    
                             }
                           
  fingerprint=temp[6]; 
   char chunk2[5000];
        char* temp2[7];
        
       
        int j=0;
      
	 while(fgets(chunk2, sizeof(chunk2), log)!= NULL){
	 temp2[0]=strtok(chunk2, "\t");
	 for(j=0; j<6; j++){
	
	 temp2[j+1] = strtok(NULL, "\t");
	 
	 
    }
    
    if((strcmp(temp2[1], actualpath) == 0) && (strcmp(fingerprint,temp2[6]) != 0))
      { if((strcmp(temp2[4],"2")==0) && (strcmp(temp2[5],"0")==0))
					{ 
						 ids[n]=temp2[0];
						 n++;
				         
					}
					fingerprint = temp2[6];
					break;
	}  
                                                                    
  }
  
}

}


if (n>1){
for (i = 0; i < n-1; i++)
	{
		for(j = i + 1; j <= n-1; j++)
		{
		
    		if((strcmp(ids[j],ids[i])==0))
    		printf("here");
    		{      id=ids[i];
    			Count++;
			break;	
			}
		}
	}
	}
else{
id=ids[0];
}
printf("the User with id:%s,modified the file %d times",id,Count+1);
	return;

}


int 
main(int argc, char *argv[])
{   /*Struct result;
     result=rsafileenc("./file_logging.log");
     rsa_pub_read=result.rsa_pub_read;
     encrypt_len=result.encrypt_len;
     rsafiledec(rsa_pub_read,encrypt_len,"./file_logging.bin"); */
    
     
     
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
