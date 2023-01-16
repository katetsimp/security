#define _GNU_SOURCE
#include <libgen.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>




#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

int Aflag=0; //global variable
void forloggin(const char *path ,int AccessType){
//variable declaration
struct timeval tv;
struct tm *DateAndHour;

MD5_CTX ctx;

unsigned char digest[MD5_DIGEST_LENGTH];
char buffer[2048];


FILE *temp_file;
FILE *(*original_fopen)(const char*, const char*);
FILE *logfile;

char* t1 = strdup(path);



uid_t id;
time_t t;

char *filename;
char modi_data_hour[26];
char  lbuff[5000]={0};
char actualpath [PATH_MAX+1];




int count;


// code
original_fopen = dlsym(RTLD_NEXT, "fopen");
logfile = original_fopen("./file_logging.log", "a");

if(logfile!=NULL){
id=getuid();//get id
realpath(path, actualpath);

filename = basename(t1);//taine the filename
 gettimeofday(&tv, NULL); 
 t = tv.tv_sec;
DateAndHour = localtime(&t); //date and time that the action occurred
sprintf(modi_data_hour,"%s",asctime(DateAndHour));
modi_data_hour[24]='\0'; // cut the '\n' character
sprintf(lbuff, "%d\t%s\t%s\t%s\t%d\t%d\t",id, actualpath, filename, modi_data_hour, AccessType, Aflag);
temp_file=original_fopen(path,"r");//open to read the data

if(temp_file!=NULL || errno==0){
MD5_Init(&ctx);

	while((count = fread(buffer, 1, 2048, temp_file))) //read the data and put the in a string
	{
		MD5_Update(&ctx, buffer, count); //digital fingerprint of the file contents
        }

	MD5_Final(digest, &ctx);

		for(count = 0; count < MD5_DIGEST_LENGTH; count++)
		{
			sprintf(lbuff + strlen(lbuff), "%02x", digest[count]);
			
			
		}
		fclose(temp_file);
		
	} 
	else{
	
	for(count = 0; count < MD5_DIGEST_LENGTH; count++) // if not exist or cant read it
		{
			sprintf(lbuff + strlen(lbuff), "%02x", 0);
			
			
		}
	}

sprintf(lbuff + strlen(lbuff) ,"\n");
fputs(lbuff, logfile);
fclose(logfile);
}
else{
printf("logfile  can not open \n");
}

}

FILE *
fopen(const char *path, const char *mode) 

{
        int t;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
      
	char ch = 'r';
     if(mode[0]!=(int)(ch)){
      if (access(path, F_OK) == 0) {
       // file exists let's open
       /* call the original fopen function */
       Aflag =0;
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
       if(original_fopen_ret == NULL){
       
		if(errno == EACCES || errno == EPERM)
		{Aflag = 1;

		}

		else if(errno == ENOENT)
		{
			
			return original_fopen_ret;
		}
		
		else
			return original_fopen_ret;
       
       }
	forloggin(path,1); 
}     else {
      // file doesn't exist lets create

      /* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	if(original_fopen_ret == NULL){
       
		if(errno == EACCES || errno == EPERM)
		{Aflag = 1;

		}

		else if(errno == ENOENT)
		{
			
			return original_fopen_ret;
		}
		
		else
			return original_fopen_ret;
       
       }
	 forloggin(path,0);
    }    
} else{
if (access(path, F_OK) == 0) {
       // file exists let's open
       /* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	if(original_fopen_ret == NULL){
       
		if(errno == EACCES || errno == EPERM)
		{Aflag = 1;

		}

		else if(errno == ENOENT)
		{
			
			return original_fopen_ret;
		}
		
		else
			return original_fopen_ret;
       
       }
	forloggin(path,1); 
}     else {
      // file doesn't exist cant creat

      /* call the original fopen function */
      original_fopen = dlsym(RTLD_NEXT, "fopen");
     original_fopen_ret = (*original_fopen)(path, mode);
	printf("File does not exist\n");
	
	
}
}
    
	return original_fopen_ret;
}	
        


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 

{
	
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

        fflush(stream);
	char dir[4096 ];
	char buff[4096 ];
	ssize_t s;
       
	sprintf(buff, "/proc/self/fd/%d",fileno(stream));//in linux format
	
	s =readlink(buff, dir, 4096);
	dir[s] ='\0';
        printf("%s \n",dir);
	forloggin(dir, 2);


	return original_fwrite_ret;

}
int remove(const char *filename){
 int r;
 int (*original_remove)(const char*);
 original_remove=dlsym(RTLD_NEXT, "remove");
 r=(*original_remove)(filename);
 if(r==-1){
 Aflag =1;
 }
 forloggin(filename, 3);
 return r;

}



   
    
 
 
 
 





