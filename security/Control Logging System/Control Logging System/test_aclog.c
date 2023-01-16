#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
int main() 
{
	int i,j;
	size_t bytes;
	FILE *file;
	char* b="giyrfuyet";
	char* a="giyrfuyet";
	
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL)
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	fopen(filenames[2],"w+");
	fwrite(b,strlen(b) , 1, file);
	fwrite(a,strlen(b) , 1, file); // file_2 modified 3 times
	
	remove(filenames[1]);
       //rsafileenc("./file_logging.log");

	for (i = 0; i <=7; i++) {

		chmod(filenames[i%3], S_ISUID);
		file = fopen(filenames[i], "w");

		if (file == NULL) 
			printf("fopen error\n");
		
		else 
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		
		chmod(filenames[i], S_IRUSR);
		file = fopen(filenames[i], "r");
		
		if (file == NULL) 
			printf("fopen error\n");
		
		else 
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}
	

	
		
}


