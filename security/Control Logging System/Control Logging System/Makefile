all: logger acmonitor test_aclog rsa

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor


test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

rsa: rsa.c
	gcc -Wall -fPIC -shared -o rsa.so rsa.c -lcrypto -ldl 




run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

    

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor

    


