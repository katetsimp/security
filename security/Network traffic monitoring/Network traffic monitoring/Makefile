CC = gcc
CFLAGS = -Wall -pedantic  
LIBS = -lpcap 
OBJ = pcap_ex.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
	
pcap_ex: $(OBJ)
	$(CC) -o $@ $^ $(LIBS)
	$(MAKE) clean
	
clean:
	rm -f *.o

