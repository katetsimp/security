OBJS	= client.o server.o
OUT	= client,server


OBJS0	= client.o
SOURCE	= client.c 
HEADER	= libssl-dev
OUT0 = client
OBJS1	= server.o
SOURCE1= server.c
HEADER1= libssl-dev
OUT1	= server

CC	 = gcc
FLAGS	 = -g -c -Wall
LFLAGS	 = -L/usr/lib -lssl -lcrypto
all: client server
client: $(OBJS0)
	$(CC) -g $(OBJS0) -o $(OUT0) $(LFLAGS)
server: $(OBJS1)
	$(CC) -g $(OBJS1) -o $(OUT1) $(LFLAGS)

client.o: client.c
	$(CC) $(FLAGS) client.c -L/usr/lib -lssl -lcrypto

server.o: server.c
	$(CC) $(FLAGS) server.c -L/usr/lib -lssl -lcrypto


clean:
	rm -f $(OBJS) $(OUT)

