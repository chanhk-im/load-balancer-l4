CC = gcc
thread = -lpthread
LB_FILES = lb.c server_pool.c nat_table.c
SERVER = server/echo_serv.c
CLIENT = client/tcp_client.c

all: 
	$(CC) $(LB_FILES) -o lb $(thread)