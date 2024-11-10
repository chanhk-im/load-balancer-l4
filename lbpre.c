#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "nat_table.h"
#include "server_pool.h"
#include "server_type.h"

#define BUF_SIZE 1024
#define MAX_SERVER_POOL 10
#define SERVER_COUNT 2
#define CLIENT_COUNT 8
#define ALGORITHM_FLAG 1  // 0: RR, 1: LC, 2: RB
#define DEBUG

struct pseudo_header {
    __uint32_t saddr;
    __uint32_t daddr;
    __uint8_t reserved;
    __uint8_t protocol;
    __uint16_t tcp_len;
};

void error_handling(char *message);
unsigned short checksum(unsigned short *buffer, int size);
void server_recv_first_info(server_t *serv);
void *server_thread_func(void *arg);
int check_conditions();
server_t parse_source_addr();
server_t parse_dest_addr();
server_t *match_server();
void modify_packet(int lb_port, uint32_t ip_addr, int port);

server_pool_t *server_pool;
int lb_sock, serv_sock;
struct sockaddr_in lb_adr;
struct sockaddr_in serv_adr;
socklen_t serv_adr_sz;

pthread_t serv_threads[SERVER_COUNT];

char buffer[BUF_SIZE];
char modified[BUF_SIZE];
int packet_len;
struct iphdr *iph;
struct tcphdr *tcph;
nat_table_t *nat_table;

int queue_cnt;
int curr_lb_port;

int main(int argc, char *argv[]) {
    int curr_id = 27507;
    uint32_t next_ack;
    uint32_t next_seq;
    int option = 1;

    srand(time(NULL));

    if (argc != 3) {
        printf("Usage: %s <IP> <Port>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));
    curr_id = rand() % 65535;
    curr_lb_port = atoi(argv[2]) + 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) {
        perror("setsockopt(IP_HDRINCL, 1)");
        exit(EXIT_FAILURE);
    }

    server_pool = create_server_pool();
    nat_table = nat_table_init();

    // Setting lb socket to connect with servers
    lb_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (lb_sock == -1) error_handling("socket() error");

    setsockopt(lb_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&lb_adr, 0, sizeof(lb_adr));
    lb_adr.sin_family = AF_INET;
    lb_adr.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &lb_adr.sin_addr) != 1) {
        perror("Destination IP and Port configuration failed");
        exit(EXIT_FAILURE);
    }

    if (bind(lb_sock, (struct sockaddr *)&lb_adr, sizeof(lb_adr)) == -1) error_handling("bind() error");

    if (listen(lb_sock, SERVER_COUNT) == -1) error_handling("listen() error");

    serv_adr_sz = sizeof(serv_adr);

    for (int i = 0; i < SERVER_COUNT; i++) {
        serv_sock = accept(lb_sock, (struct sockaddr *)&serv_adr, &serv_adr_sz);
        if (serv_sock == -1)
            error_handling("accept() error");
        else
            printf("Connected with server, sock: %d port: %d \n", serv_sock, ntohs(serv_adr.sin_port));

        server_t *new_server;
        new_server = (server_t *)malloc(sizeof(server_t));
        new_server->ip_addr = serv_adr.sin_addr.s_addr;
        new_server->port = serv_adr.sin_port;
        new_server->sock = serv_sock;
        new_server->flag = 1;
        server_pool_push(server_pool, new_server);
        server_recv_first_info(new_server);
        // pthread_create(serv_threads + i, NULL, server_thread_func, new_server);
    }

    close(lb_sock);

    while (1) {
        recv(sock, buffer, BUF_SIZE, 0);
        int check = check_conditions();
        if (check != 0) {
#ifdef DEBUG
            printf("check: %d\n", check);
#endif
        }
        if (check == 0)
            continue;
        else if (check == 1) {
            server_t parse_source = parse_source_addr();
            nat_table_elem_t *search_result;

            if ((search_result = nat_table_search_clnt(nat_table, parse_source.ip_addr, parse_source.port)) == NULL) {
                server_t *match = match_server();
                search_result = (nat_table_elem_t *)malloc(sizeof(nat_table_elem_t));
                search_result->clnt_addr = parse_source.ip_addr;
                search_result->clnt_port = parse_source.port;
                search_result->lb_port = curr_lb_port++;
                search_result->serv_addr = match->ip_addr;
                search_result->serv_port = match->resource_status.serv_port;
                search_result->next = NULL;
                nat_table_push(nat_table, search_result);
            }

            modify_packet(htons(search_result->lb_port), search_result->serv_addr, search_result->serv_port);
            int tmp;
            struct sockaddr_in daddr;
            daddr.sin_family = AF_INET;
            daddr.sin_port = search_result->serv_port;
            daddr.sin_addr.s_addr = search_result->serv_addr;
            if ((tmp = sendto(sock, modified, packet_len, 0x0, (struct sockaddr *)&daddr, sizeof(daddr))) < 0) {
                perror("error syn ");
                exit(1);
            }
        } else if (check == 2) {
            server_t parse_dest = parse_dest_addr();
            nat_table_elem_t *search_result;
            if ((search_result = nat_table_search_clnt_lb_port(nat_table, ntohs(parse_dest.port))) == NULL) {
                continue;
            }

            modify_packet(lb_adr.sin_port, search_result->clnt_addr, search_result->clnt_port);
            int tmp;
            struct sockaddr_in daddr;
            daddr.sin_family = AF_INET;
            daddr.sin_port = search_result->clnt_port;
            daddr.sin_addr.s_addr = search_result->clnt_addr;
            if ((tmp = sendto(sock, modified, packet_len, 0x0, (struct sockaddr *)&daddr, sizeof(daddr))) < 0) {
                perror("error synack ");
                exit(1);
            }
        }
    }

    close(sock);
    return 0;
}

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

unsigned short checksum(unsigned short *buffer, int size) {
    __uint32_t curr_sum = 0;
    for (int i = 0; i < size - 1; i += 2) {
        curr_sum += *(buffer++);
    }
    if (size % 2 == 1) {
        curr_sum += *((unsigned char *)buffer);
    }
    while (curr_sum >> 16) curr_sum = (curr_sum >> 16) + (curr_sum & 0xffff);
    return (unsigned short)(~curr_sum);
}

void server_recv_first_info(server_t *serv) {
    int recv_len = recv(serv->sock, &(serv->resource_status), sizeof(resource_t), 0);
    if (recv_len == 0) return;

#ifdef DEBUG
    printf("======Server Info======\n");
    printf("cpu_usage: %f\n", serv->resource_status.cpu_usage);
    printf("memory_left: %f\n", serv->resource_status.memory_left);
    printf("port: %d\n", serv->resource_status.serv_port);
    printf("=======================\n");
#endif
}

void *server_thread_func(void *arg) {
    int recv_len;
    server_t *new_server = (server_t *)arg;

    while (1) {
        recv_len = recv(new_server->sock, &(new_server->resource_status), sizeof(resource_t), 0);
        if (recv_len == 0) return NULL;

#ifdef DEBUG
        printf("======Server Info======\n");
        printf("cpu_usage: %f\n", new_server->resource_status.cpu_usage);
        printf("memory_left: %f\n", new_server->resource_status.memory_left);
        printf("port: %d\n", new_server->resource_status.serv_port);
        printf("clnt cnt: %d\n", new_server->resource_status.num_connected_client);
        printf("=======================\n");
#endif
    }
}

int check_conditions() {
    iph = (struct iphdr *)buffer;
    tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    if (iph->daddr != lb_adr.sin_addr.s_addr || tcph->dest != lb_adr.sin_port) {
        int flag = 0;
        for (int i = ntohs(lb_adr.sin_port); i <= curr_lb_port; i++) {
            if (ntohs(tcph->dest) == i) {
                flag = 1;
                break;
            }
        }
        if (flag == 0) return 0;
    }
    if (server_pool_search_serv(server_pool, iph->saddr, tcph->source) != NULL) return 2;
    return 1;
}

server_t parse_source_addr() {
    server_t parse_addr;

    iph = (struct iphdr *)buffer;
    tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    parse_addr.ip_addr = iph->saddr;
    parse_addr.port = tcph->source;
    parse_addr.sock = 0;
    parse_addr.flag = 0;
    return parse_addr;
}

server_t parse_dest_addr() {
    server_t parse_addr;

    iph = (struct iphdr *)buffer;
    tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    parse_addr.ip_addr = iph->daddr;
    parse_addr.port = tcph->dest;
    parse_addr.sock = 0;
    parse_addr.flag = 0;
    return parse_addr;
}

server_t *match_server() {
    switch (ALGORITHM_FLAG) {
        case 0:
#ifdef DEBUG
            printf("match serv port: %d\n", server_pool->servers[queue_cnt % SERVER_COUNT]->port);
#endif
            return server_pool->servers[(queue_cnt++) % SERVER_COUNT];
        case 1:
            int less = CLIENT_COUNT + 1;
            int less_idx;
            for (int i = 0; i < server_pool->size; i++) {
                if (server_pool->servers[i]->resource_status.num_connected_client < less) {
                    less_idx = i;
                    less = server_pool->servers[i]->resource_status.num_connected_client;
                }
            }
#ifdef DEBUG
            printf("match serv port: %d (clnt cnt: %d)\n", server_pool->servers[less_idx]->port,
                   server_pool->servers[less_idx]->resource_status.num_connected_client);
#endif
            return server_pool->servers[less_idx];
        case 2:
            double less_d = 2;
            int less_idx_2;
            for (int i = 0; i < server_pool->size; i++) {
                if ((server_pool->servers[i]->resource_status.cpu_usage +
                     server_pool->servers[i]->resource_status.memory_left) < less_d) {
                    less_idx_2 = i;
                    less_d = server_pool->servers[i]->resource_status.cpu_usage +
                             server_pool->servers[i]->resource_status.memory_left;
                }
            }
    }
}

void modify_packet(int lb_port, uint32_t ip_addr, int port) {
#ifdef DEBUG
    printf("======modify=====\n");
    printf("%d %d\n", ntohs(lb_port), ntohs(port));
#endif
    memcpy(modified, buffer, BUF_SIZE);

    struct iphdr *miph = (struct iphdr *)modified;
    struct tcphdr *mtcph = (struct tcphdr *)(modified + sizeof(struct iphdr));
    packet_len = ntohs(miph->tot_len);

    miph->saddr = lb_adr.sin_addr.s_addr;
    miph->daddr = ip_addr;
    miph->check = 0;
    miph->check = checksum((unsigned short *)miph, sizeof(struct iphdr) / 2);

    mtcph->source = lb_port;
    mtcph->dest = port;
    mtcph->check = 0;

    char *pseudo_packet = (char *)malloc(sizeof(struct pseudo_header) + packet_len - sizeof(struct iphdr));
    struct pseudo_header *ph = (struct pseudo_header *)pseudo_packet;
    struct tcphdr *th = (struct tcphdr *)(pseudo_packet + sizeof(struct pseudo_header));

    ph->saddr = miph->saddr;
    ph->daddr = miph->daddr;
    ph->reserved = 0;
    ph->protocol = IPPROTO_TCP;
    ph->tcp_len = htons(packet_len - sizeof(struct iphdr));

    memcpy(pseudo_packet + sizeof(struct pseudo_header), mtcph, packet_len - sizeof(struct iphdr));
    mtcph->check =
        checksum((unsigned short *)pseudo_packet, sizeof(struct pseudo_header) + packet_len - sizeof(struct iphdr));

#ifdef DEBUG
    printf("tot: %d\n", ntohs(miph->tot_len));
#endif

    free(pseudo_packet);

#ifdef DEBUG
    printf("paclen: %d\n", packet_len);
    printf("===============\n");
#endif
}