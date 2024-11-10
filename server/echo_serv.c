#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 1024
#define CLIENT_COUNT 8

struct pseudo_header {
    //...
    __uint32_t saddr;
    __uint32_t daddr;
    __uint8_t reserved;
    __uint8_t protocol;
    __uint16_t tcp_len;
};

typedef struct __resource_t {
    // for least connected
    int num_connected_client;

    // for resource based
    double cpu_usage;
    double memory_left;
    int serv_port;
} resource_t;

void error_handling(char *message);
void *lb_thread_func(void *arg);
void *serv_thread_func(void *arg);
double get_memory_usage();
double get_cpu_usage();

int lb_sock;
resource_t res;
pthread_t lb_thread;
pthread_t serv_threads[CLIENT_COUNT];

struct sockaddr_in lb_adr;
struct sockaddr_in serv_adr;
struct sockaddr_in clnt_adr;

int main(int argc, char *argv[]) {
    int serv_sock, clnt_sock;
    int raw_sock;
    char recv_packet[BUF_SIZE];
    char message[BUF_SIZE];
    int str_len, i;
    int option = 1;

    socklen_t clnt_adr_sz;

    res.num_connected_client = 0;

    if (argc != 4) {
        printf("Usage : %s <port> <LD_IP> <LD_port>\n", argv[0]);
        exit(1);
    }

    // Connect with lb
    lb_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (lb_sock == -1) error_handling("socket() error");

    memset(&lb_adr, 0, sizeof(lb_adr));
    lb_adr.sin_family = AF_INET;
    lb_adr.sin_addr.s_addr = inet_addr(argv[2]);
    lb_adr.sin_port = htons(atoi(argv[3]));

    if (connect(lb_sock, (struct sockaddr *)&lb_adr, sizeof(lb_adr)) == -1)
        error_handling("connect() error!");
    else
        puts("Connected with lb...");

    // Connect with client
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) error_handling("socket() error");

    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr *)&serv_adr, sizeof(serv_adr)) == -1) error_handling("bind() error");

    if (listen(serv_sock, 5) == -1) error_handling("listen() error");

    clnt_adr_sz = sizeof(clnt_adr);

    // setting raw sock
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) {
        perror("setsockopt(IP_HDRINCL, 1)");
        exit(EXIT_FAILURE);
    }

    pthread_create(&lb_thread, NULL, lb_thread_func, NULL);

    for (i = 0; i < CLIENT_COUNT; i++) {
        int *pass_sock = (int *)malloc(sizeof(int));
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_adr, &clnt_adr_sz);
        res.num_connected_client++;
        *pass_sock = clnt_sock;
        if (clnt_sock == -1)
            error_handling("accept() error");
        else
            printf("Connected client %d \n", i + 1);

        pthread_create(serv_threads + i, NULL, serv_thread_func, pass_sock);
    }

    close(serv_sock);
    close(raw_sock);
    return 0;
}

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void *lb_thread_func(void *arg) {
    while (1) {
        res.cpu_usage = get_cpu_usage();
        res.memory_left = get_memory_usage();
        res.serv_port = serv_adr.sin_port;
        int tmp = send(lb_sock, &res, sizeof(resource_t), 0);
        sleep(5);
    }
}

void *serv_thread_func(void *arg) {
    int sock = *((int *)arg);
    int str_len;
    char message[BUF_SIZE];

    while ((str_len = read(sock, message, BUF_SIZE)) != 0) {
        int wlen = write(sock, message, str_len);
        write(1, message, str_len);
    }

    close(sock);
    res.num_connected_client--;
}

double get_memory_usage() {
    FILE *file = fopen("/proc/meminfo", "r");
    if (file == NULL) {
        perror("Failed to open /proc/meminfo");
        return -1.0;
    }

    char line[256];
    unsigned long mem_total = 0, mem_free = 0, buffers = 0, cached = 0;

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "MemTotal: %lu kB", &mem_total);
        sscanf(line, "MemFree: %lu kB", &mem_free);
        sscanf(line, "Buffers: %lu kB", &buffers);
        sscanf(line, "Cached: %lu kB", &cached);
    }
    fclose(file);

    unsigned long mem_used = mem_total - mem_free - buffers - cached;
    return (double)mem_used / (double)mem_total;
}

double get_cpu_usage() {
    FILE *file;
    char buffer[1024];
    unsigned long long int user, nice, system, idle, iowait, irq, softirq, steal;
    unsigned long long int total_time_1, total_time_2, idle_time_1, idle_time_2;

    // Read the first sample
    file = fopen("/proc/stat", "r");
    if (file == NULL) {
        perror("Failed to open /proc/stat");
        return -1.0;
    }
    fgets(buffer, sizeof(buffer), file);
    sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait, &irq, &softirq,
           &steal);
    fclose(file);

    total_time_1 = user + nice + system + idle + iowait + irq + softirq + steal;
    idle_time_1 = idle + iowait;

    // Sleep for a second
    sleep(1);

    // Read the second sample
    file = fopen("/proc/stat", "r");
    if (file == NULL) {
        perror("Failed to open /proc/stat");
        return -1.0;
    }
    fgets(buffer, sizeof(buffer), file);
    sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait, &irq, &softirq,
           &steal);
    fclose(file);

    total_time_2 = user + nice + system + idle + iowait + irq + softirq + steal;
    idle_time_2 = idle + iowait;

    // Calculate CPU usage
    double total_diff = total_time_2 - total_time_1;
    double idle_diff = idle_time_2 - idle_time_1;
    double usage = (total_diff - idle_diff) / total_diff;

    return usage;
}