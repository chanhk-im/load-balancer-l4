#ifndef __SERVER_TYPE_H__
#define __SERVER_TYPE_H__

#include <stdint.h>

typedef struct __resource_t {
    // for least connected
    int num_connected_client;

    // for resource based
    double cpu_usage;
    double memory_left;
    int serv_port;
} resource_t;

typedef struct __server_t {
    int sock;
    uint32_t ip_addr;
    int port;
    resource_t resource_status;
    int flag;  // 1 = well connected, 0 = not connected
} server_t;

typedef struct __server_pool_t {
    int size;
    int capacity;
    server_t **servers;
} server_pool_t;

#endif