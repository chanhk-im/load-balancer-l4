#include <stdio.h>
#include <stdlib.h>

#include "server_pool.h"

server_pool_t *create_server_pool() {
    server_pool_t *new_pool = (server_pool_t *)malloc(sizeof(server_pool_t));
    new_pool->size = 0;
    new_pool->capacity = 1024;
    new_pool->servers = (server_t **)malloc(sizeof(server_t *) * new_pool->capacity);
}

void server_pool_push(server_pool_t *server_pool, server_t *serv) {
    if (server_pool->size >= server_pool->capacity) {
        return;
    }

    server_pool->servers[(server_pool->size)++] = serv;
}

server_t *server_pool_search_serv(server_pool_t *server_pool, uint32_t ip_addr, int port) {
    // printf("----server_pool---\n");
    // printf("find: %d\n", port);
    for (int i = 0; i < server_pool->size; i++) {
        server_t *curr = server_pool->servers[i];
        // printf("curr: %d %d\n", curr->port, curr->resource_status.serv_port);
        if (curr->ip_addr == ip_addr && (curr->port == port || curr->resource_status.serv_port == port)) {
            return curr;
        }
    }
    return NULL;
}