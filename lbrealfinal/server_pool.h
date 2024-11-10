#include "server_type.h"

server_pool_t *create_server_pool();
void server_pool_push(server_pool_t *server_pool, server_t *serv);
server_t *server_pool_search_serv(server_pool_t *server_pool, uint32_t ip_addr, int port);