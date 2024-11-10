#include <stdint.h>
#include "server_type.h"

typedef struct __nat_table_elem_t {
    uint32_t clnt_addr;
    int clnt_port;
    uint32_t serv_addr;
    int serv_port;
    int lb_port;
    struct __nat_table_elem_t *next;
} nat_table_elem_t;

typedef struct __nat_table_t {
    nat_table_elem_t *head;
    nat_table_elem_t *tail;
    int size;
} nat_table_t;

nat_table_t *nat_table_init();
void nat_table_push(nat_table_t *nat_table, nat_table_elem_t *elem);
nat_table_elem_t *nat_table_search_clnt(nat_table_t *nat_table, uint32_t ip_addr, int port);
nat_table_elem_t *nat_table_search_clnt_lb_port(nat_table_t *nat_table, int port);