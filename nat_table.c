#include <stdio.h>
#include <stdlib.h>
#include "nat_table.h"

nat_table_t *nat_table_init() {
    nat_table_t *new_table = (nat_table_t *)malloc(sizeof(nat_table_t));
    new_table->head = NULL;
    new_table->tail = NULL;
    new_table->size = 0;
}

void nat_table_push(nat_table_t *nat_table, nat_table_elem_t *elem) {
    if (nat_table->size == 0) {
        nat_table->head = elem;
        nat_table->tail = elem;
        nat_table->size = 1;
    }
    else {
        nat_table->tail->next = elem;
        nat_table->tail = elem;
        elem->next = NULL;
        nat_table->size++;
    }
}

nat_table_elem_t *nat_table_search_clnt(nat_table_t *nat_table, uint32_t ip_addr, int port) {
    nat_table_elem_t *curr = nat_table->head;

    while (curr != NULL) {
        if (curr->clnt_addr == ip_addr && curr->clnt_port == port) {
            return curr;
        }

        curr = curr->next;
    }
    return NULL;
}

nat_table_elem_t *nat_table_search_clnt_lb_port(nat_table_t *nat_table, int port) {
    nat_table_elem_t *curr = nat_table->head;

    while (curr != NULL) {
        if (curr->lb_port == port) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}