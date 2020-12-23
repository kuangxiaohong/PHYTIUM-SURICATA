#ifndef __DPDK_PORT_CONF__
#define __DPDK_PORT_CONF__

#include "stdint.h"

//can get from dpdk param
#define NB_MBUF             (8192 * 32) 
#define NB_SOCKETS        (8)


void dpdk_port_setup(void);
void dpdk_port_start(void);
int dpdk_get_port_queue_num(int port_id);
int dpdk_get_port_num(void);
int dpdk_get_port_and_queue(uint16_t *out_port,uint16_t *out_queue);
void dpdk_ports_print(void);
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);
int dpdk_get_port_queue_total(void);
void dpdk_port_setup_proc(void);

#endif
