#ifndef __DPDK_PARAM__
#define __DPDK_PARAM__

typedef struct dpdk_port_conf
{
	int queue_num;
	int mtu;
	int rss_tuple;
	int jumbo;
}dpdk_port_conf_t;

int dpdk_conf_parse(void);
int dpdk_get_param_cnt(void);
char **dpdk_get_param(void);
int dpdk_get_port_cnt(void);
dpdk_port_conf_t* dpdk_get_port_conf(int port_id);

#endif

