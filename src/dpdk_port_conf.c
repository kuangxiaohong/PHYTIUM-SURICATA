/**
 * \file
 *
 * \author kuangxiaohong <1002361031@qq.com>
 *
 * DPDK support.
 */

#include "dpdk_port_conf.h"
#include "dpdk_param.h"
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#ifndef MAX
#define MAX(v1, v2)	((v1) > (v2) ? (v1) : (v2))
#endif
#ifndef MIN
#define MIN(v1, v2)	((v1) < (v2) ? (v1) : (v2))
#endif

#define RX_RING_SIZE       (4096)
#define TX_RING_SIZE       (512)
#define RSS_HASH_KEY_LENGTH 40
#define PKT_PRIV_SIZE    (256)
static uint32_t port_queue_num[RTE_MAX_ETHPORTS] = {0};
static uint32_t port_cnt = 0;

//对称RSS，dpdk默认RSS为非对称的
static uint8_t g_arrayHashKey[RSS_HASH_KEY_LENGTH] =
{
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS] = {NULL};

/**
 * numa架构下为每个核和端口到其所在内存节点上分配内存
 *
 * @param nb_mbuf
 *   分配mbuf个数
 * @return
 *   0 表示成功，其它为失败
 */
static int init_mem(uint32_t nb_mbuf)
{
	int socketid,i;
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		socketid = rte_lcore_to_socket_id(lcore_id);
		if (socketid >= NB_SOCKETS) 
			rte_exit(EXIT_FAILURE,"Socket %d of lcore %u is out of range %d\n",socketid, lcore_id, NB_SOCKETS);

		if (pktmbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf, 64, PKT_PRIV_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,"Cannot init mbuf pool on socket %d\n",socketid);
			else
				printf("Allocated mbuf pool on socket %d\n",socketid);
		}
	}

	RTE_ETH_FOREACH_DEV(i){
		socketid = rte_eth_dev_socket_id(i);
		if (socketid >= NB_SOCKETS) 
					rte_exit(EXIT_FAILURE,"Socket %d of port_id %u is out of range %d\n",socketid, i, NB_SOCKETS);
		
		if (pktmbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,"Cannot init mbuf pool on socket %d\n",socketid);
			else
				printf("Allocated mbuf pool on socket %d\n",socketid);
		}
	}
	
	return 0;
}

/**
 * 根据网口配置进行dpdk网口初始化
 *
 * @param dpdk_port_conf
 *   网口配置信息
 * @param port
 *   网口
 * @param num_queues
 *   网口配置队列数
 * @return
 *   
 */
static inline void dpdk_port_init(dpdk_port_conf_t *dpdk_port_conf,uint16_t port,uint16_t num_queues)
{	
    struct rte_eth_conf port_conf =
    {
        .rxmode = {
            .mq_mode    = ETH_MQ_RX_RSS,
			//.max_rx_pkt_len = 2000,
            .split_hdr_size = 0,
			//.offloads = DEV_RX_OFFLOAD_JUMBO_FRAME,
            //.offloads = DEV_RX_OFFLOAD_CRC_STRIP,//(DEV_RX_OFFLOAD_CHECKSUM |
                        // DEV_RX_OFFLOAD_CRC_STRIP),
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = g_arrayHashKey,
				.rss_key_len = RSS_HASH_KEY_LENGTH,
                .rss_hf = ETH_RSS_UDP|ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        }
    };
 
    const uint16_t rx_rings = num_queues, tx_rings = num_queues;
    struct rte_eth_dev_info info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    int retval;
    uint16_t q,mtu;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    uint64_t rss_hf_tmp;
	int socketid = rte_eth_dev_socket_id(port);

	/* init port */
	printf("Initializing port %u in socketid %d ... ", port,socketid);
	fflush(stdout);

    rte_eth_dev_info_get(port, &info);
	
    info.default_rxconf.rx_drop_en = 0;
    if (info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;


    rss_hf_tmp = port_conf.rx_adv_conf.rss_conf.rss_hf;
    port_conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp)
    {
        printf("Port %u modified RSS hash function based on hardware support,"
               "requested:%#"PRIx64" configured:%#"PRIx64"\n",
               port,
               rss_hf_tmp,
               port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

	if (dpdk_port_conf->jumbo)	
		port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0)
		rte_exit(EXIT_FAILURE,"rte_eth_dev_configure failed\n");
 

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0)
		rte_exit(EXIT_FAILURE,"rte_eth_dev_configure failed\n");


    rxq_conf = info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    for (q = 0; q < rx_rings; q ++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,socketid,&rxq_conf, pktmbuf_pool[socketid]);
        if (retval < 0) 
			rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup q(%d) failed\n",q);
    }

    txq_conf = info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q ++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,socketid,&txq_conf);
        if (retval < 0)
			rte_exit(EXIT_FAILURE,"rte_eth_tx_queue_setup q(%d) failed\n",q);
    }

	if (rte_eth_dev_get_mtu (port, &mtu) != 0) 
		rte_exit(EXIT_FAILURE,"rte_eth_dev_get_mtu port(%d) failed\n",port);
	
	if (mtu != dpdk_port_conf->mtu) 
		if (rte_eth_dev_set_mtu (port, mtu) != 0) 
			rte_exit(EXIT_FAILURE,"rte_eth_dev_set_mtu port(%d) failed\n",port);		

    rte_eth_promiscuous_enable(port);

    return ;
}

/**
 * 检测网口link状态
 *
 * @param port_num
 *   网口个数
 * @param port_mask
 *   网口掩码
 * @return
 *   
 */
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 40 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status\n");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++)
    {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++)
        {
            if ((port_mask & (1 << portid)) == 0)
                continue;
			
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1)
            {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u Mbps - %s\n", (uint8_t)portid,(unsigned)link.link_speed,
                           (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",(uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN)
            {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
        {
            break;
        }

        if (all_ports_up == 0)
        {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
        {
            print_flag = 1;
            printf("done\n");
        }
    }
}

/**
 * 根据网口配置信息来确定网口个数和队列数，并进行网口初始化
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup_proc(void)
{	
	dpdk_port_conf_t *port_conf;
    struct rte_eth_dev_info dev_info;	
    char portName[RTE_ETH_NAME_MAX_LEN] = {0};
	int port_num,port_id,num_max_queue;
	int port_conf_num = dpdk_get_port_cnt();
	int port_total = rte_eth_dev_count_avail();
	if (port_conf_num <= 0 || port_conf_num > port_total)	
		printf("WARING: port_conf_num %d larger port total %d\n",port_conf_num, port_total);

	port_num = MIN(port_conf_num,port_total);

	port_cnt = port_num;
	printf("port_num:%d port_conf_num:%d port_avail:%d\n",port_num,port_conf_num,port_total);

	int num_cores = rte_lcore_count();
	if ( num_cores < 1 )
		rte_exit(EXIT_FAILURE,"lcore num is %d, lower 0\n",num_cores);	

	//queue_num should compare with lcore_num,because one queue bind to one lcore
	for (port_id = 0; port_id < port_num; port_id++)
    {
		if (!rte_eth_dev_is_valid_port(port_id)) 		
			rte_exit(EXIT_FAILURE,"invalid port id %d\n",port_id);

		if (rte_eth_dev_get_name_by_port(port_id, portName) == 0)
            printf(" - port (%u) Name (%s)\n", port_id, portName);
		
		port_conf = dpdk_get_port_conf(port_id);
        rte_eth_dev_info_get(port_id, &dev_info);
		num_max_queue = port_conf->queue_num > dev_info.max_rx_queues ? dev_info.max_rx_queues : port_conf->queue_num;
		num_max_queue = num_max_queue > dev_info.max_tx_queues ? dev_info.max_tx_queues : num_max_queue;

		if (num_max_queue > num_cores)
			num_max_queue = num_cores;

		port_queue_num[port_id] = num_max_queue;
        printf("port=%d max_rx_queue=%d max_tx_queue=%d queue=%d lcores=%d\n",port_id, dev_info.max_rx_queues, dev_info.max_tx_queues, num_max_queue,num_cores);
        printf("dev_info.driver_name = %s,dev_info.if_index=%d\n", dev_info.driver_name, dev_info.if_index);

		dpdk_port_init(port_conf,port_id,num_max_queue);
    }


	check_all_ports_link_status((uint8_t)port_num,(~0x0));

	return;
}

/**
 * 网口启动收包
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_start(void)
{
	int port_id,ret;
	
	RTE_ETH_FOREACH_DEV(port_id) {
	/* Start device */
	//printf("dpdk_port_start: port_id:%d\n",port_id);
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,"rte_eth_dev_start: err=%d, port=%d\n",ret, port_id);
	}
}

/**
 * 网口建立并初始化
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup(void)
{
	init_mem(NB_MBUF);
	dpdk_port_setup_proc();
}

/**
 * 获取某网口的队列数
 *
 * @param port_id
 *   网口id
 * @return 返回网口队列数
 *   
 */
int dpdk_get_port_queue_num(int port_id)
{
	return port_queue_num[port_id];
}

/**
 * 获取网口数
 *
 * @param 
 *   
 * @return 返回网口数
 *   
 */
int dpdk_get_port_num(void)
{
	return port_cnt;
}

/**
 *每调用一次返回一个网口和队列，用于多线程处理
 *
 * @param  *out_port
 * 	网口返回值
 * @param  *out_queue
 * 	队列返回值
 *   
 * @return 
 *   
 */
int dpdk_get_port_and_queue(uint16_t *out_port,uint16_t *out_queue)
{
	static uint8_t first_time = 1;
	static uint16_t port = 0;
	static uint16_t queue = 0;

	int nr_ports = dpdk_get_port_num();
	int nr_queues  = dpdk_get_port_queue_num(port);

	if (first_time == 1)
	{
		first_time = 0;
		goto complete;
	}
	
	if ((queue + 1) < nr_queues)
		queue += 1;
	else {
		port += 1;
		queue = 0;
	}

	if(port >= nr_ports)
		return -1;
complete:
	*out_port = port;
	*out_queue = queue;
	return 0;

}

/**
 *打印所有网口信息
 *
 * @param  
 * 	 
 * @return 
 *   
 */
void dpdk_ports_print(void)
{
	uint16_t nb_ports = 0, i = 0;

	nb_ports = dpdk_get_port_num();

	printf("--- DPDK Ports ---");
	printf("Overall Ports: %d ", nb_ports);

	for (; i < nb_ports; i++) {
		struct rte_eth_dev_info info;
		struct rte_eth_link link;

		printf(" -- Port: %d", i);

		rte_eth_dev_info_get(i, &info);
		rte_eth_link_get(i, &link);


		printf(" -- promiscuous: %s", rte_eth_promiscuous_get(i)?"yes":"no");

		printf(" -- link info: speed %u, duplex %u, autoneg %u, status %u",
				link.link_speed, link.link_duplex,
				link.link_autoneg, link.link_status);

		printf(" -- driver: %s", info.driver_name);
		printf(" -- NUMA node: %d", rte_eth_dev_socket_id(i));
	}
	return;
}

/**
 *获取所有队列个数
 *
 * @param  
 * 	 
 * @return 返回所有队列数
 *   
 */
int dpdk_get_port_queue_total(void)
{
	int total_rx_queue = 0;
	int port_num = dpdk_get_port_num();
	int port_id;
	for (port_id = 0; port_id < port_num; port_id++)
		total_rx_queue += dpdk_get_port_queue_num(port_id);
	return total_rx_queue;
}
