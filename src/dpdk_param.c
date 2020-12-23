/**
 * \file
 *
 * \author kuangxiaohong <1002361031@qq.com>
 *
 * DPDK support.
 */

#include "dpdk_param.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <rte_cfgfile.h>


//#define DEBUG_PARAM 

#ifdef  DEBUG_PARAM
#define DEBUG(fmt,args...) printf(fmt, ##args)
#else
#define DEBUG(fmt,args...) /* do nothing */
#endif

#define MAX_EAL_ENTRY (32)
static char argument[MAX_EAL_ENTRY][MAX_EAL_ENTRY * 2] = {{"./build/app/phytium_dpdk"}, {""}};
static uint16_t argument_count = 1;
static char *args[MAX_EAL_ENTRY];

static dpdk_port_conf_t dpdk_ports[RTE_MAX_ETHPORTS];
static int dpdk_port_num = 0;  

/**
 *dpdk配置文件解析
 *
 * @param  
 * 	 
 * @return 0成功，其它失败
 *   
 */
int dpdk_conf_parse(void)
{
	int i,j;
	struct rte_cfgfile *file = NULL;
	struct rte_cfgfile_entry entries[MAX_EAL_ENTRY];

	file = rte_cfgfile_load("dpdk.cfg", 0);

	if (file == NULL){
		printf("rte_cfgfile_load:%s\n","dpdk.cfg");
		return -1;
	}
		

	/* get section name EAL */
	if (rte_cfgfile_has_section(file, "EAL")) {

		DEBUG(" section (EAL); count %d\n", rte_cfgfile_num_sections(file, "EAL", sizeof("EAL") - 1));
		DEBUG(" section (EAL) has entries %d\n", rte_cfgfile_section_num_entries(file, "EAL"));

		int n_entries = rte_cfgfile_section_num_entries(file, "EAL");
		if (n_entries > MAX_EAL_ENTRY)
		{
			DEBUG("EAL entry (%d) overflow!\n",n_entries);
			return -1;
		}

		if (rte_cfgfile_section_entries(file, "EAL", entries, n_entries) != -1) {
			for (i = 0; i < n_entries; i++) {
				DEBUG(" - name: (%s) value: (%s)\n", entries[i].name, entries[i].value);
				snprintf(argument[i * 2 + 1], MAX_EAL_ENTRY * 2, "%s", entries[i].name);
				snprintf(argument[i * 2 + 2], MAX_EAL_ENTRY * 2, "%s", entries[i].value);
				DEBUG(" - argument: (%s) (%s)\n", argument[i * 2 + 1], argument[i * 2 + 2]);
			    argument_count += (((entries[i].name) ? 1 : 0) + ((entries[i].value) ? 1 : 0));
			}
		}
	}

	/* get section name PORT-X */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		char port_section_name[15] = {""};

		sprintf(port_section_name, "%s%d", "PORT-", i);
		if (rte_cfgfile_has_section(file, port_section_name)) {
			dpdk_port_num++;
			int n_port_entries = rte_cfgfile_section_num_entries(file, port_section_name);

			DEBUG(" %s\n", port_section_name);
			DEBUG(" section (PORT) has %d entries\n", n_port_entries);

			struct rte_cfgfile_entry entries[MAX_EAL_ENTRY];
			if (rte_cfgfile_section_entries(file, port_section_name, entries, n_port_entries) != -1) {

				for (j = 0; j < n_port_entries; j++) {
					DEBUG(" section_name %s entry_name: (%s) entry_value: (%s)\n", port_section_name, entries[j].name, entries[j].value);
			
					if (strcasecmp("mtu", entries[j].name) == 0)
						dpdk_ports[i].mtu = atoi(entries[j].value);
					else if (strcasecmp("rss-tuple", entries[j].name) == 0)
						dpdk_ports[i].rss_tuple = atoi(entries[j].value);
					else if (strcasecmp("jumbo", entries[j].name) == 0)
						dpdk_ports[i].jumbo = (strcasecmp(entries[j].value, "yes") == 0) ? 1 : 0;
					else if (strcasecmp("queue-num", entries[j].name) == 0)
						dpdk_ports[i].queue_num= atoi(entries[j].value);
					//todo:other port conf
				}
			}
		}
	}

	rte_cfgfile_close(file);
	return 0;
}

/**
 *dpdk配置参数个数获取
 *
 * @param  
 * 	 
 * @return 返回配置参数个数
 *   
 */
int dpdk_get_param_cnt(void)
{
	DEBUG("argument count (%d)\n",argument_count);
	return argument_count;
}

/**
 *dpdk配置参数获取
 *
 * @param  
 * 	 
 * @return 返回配置参数
 *   
 */
char **dpdk_get_param(void)
{
	int i,j;
	for (j = 0; j < argument_count; j++)
        args[j] = argument[j];
	
	for (i = 0; i < argument_count; i++)
		DEBUG("	%s\n",argument[i]);
	return (char **)args;
}


/**
 *dpdk网口配置个数获取
 *
 * @param  
 * 	 
 * @return 返回网口配置个数
 *   
 */
int dpdk_get_port_cnt(void)
{
	DEBUG("dpdk port count (%d)\n",dpdk_port_num);
	return dpdk_port_num;
}


/**
 *dpdk网口配置信息获取
 *
 * @param  
 * 	 
 * @return 返回某个网口配置信息
 *   
 */
dpdk_port_conf_t* dpdk_get_port_conf(int port_id)
{
	if (port_id >= RTE_MAX_ETHPORTS)
	{
		printf("dpdk_get_port_conf invalid port_id\n");
		return NULL;
	}
	
	DEBUG("dpdk port_id(%d) port_queue_num(%d)\n",port_id,dpdk_ports[port_id].queue_num);	
	DEBUG("dpdk port_id(%d) port_rss_tuple(%d)\n",port_id,dpdk_ports[port_id].rss_tuple);
	DEBUG("dpdk port_id(%d) port_mtu(%d)\n",port_id,dpdk_ports[port_id].mtu);	
	DEBUG("dpdk port_id(%d) port_jumbo(%s)\n",port_id,(dpdk_ports[port_id].jumbo == 1) ? "yes" : "no" );
	
	return &dpdk_ports[port_id];
}
   

