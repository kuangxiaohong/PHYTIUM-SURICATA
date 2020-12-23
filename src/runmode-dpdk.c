/**
 * \file
 *
 * \author kuangxiaohong <1002361031@qq.com>
 *
 * DPDK support.
 */
#include "suricata-common.h"

#include "dpdk_port_conf.h"
#include "dpdk_param.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"
#include <rte_malloc.h>


#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"


#define RUN_DPDK_MODE (1)  //1:ids 2:ips

static void* DpdkConfigParser(const char *device)
{
	uint16_t port,queue;
	DpdkIfaceConfig_t *config = rte_zmalloc(NULL, sizeof(DpdkIfaceConfig_t), 0);
	if (config == NULL) {
		printf("DpdkConfigParser error!\n");
		return NULL;
	}
	dpdk_get_port_and_queue(&port,&queue);
	
	config->portid = port;
	config->queueid = queue;
	return config;
}


static int RunModeDpdkWorkers(void)
{
	int ret = 0,i;
	uint16_t rx_threads = dpdk_get_port_queue_total();
	
	char tname[50] = {""};
	ThreadVars *tv_worker = NULL;
	TmModule *tm_module = NULL;

	RunModeInitialize();
	TimeModeSetLive();

	dpdk_ports_print();
	check_all_ports_link_status(dpdk_get_port_num(), (~0x0));
	dpdk_port_start();
	for ( i = 0; i < rx_threads; i++) {
		snprintf(tname, sizeof(tname), "phytium-dpdk-%03d", i);

		tv_worker = TmThreadCreatePacketHandler(tname,"packetpool", "packetpool","packetpool", "packetpool","pktacqloop");
		if (tv_worker == NULL) {
			printf("error: TmThreadsCreate failed for (%s)", tname);
			exit(EXIT_FAILURE);
		}

		tm_module = TmModuleGetByName("ReceiveDPDK");
		if (tm_module == NULL) {
			printf(" error:TmModuleGetByName failed for ReceiveDPDK");
			exit(EXIT_FAILURE);
		}
		void *recv_ptr = DpdkConfigParser(NULL);
		if (recv_ptr == NULL) {
			printf(" error: failed to create Data for RECV thread");
			exit(EXIT_FAILURE);
		}

		TmSlotSetFuncAppend(tv_worker, tm_module, (void *)recv_ptr);
		TmThreadSetCPU(tv_worker, WORKER_CPU_SET);

		/*
		 * If pre-acl is configured, use decode thread to process the frames.
		 */

		tm_module = TmModuleGetByName("DecodeDPDK");
		if (tm_module == NULL) {
			printf(" error: TmModuleGetByName failed for DecodeDPDK");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		tm_module = TmModuleGetByName("FlowWorker");
		if (tm_module == NULL) {
			printf( " error:TmModuleGetByName for FlowWorker failed");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		tm_module = TmModuleGetByName("RespondReject");
		if (tm_module == NULL) {
			printf("ERROR: TmModuleGetByName for RespondReject failed");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		if (TmThreadSpawn(tv_worker) != TM_ECODE_OK) {
			printf("ERROR: TmThreadSpawn failed\n");
			exit(EXIT_FAILURE);
		}

		printf(" ceated %s for count %d \n", tname, i);
	}

	printf("RunMode DPDK workers initialised");

	return ret;
}

uint8_t GetDpdkRunMode(void)
{
	return RUN_DPDK_MODE; 
}


void RunModeDpdkRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "worker",
                              "Workers dpdk mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeDpdkWorkers);
	return;
}

