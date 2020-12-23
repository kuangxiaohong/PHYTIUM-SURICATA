/**
 * \file
 *
 * \author kuangxiaohong <1002361031@qq.com>
 *
 * DPDK support.
 */

#include <sys/queue.h>

#include "source-dpdk.h"
#include "dpdk_port_conf.h"
#include "dpdk_param.h"
#include "runmode-dpdk.h"
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "suricata.h"
#include "host.h"
#include "packet-queue.h"
#include "threads.h"
#include "tm-queuehandlers.h"
#include "tm-threads-common.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-mem.h"
#include "util-profiling.h"
#include "tmqh-packetpool.h"
#include "pkt-var.h"

TmEcode DecodeDpdkThreadInit(ThreadVars *,const void *, void **);
TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data);
TmEcode ReceiveDpdkInit(ThreadVars *tv,const void *initdata, void **data);
TmEcode ReceiveDpdkDeinit(ThreadVars *tv, void *data);
TmEcode DecodeDpdk(ThreadVars *tv, Packet *p, void *data);
void DpdkReleasePacket(Packet *p);
TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot);
void DpdkFowardPacket(Packet *p);

int InitDpdkSuricata(int argc, char **argv) 
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)	
		return ret;
	dpdk_port_setup();
	return ret;
}


TmEcode ReceiveDpdkInit(ThreadVars *tv,const void *initdata, void **data)
{
	if (initdata == NULL) {
		SCLogError(SC_ERR_DPDK_PROC, " init data is empty");
		SCReturnInt(TM_ECODE_FAILED);
	}

	DpdkThreadVars *ptv = rte_zmalloc(NULL, sizeof(DpdkThreadVars), 0);
	if (unlikely(ptv == NULL)) {
		SCLogError(SC_ERR_DPDK_PROC, "failed to alloc memory");
		SCReturnInt(TM_ECODE_FAILED);
	}

	ptv->tv = tv;

	DpdkIfaceConfig_t *dpdkconf = (DpdkIfaceConfig_t *) initdata;

	ptv->portid = dpdkconf->portid;
	ptv->queueid = dpdkconf->queueid;
	ptv->mode = GetDpdkRunMode(); //1: IDS 2:IPS 0:OTHER
	*data = (void *)ptv;

	SCLogDebug("completed thread initialization for dpdk receive\n");
	SCReturnInt(TM_ECODE_OK);
}

void DpdkFowardPacket(Packet *p)
{
	int ret;
	struct rte_mbuf *m = (struct rte_mbuf *) p->dpdk_mbufPtr;
	
	//current foward from same port
	if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) 
		rte_pktmbuf_free(m);
	else{ 	
		//printf("DpdkFowardPacket2 port:%d queue:%d\n",p->dpdk_forward_port,p->dpdk_forward_queue);
		if ((ret = rte_eth_tx_burst(p->dpdk_forward_port, p->dpdk_forward_queue, &m, 1)) != 1) 
			rte_pktmbuf_free(m);
	}
	
    PacketFreeOrRelease(p);
	return;
}


void DpdkReleasePacket(Packet *p)
{
	//printf("DpdkReleasePacket\n");
    struct rte_mbuf *m = (struct rte_mbuf *) p->dpdk_mbufPtr;
	rte_pktmbuf_free(m);
    PacketFreeOrRelease(p);
    return;
}


static inline
Packet *DpdkProcessPacket(DpdkThreadVars *ptv, struct rte_mbuf *m)
{
	u_char *pkt = rte_pktmbuf_mtod(m, u_char *);
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCLogError(SC_ERR_DPDK_PROC, "Failed to get Packet Buffer for DPDK mbuff!");
        return NULL;
    }

    // printf(" DpdkProcessPacket packet %p for byte %d %ld %p\n", p, m->pkt_len, sizeof(Packet),m);
    PACKET_RECYCLE(p);
	PKT_SET_SRC(p, PKT_SRC_WIRE);

	gettimeofday(&p->ts, NULL);
	
	p->datalink = LINKTYPE_ETHERNET;
	PacketSetData(p, pkt, m->pkt_len);

    p->dpdk_mbufPtr = (void *)m;
	p->dpdk_run_mode =   ptv->mode; 
	p->dpdk_forward_port = ptv->portid;
	p->dpdk_forward_queue = ptv->queueid;
	//printf("ptv->mode:%d",ptv->mode);
	p->ReleasePacket =   (p->dpdk_run_mode == 1) ? DpdkReleasePacket : DpdkFowardPacket;
	return p;
}


TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot)
{
#define MAX_PKT_BURST (32)
#define PREFETCH_OFFSET	(3)

	SCLogDebug(" Loop to fetch and put packets");

	DpdkThreadVars *ptv = (DpdkThreadVars *)data;
	TmSlot *s = (TmSlot *)slot;
	ptv->slot = s->slot_next;
	Packet *p = NULL;

	SCLogDebug(" running on lcore %d port %d queue %d\n", rte_lcore_id(),ptv->portid,ptv->queueid);

	if (unlikely(ptv == NULL)) 
		SCReturnInt(TM_ECODE_FAILED);
	
	while(1) {
		if (suricata_ctl_flags & SURICATA_STOP)	
			SCReturnInt(TM_ECODE_OK);

		struct rte_mbuf *bufs[MAX_PKT_BURST];
		const uint16_t nb_rx = rte_eth_rx_burst(ptv->portid, ptv->queueid, bufs, MAX_PKT_BURST);

		if (likely(nb_rx)) {
			
			printf("receive loop nb_rx(%u) lcore %d port %d queue %d\n",nb_rx,rte_lcore_id(),ptv->portid,ptv->queueid);
			int i, ret;
			for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) 
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
			
			for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {			
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 2], void *));				
				//printf("process loop index(%u)\n",i);
				//rte_pktmbuf_free(bufs[i]);				
				//rte_pktmbuf_dump(stdout,bufs[i],bufs[i]->pkt_len);				
				p = DpdkProcessPacket(ptv, bufs[i]);
			    if (unlikely(NULL == p)) {
                     printf("DpdkProcessPacket failed\n");
                     rte_pktmbuf_free(bufs[i]);
                     continue;
                }
											
				ret = TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);				
				if (unlikely(ret != TM_ECODE_OK)) {
					printf("TmThreadsSlotProcessPkt failed\n");
					TmqhOutputPacketpool(ptv->tv, p);
					SCLogNotice(" failed TmThreadsSlotProcessPkt");
					SCReturnInt(TM_ECODE_FAILED);
				}
			}

			for (; i < nb_rx; i++) {			
				//printf("process loop index(%u)\n",i);
				//rte_pktmbuf_dump(stdout,bufs[i],bufs[i]->pkt_len);
				//rte_pktmbuf_free(bufs[i]);
				p = DpdkProcessPacket(ptv, bufs[i]);
				if (unlikely(NULL == p)) {
					printf("DpdkProcessPacket failed\n");
					rte_pktmbuf_free(bufs[i]);
					continue;
			 	}
			
				ret = TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
				if (unlikely(ret != TM_ECODE_OK)) {
					TmqhOutputPacketpool(ptv->tv, p);
					SCLogNotice(" failed TmThreadsSlotProcessPkt");
					SCReturnInt(TM_ECODE_FAILED);
				}
			}
		}
	}

	SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveDpdkDeinit(ThreadVars *tv, void *data)
{
	/* stop RX queue */
	rte_free(data);
	data = NULL;
	SCReturnInt(TM_ECODE_OK);
}


void TmModuleReceiveDpdkRegister (void)
{
	SCLogDebug("TmModuleReceiveDpdkRegister\n");
	tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
	tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDpdkInit;
	tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDpdkLoop;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDpdkDeinit;
	tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
	tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
	SCReturn;
}


TmEcode DecodeDpdk(ThreadVars *tv, Packet *p, void *data)
{
	//printf("DecodeDpdk enter! data:%p\n",data);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    if (p->flags & PKT_PSEUDO_STREAM_END) {
//        PacketPoolReturnPacket(p);
        return TM_ECODE_OK;
    }

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

	/* call the decoder */
	DecodeEthernet(tv, dtv, p, (uint8_t *) p->ext_pkt /*rte_pktmbuf_mtod(p->dpdk_v.m, uint8_t *)*/,
		 p->pktlen );

    PacketDecodeFinalize(tv, dtv, p);

	//printf("DecodeDpdk out!\n");

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data)
{

	SCLogDebug(" inside DecodeDpdkThreadDeinit ");

	if (data != NULL)
		DecodeThreadVarsFree(tv, data);

	SCLogDebug(" freed data!");

	SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeDpdkThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
	DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}


void TmModuleDecodeDpdkRegister (void)
{
	SCLogDebug("TmModuleDecodeDpdkRegister\n");
	tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
	tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDpdkThreadInit;
	tmm_modules[TMM_DECODEDPDK].Func = DecodeDpdk;
	tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDpdkThreadDeinit;
	tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
	tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;

	SCReturn;
}


