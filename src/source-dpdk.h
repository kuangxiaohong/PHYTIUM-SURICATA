#ifndef __SOURCE_DPDK_H__
#define __SOURCE_DPDK_H__

#include <stddef.h>
#include "suricata-common.h"

#include "threadvars.h"
#include "tm-threads.h"
#include "decode.h"



typedef struct DpdkIfaceConfig
{
	uint16_t portid;
	uint16_t queueid;

} DpdkIfaceConfig_t;


/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct DpdkThreadVars_
{

	ThreadVars *tv;
	TmSlot *slot;
	Packet *in_p;
	uint8_t mode;

	uint16_t portid;
	uint16_t queueid;

} DpdkThreadVars;

int InitDpdkSuricata(int argc, char **argv) ;

void TmModuleReceiveDpdkRegister (void);
void TmModuleDecodeDpdkRegister (void);



#endif

