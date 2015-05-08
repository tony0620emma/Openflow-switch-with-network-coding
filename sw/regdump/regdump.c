/* ****************************************************************************
 * $Id: regdump.c 5851 2009-11-13 00:17:17Z grg $
 *
 * Module: regdump.c
 * Project: NetFPGA OpenFlow switch
 * Description: Test program to dump the NetFPGA registers
 *
 * Change history:
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <net/if.h>

#include <time.h>

#include "../../../../lib/C/common/nf2util.h"
#include "../../lib/C/reg_defines_openflow_switch.h"
#include "nf2_drv.h"

#define PATHLEN		80

#define DEFAULT_IFACE	"nf2c0"

/* Global vars */
static struct nf2device nf2;
static int verbose = 0;
static int force_cnet = 0;

/* Function declarations */
void print (void);
void printMAC (unsigned char*);
void printIP (unsigned);
void read_openflow_wildcard_table(int, int *entry_not_zero, nf2_of_entry_wrap *wildcard,
                                  nf2_of_entry_wrap *wildcard_mask,
                                  nf2_of_action_wrap *wildcard_actions);
void print_openflow_table(nf2_of_entry_wrap, nf2_of_entry_wrap, nf2_of_action_wrap );

int main(int argc, char *argv[]) {
	unsigned val;
	nf2.device_name = DEFAULT_IFACE;

	if (check_iface(&nf2)) {
		exit(1);
	}
	if (openDescriptor(&nf2)) {
		exit(1);
	}

	print();
	closeDescriptor(&nf2);
	return 0;
}


void print(void) {
	unsigned val;
	int i, j, entry_not_zero;
	nf2_of_entry_wrap openflow_wildcard_entry;
	nf2_of_entry_wrap openflow_wildcard_mask;
	nf2_of_action_wrap openflow_wildcard_actions;

	//	readReg(&nf2, UNET_ID, &val);
	//	printf("Board ID: Version %i, Device %i\n", GET_VERSION(val), GET_DEVICE(val));
	readReg(&nf2, MAC_GRP_0_CONTROL_REG, &val);
	printf("MAC 0 Control: 0x%08x:  ", val);
	if(val&(1<<MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("TX disabled, ");
	}
	else {
	  printf("TX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("RX disabled, ");
	}
	else {
	  printf("RX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RESET_MAC_BIT_NUM)) {
	  printf("reset on\n");
	}
	else {
	  printf("reset off\n");
	}
	printf("mac config 0x%02x\n", val>>MAC_GRP_MAC_DISABLE_TX_BIT_NUM);

	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_PKTS_STORED_REG, &val);
	printf("Num pkts enqueued to rx queue 0:    %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG, &val);
	printf("Num pkts dropped (rx queue 0 full): %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG, &val);
	printf("Num pkts dropped (bad fcs q 0):     %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of rx queue 0: %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of rx queue 0: %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG, &val);
	printf("Num pkts dequeued from rx queue 0:  %u\n", val);
	readReg(&nf2, MAC_GRP_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in rx queue 0:             %u\n", val);

	readReg(&nf2, MAC_GRP_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in tx queue 0:             %u\n", val);
	readReg(&nf2, MAC_GRP_0_TX_QUEUE_NUM_PKTS_SENT_REG, &val);
	printf("Num pkts dequeued from tx queue 0:  %u\n", val);
	readReg(&nf2, MAC_GRP_0_TX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of tx queue 0: %u\n", val);
	readReg(&nf2, MAC_GRP_0_TX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of tx queue 0: %u\n", val);
	readReg(&nf2, MAC_GRP_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG, &val);
	printf("Num pkts enqueued to tx queue 0:    %u\n\n", val);

	readReg(&nf2, MAC_GRP_1_CONTROL_REG, &val);
	printf("MAC 1 Control: 0x%08x ", val);
	if(val&(1<<MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("TX disabled, ");
	}
	else {
	  printf("TX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("RX disabled, ");
	}
	else {
	  printf("RX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RESET_MAC_BIT_NUM)) {
	  printf("reset on\n");
	}
	else {
	  printf("reset off\n");
	}
	printf("mac config 0x%02x\n", val>>MAC_GRP_MAC_DISABLE_TX_BIT_NUM);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_PKTS_STORED_REG, &val);
	printf("Num pkts enqueued to rx queue 1:    %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG, &val);
	printf("Num pkts dropped (rx queue 1 full): %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG, &val);
	printf("Num pkts dropped (bad fcs q 1):     %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of rx queue 1: %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of rx queue 1: %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG, &val);
	printf("Num pkts dequeued from rx queue 1:  %u\n", val);
	readReg(&nf2, MAC_GRP_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in rx queue 1:             %u\n", val);

	readReg(&nf2, MAC_GRP_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in tx queue 1:             %u\n", val);
	readReg(&nf2, MAC_GRP_1_TX_QUEUE_NUM_PKTS_SENT_REG, &val);
	printf("Num pkts dequeued from tx queue 1:  %u\n", val);
	readReg(&nf2, MAC_GRP_1_TX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of tx queue 1: %u\n", val);
	readReg(&nf2, MAC_GRP_1_TX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of tx queue 1: %u\n", val);
        readReg(&nf2, MAC_GRP_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG, &val);
        printf("Num pkts enqueued to tx queue 1:    %u\n\n", val);

	readReg(&nf2, MAC_GRP_2_CONTROL_REG, &val);
	printf("MAC 2 Control: 0x%08x ", val);
	if(val&(1<<MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("TX disabled, ");
	}
	else {
	  printf("TX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("RX disabled, ");
	}
	else {
	  printf("RX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RESET_MAC_BIT_NUM)) {
	  printf("reset on\n");
	}
	else {
	  printf("reset off\n");
	}
	printf("mac config 0x%02x\n", val>>MAC_GRP_MAC_DISABLE_TX_BIT_NUM);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_PKTS_STORED_REG, &val);
	printf("Num pkts enqueued to rx queue 2:    %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG, &val);
	printf("Num pkts dropped (rx queue 2 full): %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG, &val);
	printf("Num pkts dropped (bad fcs q 2):     %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of rx queue 2: %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of rx queue 2: %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG, &val);
	printf("Num pkts dequeued from rx queue 2:  %u\n", val);
	readReg(&nf2, MAC_GRP_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in rx queue 2:             %u\n", val);

	readReg(&nf2, MAC_GRP_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in tx queue 2:             %u\n", val);
	readReg(&nf2, MAC_GRP_2_TX_QUEUE_NUM_PKTS_SENT_REG, &val);
	printf("Num pkts dequeued from tx queue 2:  %u\n", val);
	readReg(&nf2, MAC_GRP_2_TX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of tx queue 2: %u\n", val);
	readReg(&nf2, MAC_GRP_2_TX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of tx queue 2: %u\n", val);
        readReg(&nf2, MAC_GRP_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG, &val);
        printf("Num pkts enqueued to tx queue 2:    %u\n\n", val);

	readReg(&nf2, MAC_GRP_3_CONTROL_REG, &val);
	printf("MAC 3 Control: 0x%08x ", val);
	if(val&(1<<MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("TX disabled, ");
	}
	else {
	  printf("TX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM)) {
	  printf("RX disabled, ");
	}
	else {
	  printf("RX enabled,  ");
	}
	if(val&(1<<MAC_GRP_RESET_MAC_BIT_NUM)) {
	  printf("reset on\n");
	}
	else {
	  printf("reset off\n");
	}
        printf("mac config 0x%02x\n", val>>MAC_GRP_MAC_DISABLE_TX_BIT_NUM);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_PKTS_STORED_REG, &val);
	printf("Num pkts enqueued to rx queue 3:    %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG, &val);
	printf("Num pkts dropped (rx queue 3 full): %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG, &val);
	printf("Num pkts dropped (bad fcs q 3):     %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of rx queue 3: %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of rx queue 3: %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG, &val);
	printf("Num pkts dequeued from rx queue 3:  %u\n", val);
	readReg(&nf2, MAC_GRP_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in rx queue 3:             %u\n", val);

	readReg(&nf2, MAC_GRP_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG, &val);
	printf("Num pkts in tx queue 3:             %u\n", val);
	readReg(&nf2, MAC_GRP_3_TX_QUEUE_NUM_PKTS_SENT_REG, &val);
	printf("Num pkts dequeued from tx queue 3:  %u\n", val);
	readReg(&nf2, MAC_GRP_3_TX_QUEUE_NUM_WORDS_PUSHED_REG, &val);
	printf("Num words pushed out of tx queue 3: %u\n", val);
	readReg(&nf2, MAC_GRP_3_TX_QUEUE_NUM_BYTES_PUSHED_REG, &val);
	printf("Num bytes pushed out of tx queue 3: %u\n", val);
        readReg(&nf2, MAC_GRP_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG, &val);
        printf("Num pkts enqueued to tx queue 3:    %u\n\n", val);

	readReg(&nf2, IN_ARB_NUM_PKTS_SENT_REG, &val);
	printf("IN_ARB_NUM_PKTS_SENT_REG            %u\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_WORD_0_LO_REG, &val);
	printf("IN_ARB_LAST_PKT_WORD_0_LO_REG       0x%08x\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_WORD_0_HI_REG, &val);
	printf("IN_ARB_LAST_PKT_WORD_0_HI_REG       0x%08x\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_CTRL_0_REG, &val);
	printf("IN_ARB_LAST_PKT_CTRL_0_REG          0x%02x\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_WORD_1_LO_REG, &val);
	printf("IN_ARB_LAST_PKT_WORD_1_LO_REG       0x%08x\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_WORD_1_HI_REG, &val);
	printf("IN_ARB_LAST_PKT_WORD_1_HI_REG       0x%08x\n", val);
	readReg(&nf2, IN_ARB_LAST_PKT_CTRL_1_REG, &val);
	printf("IN_ARB_LAST_PKT_CTRL_1_REG          0x%02x\n", val);
	readReg(&nf2, IN_ARB_STATE_REG, &val);
	printf("IN_ARB_STATE_REG                    %u\n\n", val);

	readReg(&nf2, BRAM_OQ_DISABLE_QUEUES_REG, &val);
	printf("BRAM_OQ_DISABLE_QUEUES_REG                    %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_0_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_0_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_0_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_0_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_0_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_0_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_0_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_0_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_1_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_1_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_1_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_1_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_1_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_1_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_1_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_1_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_2_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_2_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_2_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_2_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_2_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_2_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_2_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_2_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_3_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_3_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_3_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_3_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_3_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_3_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_3_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_3_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_4_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_4_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_4_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_4_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_4_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_4_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_4_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_4_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_5_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_5_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_5_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_5_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_5_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_5_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_5_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_5_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_6_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_6_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_6_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_6_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_6_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_6_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_6_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_6_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	readReg(&nf2, BRAM_OQ_QUEUE_7_NUM_PKT_BYTES_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_7_NUM_PKT_BYTES_RECEIVED_REG    %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_7_NUM_PKTS_RECEIVED_REG, &val);
	printf("BRAM_OQ_QUEUE_7_NUM_PKTS_RECEIVED_REG         %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_7_NUM_PKTS_DROPPED_REG, &val);
	printf("BRAM_OQ_QUEUE_7_NUM_PKTS_DROPPED_REG          %u\n", val);
	readReg(&nf2, BRAM_OQ_QUEUE_7_NUM_WORDS_IN_QUEUE_REG, &val);
	printf("BRAM_OQ_QUEUE_7_NUM_WORDS_IN_QUEUE_REG        %u\n\n", val);

	printf("OPENFLOW_WILDCARD_TABLE_SIZE                  %u\n",
	        OPENFLOW_WILDCARD_TABLE_SIZE);
	printf("OPENFLOW_WILDCARD_NUM_DATA_WORDS_USED         %u\n",
	        OPENFLOW_WILDCARD_NUM_DATA_WORDS_USED);
	printf("OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED          %u\n\n",
	        OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED);

	readReg(&nf2, OPENFLOW_LOOKUP_WILDCARD_MISSES_REG, &val);
	printf("OPENFLOW_LOOKUP_WILDCARD_MISSES_REG           %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_WILDCARD_HITS_REG, &val);
	printf("OPENFLOW_LOOKUP_WILDCARD_HITS_REG             %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_EXACT_MISSES_REG, &val);
	printf("OPENFLOW_LOOKUP_EXACT_MISSES_REG              %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_EXACT_HITS_REG, &val);
	printf("OPENFLOW_LOOKUP_EXACT_HITS_REG                %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_0_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_0_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_1_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_1_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_2_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_2_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_3_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_3_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_4_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_4_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_5_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_5_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_6_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_6_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_7_REG, &val);
	printf("OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_7_REG        %u\n",val);
	readReg(&nf2, OPENFLOW_LOOKUP_TIMER_REG, &val);
	printf("OPENFLOW_LOOKUP_TIMER_REG                     %u\n\n",val);

	readReg(&nf2, WDT_ENABLE_FLG_REG, &val);
	printf("WDT_ENABLE_FLG_REG                            0x%08x\n",val);
	readReg(&nf2, WDT_COUNTER_REG, &val);
	printf("WDT_COUNTER_REG                               %u\n\n",val);

	for(i=0; i<OPENFLOW_WILDCARD_TABLE_SIZE; i=i+1){
		//Read the Header data from the table
		read_openflow_wildcard_table(i, &entry_not_zero,
		                             &openflow_wildcard_entry,
		                             &openflow_wildcard_mask,
		                             &openflow_wildcard_actions);

		if (entry_not_zero == 1) {
			printf("#    tr_d tr_s pr ts ip_dst          ip_src          type eth_dst      eth_src      sp vlan\n");
			printf("%02u", i);
			//Print the entry
			print_openflow_table(openflow_wildcard_entry,
			                     openflow_wildcard_mask,
			                     openflow_wildcard_actions);
		}
	}
	printf("\n");
}


//
// printMAC: print a MAC address as a : separated value. eg:
//    00:11:22:33:44:55
//
void printMAC(unsigned char* mac) {
	int j;

	for(j = 0; j < 6; ++j) {
		printf("%02x", mac[j]);
	}
}


//
// printIP: print an IP address in dotted notation. eg: 192.168.0.1
//
void printIP(unsigned ip) {
	printf("%03u.%03u.%03u.%03u",
	       ((ip>>24)&0xff), ((ip>>16)&0xff), ((ip>>8)&0xff), ((ip>>0)&0xff));
}


void read_openflow_wildcard_table(int index, int *entry_not_zero,
                                  nf2_of_entry_wrap *wildcard,
                                  nf2_of_entry_wrap *wildcard_mask,
                                  nf2_of_action_wrap *wildcard_actions) {
	int j;

	*entry_not_zero = 0;

	writeReg(&nf2, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, index);

	//Read the Header data from the table
	for(j=0; j<OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED; j=j+1) {
		readReg(&nf2, OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG + j * 4,
		        &wildcard->raw[j]);
		if (wildcard->raw[j] != 0)
			*entry_not_zero = 1;
		readReg(&nf2, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG + j * 4,
		        &wildcard_mask->raw[j]);
		if (wildcard_mask->raw[j] != 0)
			*entry_not_zero = 1;
	}

	//Read the Action data from the table
	for (j=0; j<OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED; j=j+1) {
		readReg(&nf2, OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG + j * 4,
		        &wildcard_actions->raw[j]);
		if (wildcard_actions->raw[j] != 0)
			*entry_not_zero = 1;
	}
}


void print_openflow_table(nf2_of_entry_wrap wildcard, nf2_of_entry_wrap wildcard_mask,
                          nf2_of_action_wrap wildcard_actions) {
	int j;
	unsigned val;

	//print entry
	printf(" E");
	printf(" %04x %04x", wildcard.entry.transp_dst, wildcard.entry.transp_src);
	printf(" %02x %02x", wildcard.entry.ip_proto, wildcard.entry.ip_tos);
	printf(" ");
	printIP(wildcard.entry.ip_dst);
	printf(" ");
	printIP(wildcard.entry.ip_src);
	printf(" %04x ", wildcard.entry.eth_type);
	printMAC(wildcard.entry.eth_dst);
	printf(" ");
	printMAC(wildcard.entry.eth_src);
	printf(" %02x %04x\n",  wildcard.entry.src_port, wildcard.entry.vlan_id);

	//print mask
	printf("   M");
	printf(" %04x %04x", wildcard_mask.entry.transp_dst, wildcard_mask.entry.transp_src);
	printf(" %02x %02x", wildcard_mask.entry.ip_proto, wildcard_mask.entry.ip_tos);
	printf(" ");
	printIP(wildcard_mask.entry.ip_dst);
	printf(" ");
	printIP(wildcard_mask.entry.ip_src);
	printf(" %04x ", wildcard_mask.entry.eth_type);
	printMAC(wildcard_mask.entry.eth_dst);
	printf(" ");
	printMAC(wildcard_mask.entry.eth_src);
	printf(" %02x %04x\n",  wildcard_mask.entry.src_port, wildcard_mask.entry.vlan_id);

	//Print the Actions
	printf("   A dp: ");
	for(j=0; j<8; ++j) {
		printf("%i", ((*((char*)wildcard_actions.raw)) >> j) & 0x1);
	}
	printf("\n     ");
	for (j=0; j<OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED; j=j+1){
		printf("%08x ", wildcard_actions.raw[j]);
	}
	printf("\n");
}

