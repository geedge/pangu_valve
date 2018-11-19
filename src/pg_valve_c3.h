#ifndef __PANGU_VALVE_C3_H__
#define __PANGU_VALVE_C3_H__

#include "grule_for_view.h"
#include "pg_valve_tools.h"
#include "pg_valve_stat.h"

#define G_DIR_DOUBLE 0
#define G_DIR_C2S 1
#define G_DIR_S2C 2

#define C3CLIENTLEN 8      	

#define DISP_SUCC 10
#define DISP_FAIL_C3 -20
#define DISP_FAIL_C3_CHECK -30
#define DISP_LIMIT -40
#define DISP_RETRY -50

//一级直接生效表，KEY: CONFIG_STRING
typedef struct __one_config_hnode
{
	grule_t grule; 
	int32_t disp_status; //两个方向下发的状态，下发成功后置1，不成功或未下发时是0；STATUS_BIT_ORIGINAL/STATUS_BIT_REVERSE
}one_config_hnode_t;

int dispatch_config_to_c3(const char *table_name, int service_id, int table_id, one_config_hnode_t &config_node);

typedef struct __pg_grule_handle
{
	grule_hdl_t grule_handle;
	pthread_mutex_t mutex_lock;
	pthread_t signal_thid;
	int first_connect;
}pg_grule_handle_t;

void clear_c3_first_status(void);
bool global_init_grule_handle(const char *auth_data_str, int len, const char *ccc_list, pthread_t signal_thid);

#define DIP 0x4
#define DIP_PROTO 0x104
#define DIP_DPORT_PROTO 0x144
#define DIP_SPORT_PROTO 0x114
#define DIP_SPORT_DPORT_PROTO 0x154
#define SIP 0x1
#define SIP_PROTO 0x101
#define SIP_DPORT_PROTO 0x141
#define SIP_SPORT_PROTO 0x111
#define SIP_SPORT_DPORT_PROTO 0x151
#define SIP_DIP 0x5
#define SIP_DIP_PROTO 0x105
#define SIP_DIP_DPORT_PROTO 0x145
#define SIP_DIP_SPORT_PROTO 0x115
#define SIP_DIP_SPORT_DPORT_PROTO 0x155
#define DIP_MDIP 0xc
#define DIP_MDIP_PROTO_MPROTO 0x30c
#define DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO 0x3cc
#define DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO 0x33c
#define DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO 0x3fc
#define SIP_MSIP 0x3
#define SIP_MSIP_PROTO_MPROTO 0x303
#define SIP_MSIP_DPORT_MDPORT_PROTO_MPROTO 0x3c3
#define SIP_MSIP_SPORT_MSPORT_PROTO_MPROTO 0x333
#define SIP_MSIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO 0x3f3
#define SIP_MSIP_DIP_MDIP 0xf
#define SIP_MSIP_DIP_MDIP_PROTO_MPROTO 0x30f
#define SIP_MSIP_DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO 0x3cf
#define SIP_MSIP_DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO 0x33f
#define SIP_MSIP_DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO 0x3ff

#endif

