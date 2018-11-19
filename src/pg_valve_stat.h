#ifndef __PANGU_VALVE_STAT_H__
#define __PANGU_VALVE_STAT_H__

#include <map>
#include <iostream>
#include <string>

#include <MESA/field_stat2.h>
#include <MESA/MESA_handle_logger.h>

using namespace std;

typedef enum __STAT_SERVICE_TYPE
{	
	STAT_SERVICE_NONE=0,
	STAT_SERVICE_ADD,
	STAT_SERVICE_DEL,
}STAT_SERVICE_TYPE_t;

typedef struct __stat_service_priv
{
	u_int32_t log_num;
	STAT_SERVICE_TYPE_t type;
}stat_service_priv_t;

typedef struct __stat_service_hnode
{
	u_int64_t cur_num;
	u_int64_t max_num;
}stat_service_hnode_t;

typedef enum __STAT_FIELD_EXIST
{
	STAT_FIELD_EXITS=0,
	STAT_FIELD_PENDING,
	STAT_FIELD_EACTIVE,
	STAT_FIELD_EINACTIVE,

	STAT_EXIST_NUM,
}STAT_FIELD_EXIST_t;

typedef enum __STAT_FIELD_INCR
{
	STAT_FIELD_RECV=0,
	STAT_FIELD_RERROR,
	STAT_FIELD_RVALID,
	STAT_FIELD_RINVALID,
	STAT_FIELD_DISP_SUCC,
	STAT_FIELD_DISP_FAIL,
	STAT_FIELD_DISP_LIMIT,

	STAT_INCR_NUM,
}STAT_FIELD_INCR_t;

typedef struct __statistic_exist
{
	u_int64_t num[STAT_EXIST_NUM];
}statistic_exist_t;

typedef struct __statistic_incr
{
	u_int64_t num[STAT_INCR_NUM];
}statistic_incr_t;

typedef struct __stat_table_key
{
	int32_t service_id;
	int32_t table_id;
}stat_table_key_t;

typedef struct __stat_table_priv
{
	int64_t log_num;
	STAT_FIELD_INCR_t type;
}stat_table_priv_t;

void pz_trans_statistic_count(int32_t service_id, int32_t table_id, int32_t log_num, STAT_FIELD_INCR_t type);

int service_grule_setup_hnode(int32_t serv_type, u_int64_t max_num);
void service_grule_statistic_count(int32_t serv_type, int32_t log_num, STAT_SERVICE_TYPE_t stat_type);
bool service_grule_reach_limit(int32_t serv_type);
void service_config_clear(void);

#endif

