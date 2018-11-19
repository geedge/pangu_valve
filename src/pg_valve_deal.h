#ifndef __PANGU_VAVLE_DEAL_H__
#define __PANGU_VAVLE_DEAL_H__

#include <iostream>
#include <map>

#include <MESA/Maat_rule.h>

#include "pg_valve_c3.h"
#include "pg_valve_tools.h"

using namespace std;

//IP域表的类型
#define REGION_TYPE_IP 1
#define REGION_TYPE_FIND 2
#define REGION_TYPE_POOL 3

typedef enum __SSCANF_ERROR_NO
{
	SSCANF_OK=0,
	SSCANF_ERROR_NUM,
	SSCANF_ERROR_DID,
	SSCANF_ERROR_DSETID,
	SSCANF_ERROR_LIMIT,
	SSCANF_ERROR_SERVICE,
	SSCANF_ERROR_PROTOCOL,
	SSCANF_ERROR_IP,
	SSCANF_ERROR_TUPLE,
	SSCANF_ERROR_RULE,
}SSCANF_ERROR_NO_t;

typedef enum __SW_STAT
{
	SW_STAT_NONE = 0,
	SW_STAT_ACTIVATE = 1,
	SW_STAT_DEACTIVATE = 2,
}SW_STAT_t;

typedef struct __grule_map_info
{
	int32_t serv_type;
	int32_t rule_scope;
}grule_map_info_t;

typedef struct __table_hash_key
{
	int32_t service_id;
	int32_t table_id;
	int64_t dsetid;
	int64_t did;
}table_hash_key_t;

typedef struct __swtable_state
{
	SW_STAT_t switcher;
	grule_map_info_t gmap_info;
}swtable_state_t;

//带开关的二级开关表
//两级开关KEY: ServiceID+TableID+DSET+DID，查找到DID所辖的所有配置ID
//全量or增量事件结束时进行:
//增量动作
typedef struct __onesw_config_hnode
{
	int64_t dsetid; //若不存在三级开关，设置为0
	int64_t did;
	map<int64_t, one_config_hnode_t> full; //KEY:cfg_id，DID的域配置生效全量；
}onesw_config_hnode_t;

//两级开关KEY: ServiceID+TableID+DSET+DID，变换TableID
typedef struct __two_config_hnode
{
	int64_t dsetid; //若不存在三级开关，设置为0
	int64_t did;
	SW_STAT_t sw_status; //KEY: DID；VALUE: 开关状态
	grule_map_info_t gmap_info;//无父开关时有效
	time_t last_invalid;
}two_config_hnode_t;

//三级开关表，KEY: ServiceID+TableID+DSET
typedef struct __three_config_hnode
{
	int64_t dsetid;
	SW_STAT_t sw_status; //DSET的开关
	grule_map_info_t gmap_info;
	bool exist_before;
	map<int64_t, int64_t> didset;//KEY: DID；VALUE: 无所谓
	time_t last_invalid; //设置为失效时刻的时间，遍历时若超时，删除元素
}three_config_hnode_t;

typedef struct __configure_table
{
	const char *table_name;
	int32_t service_id;
	int32_t table_id_key;
	MESA_htable_handle hash_handle;
	bool over_flag;	//己全量是否完成
	int32_t action;
	int32_t region_type;
	int32_t table_id_maat;
	int32_t statid_table;

	//返回值：0-节点不存在；1-节点存在
	int32_t (*get_hnode_sw_action_recur)(struct __configure_table *table, int64_t dsetid, int64_t did, swtable_state_t *result);
	int32_t (*drive_full_cfg_by_parent)(struct __configure_table *table, int64_t dsetid, int64_t did, swtable_state_t *sw_state);
	int32_t (*update_hnode_dset)(struct __configure_table *table, int64_t dsetid, int64_t did);

	Maat_start_callback_t *maat_start_cb;
	Maat_update_callback_t *maat_update_cb;
	Maat_finish_callback_t *maat_finish_cb;

	struct __configure_table *parent;//当前表的开关表；初始化填充
	struct __configure_table *child; //开关表的孩子表；初始化填充
	struct __configure_table *next; //开关表的孩子表的兄弟表，可以是不同级别的孩子表；初始化填充
}configure_table_t;

typedef struct __htable_privdata
{
	configure_table_t *table;
	int64_t dsetid; //three驱动onesw时，该值是啥?
	int64_t did;
	union{
		one_config_hnode_t iprule;  //域表的配置
		SW_STAT_t did_switch; //开关表的配置
	};
	grule_map_info_t gmap_info; //开关表下发C3的servtype
}htable_privdata_t;

void one_destroy_hnode(void *data);
void two_destroy_hnode(void *data);
void three_destroy_hnode(void *data);

configure_table_t *new_table_instance_one(const char *table_name, int32_t service_id, int32_t table_id, int32_t region_type, MESA_htable_handle hash_handle);
configure_table_t *new_table_instance_onesw(const char *table_name, int32_t service_id, int32_t table_id, int32_t region_type, MESA_htable_handle hash_handle);
configure_table_t *new_table_instance_two(const char *table_name, int32_t service_id, int32_t table_id, MESA_htable_handle hash_handle);
configure_table_t *new_table_instance_three(const char *table_name, int32_t service_id, int32_t table_id, MESA_htable_handle hash_handle);
void* thread_dispatch_full_config(void *arg);

#endif

