#ifndef __PANGU_VAVLE_MAIN_H__
#define __PANGU_VAVLE_MAIN_H__

#include <MESA/MESA_htable.h>
#include <MESA/field_stat2.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/Maat_rule.h>
#include <MESA/asmis_log.h>
#include <MESA/MESA_prof_load.h>

#include "pg_valve_tools.h"
#include "pg_valve_stat.h"
#include "pg_valve_deal.h"

#define PANGU_CONF_FILE "./conf/pangu_valve.conf"
#define PANGU_LOCK_FILE "/tmp/pangu_valve_lock"

#define TABLES_ONE_FILE "./conf/table_info/table_info_one.conf"
#define TABLES_TREE_FILE "./conf/table_info/table_info_tree.conf"
#define MAAT_INFO_FILE "./conf/table_info/maat_info.conf"
#define SERVICE_MAP_FILE "./conf/table_info/service_id_map.conf"

#define MODULE_NAME "PG_VALVE"

#define MAX_PATH_LEN 256
 
struct config_table_direct
{
	char table_name[64];
	int32_t service_id;
	int32_t table_id; //唯一值，用作哈希表key，用作回传Magellan日志
	int32_t region_type; //一级IP表的类型
};

struct config_table_relation{
	char table_three_name[64];
	char table_two_name[64];
	char table_onesw_name[64];
	int32_t service_id;
	int32_t table_id_three;
	int32_t table_id_two;
	int32_t table_id_onesw;
	int32_t region_type; //一级IP表的类型
};

struct maat_table_relation{
	char instance_name[64];
	char full_dir[256];
	char incr_dir[256];
	char version_file[256];
	char redisip[128];
	int redisport;
	int redis_index;
	char **tables_name;
	int table_num;
};

struct service_id_map
{
	int32_t service_id;
	int32_t limit_rate;
	grule_map_info_t grule_info;
	u_int64_t max_limit;
};

typedef struct __pgvavle_global_info
{
	//MaatRedis//
	char maat_table_info[MAX_PATH_LEN];
	char redis_ip[64];
	char effective_range[4096];
	int redis_port;
	int maat_source;

	//数据结构
	unsigned int hash_size;
	unsigned int sw_invalid_timeout;	//开关表元素失效后哈希的淘汰时间
	MESA_htable_handle htable_stat_log; //以表为单位统计增量，输出统计日志
	MESA_htable_handle htable_stat_serv;//统计service的生效配置量，用于做上限；

	//主从
	char leader_key[128];
	char local_ip[64];
	unsigned int consul_sw;
	unsigned int http_timeout;
	unsigned int lock_delay;
	unsigned int session_ttl;

	//C3
	char authdata[128];
	char ccclist[128];
	unsigned int service_limit_sw;
	pthread_rwlock_t rwlock;
	
	//log//
	unsigned int log_level;
	int asmis_heart_intvl;
	char root_log_dir[MAX_PATH_LEN];
	char asmis_appname[128];
	void *log_runtime;
	void *log_statistic;
	void *asmis_handle;
	screen_stat_handle_t fsstat_handle;
	char fs_dst_ip[64];
	char appname[64];
	int statid_table_one;
	int statid_table_sw;
	int statid_exist[STAT_EXIST_NUM];
	int statid_incr[STAT_INCR_NUM];
	unsigned int statistic_period;
	unsigned int fsstatid_trig;
	unsigned int fssprint_mode;
	unsigned int fs_dst_port;
}pgvavle_global_info_t;

bool is_table_three(configure_table_t *table);

struct __tables_map_ref
{
	map<string, configure_table_t *> &tables_one; //所有表
	map<string, configure_table_t *> &tables_sw; //所有表
};

typedef struct __iterator_table_priv
{
	configure_table_t *table;
	statistic_exist_t *stat_out;
}iterator_table_priv_t;

int32_t service_to_c3_servtype(int32_t service_key, int32_t limit_rate, grule_map_info_t *gmap_info);
int32_t get_gserv_type_fsid(int32_t gserv_type);
void valve_statistic_log_output(map<string, configure_table_t *> &tables_one, map<string, configure_table_t *> &tables_sw);

#endif

