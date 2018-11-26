#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <iostream>
#include <map>
#include <string>

#include "load_table_info.hpp"

#include "pg_valve_main.h"
#include "pg_valve_maat.h"
#include "pg_valve_stat.h"
#include "pg_valve_consul.h"
#include <MESA/wired_cfg.h>

using namespace std;

pgvavle_global_info_t g_pgvalve_info;
map<int64_t, grule_map_info_t> g_map_service_grule;
map<int32_t, int32_t> g_map_grule_fs2;
bool g_valve_master=false;

unsigned int get_ip_by_ifname(const char *ifname)
{
	int sockfd;
	struct ifreq ifr;
	unsigned int ip;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == sockfd) 
		return INADDR_NONE;

	strcpy(ifr.ifr_name,ifname); 
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) 
	{
		close(sockfd);
		return INADDR_NONE;
	}

	ip = ((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr;
	close(sockfd);
	return ip;
}

static int32_t read_conf_and_init(void)
{
	char tmp_buf[256], tmp_logdir[256];

	memset(&g_pgvalve_info, 0, sizeof(pgvavle_global_info_t));

	//log init//
	MESA_load_profile_string_def(PANGU_CONF_FILE, "LOG", "RUN_LOG_DIR", g_pgvalve_info.root_log_dir, sizeof(g_pgvalve_info.root_log_dir), "../log");
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "LOG", "RUN_LOG_LV", &g_pgvalve_info.log_level, 10);
	sprintf(tmp_logdir, "%s/runtime_log", g_pgvalve_info.root_log_dir);
	if(mkdir_according_path(tmp_logdir))
	{
		printf("mkdir %s failed: %s\n", g_pgvalve_info.root_log_dir, strerror(errno));
		return -1;
	}
	snprintf(tmp_buf, 256, "%s/runtime.log", tmp_logdir);
	g_pgvalve_info.log_runtime = MESA_create_runtime_log_handle(tmp_buf, g_pgvalve_info.log_level);
	if(NULL==g_pgvalve_info.log_runtime)
	{
		return -1;
	}
	sprintf(tmp_logdir, "%s/statistic_log", g_pgvalve_info.root_log_dir);
	if(mkdir_according_path(tmp_logdir))
	{
		printf("mkdir %s failed: %s\n", g_pgvalve_info.root_log_dir, strerror(errno));
		return -1;
	}
	snprintf(tmp_buf, 256, "%s/statistic.log", tmp_logdir);
	g_pgvalve_info.log_statistic = MESA_create_runtime_log_handle(tmp_buf, g_pgvalve_info.log_level);
	if(NULL==g_pgvalve_info.log_statistic)
	{
		return -1;
	}

	MESA_load_profile_string_def(PANGU_CONF_FILE, "LOG", "ASMIS_PROC_NAME", g_pgvalve_info.asmis_appname, 64, "PANGU/valve");
	MESA_load_profile_int_def(PANGU_CONF_FILE, "LOG", "ASMIS_HEART_INTERVAL", &g_pgvalve_info.asmis_heart_intvl, 10);
	MESA_load_profile_string_def(PANGU_CONF_FILE, "LOG", "FS_STAT_APPNAME", g_pgvalve_info.appname, 64, "PANGU_VALVE");
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "LOG", "STATISTIC_INTERVAL", &g_pgvalve_info.statistic_period, 300);
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "LOG", "FS_STAT_TRIG", &g_pgvalve_info.fsstatid_trig, 0);
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "LOG", "FS_STAT_MODE", &g_pgvalve_info.fssprint_mode, 1);
	MESA_load_profile_string_def(PANGU_CONF_FILE, "LOG", "FS_STAT_DST_IP", g_pgvalve_info.fs_dst_ip, 64, "10.172.128.2");
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "LOG", "FS_STAT_DST_PORT", &g_pgvalve_info.fs_dst_port, 8125);

	if(0>MESA_load_profile_string_nodef(PANGU_CONF_FILE, "SYSTEM", "LOCAL_NET_NAME", tmp_buf, 64))
	{
		printf("[SYSTEM] CONSUL_LEADER_KEY not found.\n");
		assert(0);
		return -1;
	}
	int local_ip = get_ip_by_ifname(tmp_buf);
	inet_ntop(AF_INET, &local_ip, g_pgvalve_info.local_ip, 64);

	//系统配置
	if(MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "CONSUL_SWITCH", &g_pgvalve_info.consul_sw, 0) <0)
	{
		printf("[SYSTEM] CONSUL_SWITCH not found.\n");
		assert(0);
		return -1;
	}
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "CONSUL_REQ_TIMEOUT", &g_pgvalve_info.http_timeout, 14);
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "CONSUL_LOCK_DELAY", &g_pgvalve_info.lock_delay, 10);
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "CONSUL_SESSION_TTL", &g_pgvalve_info.session_ttl, 30);
	if(g_pgvalve_info.consul_sw && (0>MESA_load_profile_string_nodef(PANGU_CONF_FILE, "SYSTEM", "CONSUL_LEADER_KEY", g_pgvalve_info.leader_key, 128) || g_pgvalve_info.leader_key[0]==0))
	{
		printf("[SYSTEM] CONSUL_LEADER_KEY not found.\n");
		assert(0);
		return -1;
	}
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "HASH_TABLE_SIZE", &g_pgvalve_info.hash_size, 8388608);
	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "SW_HNODE_TIMEOUT_MIN", &g_pgvalve_info.sw_invalid_timeout, 2880);
	g_pgvalve_info.sw_invalid_timeout *= 60; //2天

	//Maat//
	MESA_load_profile_string_def(PANGU_CONF_FILE, "SYSTEM", "MAAT_TABLE_INFO_PATH", g_pgvalve_info.maat_table_info, sizeof(g_pgvalve_info.maat_table_info), "./conf/maat_table_info.conf");
	MESA_load_profile_int_def(PANGU_CONF_FILE, "SYSTEM", "MAAT_CONFIG_RECV_WAY", &g_pgvalve_info.maat_source, MAAT_CONFIG_REDIS);
	MESA_load_profile_string_def(PANGU_CONF_FILE, "SYSTEM", "MAAT_EFFECTIVE_RANGE", g_pgvalve_info.effective_range, 4096, "");

	MESA_load_profile_uint_def(PANGU_CONF_FILE, "SYSTEM", "SERVICE_TOPLIMIT_SW", &g_pgvalve_info.service_limit_sw, 0);
	if(MESA_load_profile_string_nodef(PANGU_CONF_FILE, "SYSTEM", "C3_AUTH_DATA", g_pgvalve_info.authdata, 128) < 0)
	{
		assert(0);
		return -1;
	}
	if(MESA_load_profile_string_nodef(PANGU_CONF_FILE, "SYSTEM", "C3_CCC_LISTS", g_pgvalve_info.ccclist, 128) < 0)
	{
		assert(0);
		return -1;
	}
	pthread_rwlock_init(&g_pgvalve_info.rwlock, NULL);
	return 0;
}

void wired_load_config(void)
{
	void *wired_handle = wired_cfg_create("PANGU_VALVE/cfg_pangu_valve", PANGU_CONF_FILE);
	if(wired_cfg_init(wired_handle) != WCFG_RET_OK)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "wired_cfg_init %s failed.", PANGU_CONF_FILE);
	}
	wired_cfg_destroy(wired_handle);

	wired_handle = wired_cfg_create("PANGU_VALVE/cfg_service_id_map", SERVICE_MAP_FILE);
	if(wired_cfg_init(wired_handle) != WCFG_RET_OK)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "wired_cfg_init %s failed.", SERVICE_MAP_FILE);
	}
	wired_cfg_destroy(wired_handle);

	wired_handle = wired_cfg_create("PANGU_VALVE/cfg_maat_info", MAAT_INFO_FILE);
	if(wired_cfg_init(wired_handle) != WCFG_RET_OK)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "wired_cfg_init %s failed.", SERVICE_MAP_FILE);
	}
	wired_cfg_destroy(wired_handle);
}

bool instance_already_running(void)
{
	int fd;
	struct flock flk;

	fd = open(PANGU_LOCK_FILE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if(fd < 0)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "instance_already_running: open file %s fail: %s.", strerror(errno));
		return true;
	}

	flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0;

	if(fcntl(fd, F_SETLK, &flk) < 0)
	{
		if(errno==EACCES || errno==EAGAIN)
		{
			return true;
		}
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "instance_already_running: fcntl file %s fail: %s.", strerror(errno));
		return true;
	}
	return false;
}

static int init_asmis_log_handle(const char *appname)
{
	int ret;

	g_pgvalve_info.asmis_handle = asmis_log_Init(appname);;
	
	ret = asmis_log_AppVer(g_pgvalve_info.asmis_handle, "2018-07-25T09:00:00", "20180725.1", "ConsulCluster");
	ret |= asmis_log_RunStart(g_pgvalve_info.asmis_handle, 1);
	return ret;
}

void htable_destroy_node(void *data)
{
	free(data);
}

static MESA_htable_handle init_and_create_htable(unsigned int slot_size, int expire_time, void (* data_free)(void *data))
{
	MESA_htable_create_args_t htable_args;

	memset(&htable_args, 0, sizeof(MESA_htable_create_args_t));
	
	htable_args.thread_safe	= 1;
	htable_args.recursive	= 1;
	htable_args.hash_slot_size = slot_size;
	htable_args.max_elem_num = 10*slot_size;
	//MESA_htable_iterate_bytime回调中再次调用serach/add等操作时，HASH_ELIMINATE_ALGO_LRU会改变内部链表，导致遍历乱套；
	htable_args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	htable_args.expire_time = expire_time;
	htable_args.data_free = data_free; //释放节点内存

	return MESA_htable_create(&htable_args, sizeof(MESA_htable_create_args_t));
}

void debug_print_tree(map<string, configure_table_t *> &top_debug)
{
	configure_table_t *parent, *tmp_parent;
	configure_table_t *child, *tmp_child;
	map<string, configure_table_t *>::iterator iter;
	char buffer[1024];

	for(iter=top_debug.begin(); iter!=top_debug.end(); iter++)
	{
		parent = iter->second;
		child  = parent->child;

		while(child != NULL)
		{
			assert(child->parent == parent);
			sprintf(buffer, "SW_TableTree: %s", iter->first.c_str());
			
			tmp_parent = child;
			while(tmp_parent != NULL)
			{
				tmp_child = tmp_parent->child;
				sprintf(buffer+strlen(buffer), "-->%s", tmp_parent->table_name);

				if(tmp_child != NULL)	assert(tmp_parent == tmp_child->parent);
				tmp_parent = tmp_child;
			}
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "%s", buffer);

			child = child->next;
		}
	}
}

bool is_table_three(configure_table_t *table)
{
	configure_table_t *next;

	if(table->child == NULL)
	{
		return false;
	}

	next = table->child;
	while(next != NULL)
	{
		if(next->child != NULL)
		{
			return true;
		}
		next = next->next;
	}

	return false;
}

int32_t fill_in_single_table_tree(char *line_content, struct config_table_relation *table, int32_t table_index)
{
	char region_type[64], table_three_name[64], table_two_name[64], table_onesw_name[64];
	int ret;

	ret = sscanf(line_content, "%[^ \t]%*[ \t]%s%*[ \t]%s%*[ \t]%u%*[ \t]%s", 
		table_three_name, table_two_name, table_onesw_name, &table->service_id, region_type);
	if(ret != 5)
	{
		assert(0);
		return -1;
	}
	if(!strcmp(table_three_name, "NULL"))
	{
		table->table_three_name[0] = '\0';
	}
	else if(sscanf(table_three_name, "%[^:]:%d", table->table_three_name, &table->table_id_three) != 2)
	{
		assert(0);
		return -2;
	}
	
	if(!strcmp(table_two_name, "NULL"))
	{
		table->table_two_name[0] = '\0';
	}
	else if(sscanf(table_two_name, "%[^:]:%d", table->table_two_name, &table->table_id_two) != 2)
	{
		assert(0);
		return -2;
	}
	
	if(sscanf(table_onesw_name, "%[^:]:%d", table->table_onesw_name, &table->table_id_onesw) != 2)
	{
		assert(0);
		return -2;
	}
	
	if(!strcmp(region_type, "REGION_TYPE_IP"))
	{
		table->region_type = REGION_TYPE_IP;
	}
	else if(!strcmp(region_type, "REGION_TYPE_FIND"))
	{
		table->region_type = REGION_TYPE_FIND;
	}
	else if(!strcmp(region_type, "REGION_TYPE_POOL"))
	{
		table->region_type = REGION_TYPE_POOL;
	}
	else
	{
		return -2;
	}
	
	return 0;
}

int load_table_tree_info(struct config_table_relation **table_conifg_tree, int *num)
{
	LoadTableInfo<struct config_table_relation> load_tree(TABLES_TREE_FILE, fill_in_single_table_tree);

	return load_tree.load_table_info(table_conifg_tree, num);
}

void set_child_to_parent(configure_table_t *parent, configure_table_t *child)
{
	if(parent->child == NULL)
		parent->child = child;
	else
	{
		configure_table_t *tmp = parent->child;
		while(tmp->next != NULL) 
			tmp = tmp->next;
		tmp->next = child;
	}
}

int setup_sw_tables_relationship(map<string, configure_table_t *> &tables, map<string, configure_table_t *> &tables_sw, map<string, configure_table_t *> &tables_one)
{
	map<string, configure_table_t *> top_debug; //所有TOP表
	configure_table_t *ctable_three;
	configure_table_t *ctable_two;
	configure_table_t *ctable_onesw;
	MESA_htable_handle hash_table;
	struct config_table_relation *table_conifg_tree=NULL;
	int table_num=0;

	if(load_table_tree_info(&table_conifg_tree, &table_num))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "load_table_tree_info failed.");
		return -1;
	}

	for(int i=0; i<table_num; i++)
	{
		ctable_three = ctable_two = NULL;
		
		if(table_conifg_tree[i].table_three_name[0] != '\0')
		{
			if(tables.find(string(table_conifg_tree[i].table_three_name)) != tables.end())
			{
				ctable_three = tables[string(table_conifg_tree[i].table_three_name)];
				assert(table_conifg_tree[i].table_id_three == ctable_three->table_id_key);
			}
			else
			{
				hash_table = init_and_create_htable(g_pgvalve_info.hash_size, 0, htable_destroy_node);
				ctable_three = new_table_instance_three(table_conifg_tree[i].table_three_name, table_conifg_tree[i].service_id, table_conifg_tree[i].table_id_three, hash_table);
				tables[string(table_conifg_tree[i].table_three_name)] = ctable_three;
				tables_sw[string(table_conifg_tree[i].table_three_name)] = ctable_three;
				top_debug[string(table_conifg_tree[i].table_three_name)] = ctable_three;
			}
		}

		if(table_conifg_tree[i].table_two_name[0] != '\0')
		{
			if(tables.find(string(table_conifg_tree[i].table_two_name)) != tables.end())
			{
				ctable_two = tables[string(table_conifg_tree[i].table_two_name)];
				assert(table_conifg_tree[i].table_id_two == ctable_two->table_id_key);
			}
			else
			{
				if(ctable_three != NULL)
				{
					hash_table = ctable_three->hash_handle;
				}
				else
				{
					hash_table = init_and_create_htable(g_pgvalve_info.hash_size, 0, htable_destroy_node);
				}

				ctable_two = new_table_instance_two(table_conifg_tree[i].table_two_name, table_conifg_tree[i].service_id, table_conifg_tree[i].table_id_two, hash_table);
				tables[string(table_conifg_tree[i].table_two_name)] = ctable_two;
				tables_sw[string(table_conifg_tree[i].table_two_name)] = ctable_two;

				if(ctable_three != NULL)
				{
					ctable_two->parent = ctable_three;
					set_child_to_parent(ctable_three, ctable_two);
				}
				else
				{
					top_debug[string(table_conifg_tree[i].table_two_name)] = ctable_two;
				}
			}
		}

		ctable_onesw = new_table_instance_onesw(table_conifg_tree[i].table_onesw_name, table_conifg_tree[i].service_id, table_conifg_tree[i].table_id_onesw, table_conifg_tree[i].region_type, hash_table);
		tables[string(table_conifg_tree[i].table_onesw_name)] = ctable_onesw;
		tables_one[string(table_conifg_tree[i].table_onesw_name)] = ctable_onesw;
		if(ctable_two != NULL)
		{
			ctable_onesw->parent = ctable_two;
			set_child_to_parent(ctable_two, ctable_onesw);
		}
		else
		{
			ctable_onesw->parent = ctable_three;
			set_child_to_parent(ctable_three, ctable_onesw);
		}
	}
	
	debug_print_tree(top_debug);
	return 0;
}

int32_t fill_in_single_table_one(char *line_content, struct config_table_direct *table, int32_t table_index)
{
	char region_type[64], table_name[64];
	int ret;

	ret = sscanf(line_content, "%[^ \t]%*[ \t]%u%*[ \t]%s", table_name, &table->service_id, region_type);
	if(ret != 3)
	{
		assert(0);
		return -1;
	}
	if(sscanf(table_name, "%[^:]:%d", table->table_name, &table->table_id) != 2)
	{
		assert(0);
		return -2;
	}

	if(!strcmp(region_type, "REGION_TYPE_IP"))
	{
		table->region_type = REGION_TYPE_IP;
	}
	else if(!strcmp(region_type, "REGION_TYPE_FIND"))
	{
		table->region_type = REGION_TYPE_FIND;
	}
	else if(!strcmp(region_type, "REGION_TYPE_POOL"))
	{
		table->region_type = REGION_TYPE_POOL;
	}
	else
	{
		return -2;
	}
	return 0;
}

int load_table_tree_one(struct config_table_direct **table_conifg_one, int *num)
{
	LoadTableInfo<struct config_table_direct> load_one(TABLES_ONE_FILE, fill_in_single_table_one);

	return load_one.load_table_info(table_conifg_one, num);
}

int setup_direct_tables(map<string, configure_table_t *> &tables, map<string, configure_table_t *> &tables_one)
{
	configure_table_t *ctable_one;
	MESA_htable_handle hash_table;
	struct config_table_direct *table_conifg_direct=NULL;
	int table_num=0;

	if(load_table_tree_one(&table_conifg_direct, &table_num))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "load_table_tree_info failed.");
		return -1;
	}

	for(int i=0; i<table_num; i++)
	{
		hash_table = init_and_create_htable(g_pgvalve_info.hash_size, 0, htable_destroy_node);
		ctable_one = new_table_instance_one(table_conifg_direct[i].table_name, table_conifg_direct[i].service_id, table_conifg_direct[i].table_id, table_conifg_direct[i].region_type, hash_table);
		assert(tables.find(string(table_conifg_direct[i].table_name)) == tables.end());
		tables[string(table_conifg_direct[i].table_name)] = ctable_one;
		tables_one[string(table_conifg_direct[i].table_name)] = ctable_one;
	}

	return 0;
}

int32_t fill_in_single_maat_instance(char *line_content, struct maat_table_relation *table, int32_t table_index)
{
	char maat_root[256], table_list[4096];
	int ret, j;
	char *ptmp, *save_ptr=NULL;

	ret = sscanf(line_content, "%[^ \t]%*[ \t]%s%*[ \t]%s%*[ \t]%s%*[ \t]%u%*[ \t]%u%*[ \t]%s", 
			table->instance_name, maat_root, table->version_file, 
			table->redisip, &table->redisport, &table->redis_index, table_list);
	if(ret != 7)
	{
		assert(0);
		return -1;
	}
	snprintf(table->full_dir, 256, "%s/full/index", maat_root);
	snprintf(table->incr_dir, 256, "%s/inc/index", maat_root);
	
	table->table_num = 0;
	for(ptmp = strtok_r(table_list, ";", &save_ptr); ptmp != NULL; ptmp = strtok_r(NULL, ";", &save_ptr))
	{
		if(table->table_num == 0)
		{
			table->tables_name = (char **)malloc(sizeof(void *));
		}
		else
		{
			table->tables_name = (char **)realloc(table->tables_name, (table->table_num + 1)*sizeof(void *));
		}
		
		for(j=0; j<table->table_num; j++)
		{
			if(!strcmp(table->tables_name[j], ptmp)) //已经存在
			{
				break;
			}
		}
		if(j<table->table_num)
		{
			continue;
		}
		table->tables_name[table->table_num] = (char *)malloc(sizeof(char)*64);
		snprintf(table->tables_name[table->table_num], 64, "%s", ptmp);
		table->table_num++;
	}
	return 0;
}

int load_maat_info(struct maat_table_relation **maat_lists, int *num)
{
	LoadTableInfo<struct maat_table_relation> load_maat(MAAT_INFO_FILE, fill_in_single_maat_instance);

	return load_maat.load_table_info(maat_lists, num);
}

int32_t get_gserv_type_fsid(int32_t gserv_type)
{
	if(g_map_grule_fs2.find(gserv_type) != g_map_grule_fs2.end())
	{
		return g_map_grule_fs2[gserv_type];
	}

	return -1;
}

int64_t service_map_key(int32_t service_id, int32_t limit_rate)
{
	int64_t service = service_id, limit = limit_rate;
	return (limit<<32) | service;
}

int32_t service_to_c3_servtype(int32_t service_key, int32_t limit_rate, grule_map_info_t *gmap_info)
{
	int64_t key = service_map_key(service_key, limit_rate);
	
	if(g_map_service_grule.find(key) != g_map_service_grule.end())
	{
		grule_map_info_t grule_info = g_map_service_grule[key];
		gmap_info->serv_type = grule_info.serv_type;
		gmap_info->rule_scope = grule_info.rule_scope;
		return 0;
	}
	return -1;
}

int32_t fill_in_service_id_map(char *line_content, struct service_id_map *map_info, int32_t table_index)
{
	int ret;

	ret = sscanf(line_content, "%d%*[ \t]%d%*[ \t]%d%*[ \t]%d%*[ \t]%lu", 
			&map_info->service_id, &map_info->limit_rate, &map_info->grule_info.serv_type, &map_info->grule_info.rule_scope, &map_info->max_limit);
	if(ret != 5)
	{
		assert(0);
		return -1;
	}

	return 0;
}

int load_service_map_info(void)
{
	struct service_id_map *map_lists;
	int ret=0, num;
	LoadTableInfo<struct service_id_map> load_serv_map(SERVICE_MAP_FILE, fill_in_service_id_map);
	int64_t key;

	if(load_serv_map.load_table_info(&map_lists, &num) < 0)
	{
		return -1;
	}

	for(int i=0; i<num; i++)
	{
		key = service_map_key(map_lists[i].service_id, map_lists[i].limit_rate);
		if(g_map_service_grule.find(key) == g_map_service_grule.end())
		{
			g_map_service_grule[key] = map_lists[i].grule_info; //根据下发的服务类型与G服务类型建立映射
			g_map_grule_fs2[map_lists[i].grule_info.serv_type] = 0; //G服务类型与FS建立映射，根据前者进行统计
			ret |= service_grule_setup_hnode(map_lists[i].grule_info.serv_type, map_lists[i].max_limit);
		}
	}
	free(map_lists);
	return ret;
}

static int register_field_stat(map<string, configure_table_t *> &tables_one, map<string, configure_table_t *> &tables_sw, 
	const char *rootdir, const char *dstip, unsigned int dstport)
{
	char buffer[256], fsfile[256];
	unsigned short fs_port=dstport;
	const char *fs_colom_inc[STAT_INCR_NUM] ={"RECV", "ERROR", "RVALID", "RINVALID", "DISP_SUCC", "DISP_FAIL", "DISP_LIMIT"};
	const char *fs_colom_exist[STAT_EXIST_NUM] ={"EXIST", "PENDING", "EACTIVE", "EINACTIVE"};
	map<string, configure_table_t *>::iterator iter;
	configure_table_t *table;
	u_int32_t i;

	snprintf(buffer, 256, "%s/field_stat2", rootdir);
	if(mkdir_according_path(buffer))
	{
		printf("mkdir %s failed: %s\n", buffer, strerror(errno));
		return -1;
	}

	snprintf(fsfile, 256, "%s/fsstat_clmb.log", buffer);
	g_pgvalve_info.fsstat_handle = FS_create_handle();
	FS_set_para(g_pgvalve_info.fsstat_handle, OUTPUT_DEVICE, fsfile, strlen(fsfile)+1);
	FS_set_para(g_pgvalve_info.fsstat_handle, PRINT_MODE, &(g_pgvalve_info.fssprint_mode), sizeof(g_pgvalve_info.fssprint_mode));
	FS_set_para(g_pgvalve_info.fsstat_handle, STAT_CYCLE, &(g_pgvalve_info.statistic_period), sizeof(g_pgvalve_info.statistic_period));
	
	int value = 0;
	FS_set_para(g_pgvalve_info.fsstat_handle, CREATE_THREAD, &value, sizeof(value));
	value = 1;
	FS_set_para(g_pgvalve_info.fsstat_handle, FLUSH_BY_DATE, &value, sizeof(value));

	FS_set_para(g_pgvalve_info.fsstat_handle, APP_NAME, g_pgvalve_info.appname, strlen(g_pgvalve_info.appname)+1);
	FS_set_para(g_pgvalve_info.fsstat_handle, STATS_SERVER_IP, dstip, strlen(dstip)+1);
	FS_set_para(g_pgvalve_info.fsstat_handle, STATS_SERVER_PORT, &fs_port, sizeof(fs_port));

	//FS_STAT行, IP域表
	for(iter=tables_one.begin(); iter!=tables_one.end(); iter++)
	{
		table = iter->second;
		table->statid_table = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_LINE, FS_CALC_CURRENT, table->table_name);
		if(table->statid_table < 0)
		{
			printf("FS_register FS_STYLE_LINE for %s fail.\n", table->table_name);
			assert(0);
			return -1;
		}
	}
	g_pgvalve_info.statid_table_one = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_LINE, FS_CALC_CURRENT, "TOTAL_ONE");
	
	//FS_STAT行, 开关表
	for(iter=tables_sw.begin(); iter!=tables_sw.end(); iter++)
	{
		table = iter->second;
		table->statid_table = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_LINE, FS_CALC_CURRENT, table->table_name);
		if(table->statid_table < 0)
		{
			printf("FS_register FS_STYLE_LINE for %s fail.\n", table->table_name);
			assert(0);
			return -1;
		}
	}
	g_pgvalve_info.statid_table_sw = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_LINE, FS_CALC_CURRENT, "TOTAL_SW");

	//FS_STAT列
	for(i=0; i<STAT_INCR_NUM; i++)
	{
		g_pgvalve_info.statid_incr[i] = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, fs_colom_inc[i]);
	}
	for(i=0; i<STAT_EXIST_NUM; i++)
	{
		g_pgvalve_info.statid_exist[i] = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, fs_colom_exist[i]);
	}

	//FS_STAT独立统计，统计每个G服务类型的生效数
	map<int32_t, int32_t>::iterator iter_fs;
	char item_name[64];
	for(iter_fs=g_map_grule_fs2.begin(); iter_fs!=g_map_grule_fs2.end(); iter_fs++)
	{
		sprintf(item_name, "SERVICE_%u", iter_fs->first);
		iter_fs->second = FS_register(g_pgvalve_info.fsstat_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, item_name);
	}

	FS_start(g_pgvalve_info.fsstat_handle);
	return 0;
}

void* thread_consul_status(void *arg)
{
	const char *session_id = (char *)arg;
	bool retry;
	time_t start_time, end_time;
	
	while(1)
	{
		start_time = time(NULL);
		retry = false;
retry_lock:
		if(!consul_try_get_lock(session_id, g_pgvalve_info.leader_key, g_pgvalve_info.local_ip, g_pgvalve_info.http_timeout))
		{
			if(g_valve_master) //已经是master了才需要重试，重试依然失败就重启，能释放锁
			{
				if(!retry)
				{
					retry = true;
					goto retry_lock;
				}
				MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "consul_try_get_lock failed, restart.");
				exit(20);
			}
		}
		else if(!g_valve_master)
		{
			g_valve_master = true;
		}

		retry = false;
retry_session:
		if(!consul_renew_session(session_id, g_pgvalve_info.http_timeout)) //slave也需要刷新session
		{
			if(!retry)
			{
				retry = true;
				goto retry_session;
			}
			else
			{
				MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "consul_renew_session failed, restart.");
				exit(20);
			}
		}

		end_time = time(NULL);
		if(start_time + g_pgvalve_info.session_ttl >= end_time)
		{
			sleep((g_pgvalve_info.session_ttl - (end_time-start_time))/2);
		}
	}

	return NULL;
}

void* thread_asmis_log(void *arg)
{
	while(1)
	{
		sleep(g_pgvalve_info.asmis_heart_intvl);
		asmis_log_HeartBeat(g_pgvalve_info.asmis_handle, "pangu_valve is running");
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct maat_table_relation *g_table_maat_lists=NULL;
	int g_table_maat_num;
	map<string, configure_table_t *> tables; //所有表
	map<string, configure_table_t *> tables_one; //所有表
	map<string, configure_table_t *> tables_sw; //所有表
	pthread_t	 	thread_desc;
	pthread_attr_t 	attr;	
	char session_id[128];

	wired_load_config();
	if(read_conf_and_init() || init_asmis_log_handle(g_pgvalve_info.asmis_appname))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "read_conf_and_init/init_asmis_log_handle fail.");
		return -1;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);	
	pthread_create(&thread_desc, &attr, thread_asmis_log, NULL);
	if(g_pgvalve_info.consul_sw)
	{
		if(!consul_create_session(g_pgvalve_info.lock_delay, g_pgvalve_info.session_ttl, session_id, 128, g_pgvalve_info.log_runtime))
		{
			printf("consul_create_session failed.\n");
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "consul_create_session failed.");
			exit(20);
		}
		pthread_create(&thread_desc, &attr, thread_consul_status, (void *)session_id);
		while(!g_valve_master)
		{
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_DEBUG, MODULE_NAME, "pangu_valve waiting to be master.");
			sleep(4);
		}
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "pangu_valve elected as master! session_id: %s.", session_id);
	}
	else if(instance_already_running())
	{
		printf("There is another instance already running, only one instance can run at the same time.\n");
		exit(20);
	}
	
	g_pgvalve_info.htable_stat_log = init_and_create_htable(256, 0, NULL);
	g_pgvalve_info.htable_stat_serv = init_and_create_htable(256, 0, NULL);

	if(load_service_map_info())
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "load_service_map_info fail.");
		return -1;
	}
	
	if(load_maat_info(&g_table_maat_lists, &g_table_maat_num))
	{
		return -1;
	}
	if(setup_sw_tables_relationship(tables, tables_sw, tables_one))
	{
		return -2;
	}
	if(setup_direct_tables(tables, tables_one))
	{
		return -3;
	}
	
	assert(tables.size() == tables_one.size()+tables_sw.size());
	if(register_field_stat(tables_one, tables_sw, g_pgvalve_info.root_log_dir, g_pgvalve_info.fs_dst_ip, g_pgvalve_info.fs_dst_port))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "register_field_stat fail.");
		return -1;
	}

	struct __tables_map_ref table_map = {tables_one, tables_sw};	
	if(pthread_create(&thread_desc, &attr, thread_dispatch_full_config, (void *)&table_map))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "pthread_create(): %s", strerror(errno));
		return -1;
	}
	if(!global_init_grule_handle(g_pgvalve_info.authdata, strlen(g_pgvalve_info.authdata), g_pgvalve_info.ccclist, thread_desc))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "global_init_grule_handle fail.");
		return -1;
	}

	MaatService **maat_service = (MaatService **)malloc(g_table_maat_num * sizeof(void *));
	for(int i=0; i<g_table_maat_num; i++)
	{
		maat_service[i] = new MaatService(&g_table_maat_lists[i]);
		if(maat_service[i] == NULL)
		{
			assert(0);
			return -1;
		}
		if(maat_service[i]->maat_feather_start() < 0)
		{
			assert(0);
			return -1;
		}

		for(int j=0; j<g_table_maat_lists[i].table_num; j++)
		{
			assert(tables.find(g_table_maat_lists[i].tables_name[j]) != tables.end());
			configure_table_t *table = tables[g_table_maat_lists[i].tables_name[j]];
			if(maat_start_config_table(table, maat_service[i]))
			{
				MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "maat_start_config_table_%s %s:%d failed.", maat_service[i]->get_instance_name(), table->table_name, table->table_id_key);
				return -2;
			}
			else
			{
				MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "maat_start_config_table_%s %s:%d success.", maat_service[i]->get_instance_name(), table->table_name, table->table_id_key);
			}
		}
	}
	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "pangu_valve starts all tables full config over.\n");

	time_t now, remain;
	while(1)
	{
		now = time(NULL);
		remain = g_pgvalve_info.statistic_period - (now % g_pgvalve_info.statistic_period);
		sleep(remain);

		valve_statistic_log_output(tables_one, tables_sw);
	}
	return 0;
}

