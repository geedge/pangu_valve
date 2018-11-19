#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/prctl.h>

#include <MESA/MESA_htable.h>

#include "pg_valve_main.h"
#include "pg_valve_stat.h"

extern pgvavle_global_info_t g_pgvalve_info;

static int service_config_clear_iterator(const uchar * key, uint size, void * data, void *user)
{
	stat_service_hnode_t *hnode = (stat_service_hnode_t *)data;
	hnode->cur_num = 0;
	return ITERATE_CB_RET_CONTINUE_FLAG;	
}

void service_config_clear(void)
{
	MESA_htable_iterate_bytime(g_pgvalve_info.htable_stat_serv, ITERATE_TYPE_OLDEST_FIRST, service_config_clear_iterator, NULL);
}

static int service_config_limit_iterator(const uchar * key, uint size, void * data, void *user)
{
	stat_service_hnode_t *hnode = (stat_service_hnode_t *)data;
	int32_t gserv_type = *(int32_t *)key;

	if(g_pgvalve_info.fsstatid_trig)
	{
		FS_operate(g_pgvalve_info.fsstat_handle, get_gserv_type_fsid(gserv_type), 0, FS_OP_SET, hnode->cur_num);
	}
	return ITERATE_CB_RET_CONTINUE_FLAG;
}

static long service_grule_setup_hnode_cb(void *data, const uchar *key, uint size, void *arg)
{
	stat_service_hnode_t *hnode = (stat_service_hnode_t *)data;
	int ret;
	u_int64_t max_num = *(u_int64_t *)arg;

	if(hnode == NULL)
	{
		hnode = (stat_service_hnode_t *)calloc(1, sizeof(stat_service_hnode_t));
		if((ret = MESA_htable_add(g_pgvalve_info.htable_stat_serv, key, size, hnode)) < 0)
		{
			free(hnode);
			return -1;
		}
	}
	
	hnode->max_num = max_num;
	return 0;
}

int service_grule_setup_hnode(int32_t serv_type, u_int64_t max_num)
{
	long cb_ret;

	MESA_htable_search_cb(g_pgvalve_info.htable_stat_serv, (unsigned char *)&serv_type, sizeof(serv_type), service_grule_setup_hnode_cb, &max_num, &cb_ret);
	return (cb_ret==0)?0:-1;
}

static long service_grule_statistic_count_cb(void *data, const uchar *key, uint size, void *arg)
{
	stat_service_hnode_t *hnode = (stat_service_hnode_t *)data;
	stat_service_priv_t *serv_priv = (stat_service_priv_t *)arg;
	
	if(hnode == NULL)
	{
		assert(0);
	}

	switch(serv_priv->type)
	{
		case STAT_SERVICE_ADD: 
			hnode->cur_num += serv_priv->log_num;
			break;
		case STAT_SERVICE_DEL:
			assert(hnode->cur_num >= serv_priv->log_num);
			hnode->cur_num -= serv_priv->log_num;
			break;
		default: break;
	}

	return 0;
}

void service_grule_statistic_count(int32_t serv_type, int32_t log_num, STAT_SERVICE_TYPE_t stat_type)
{
	stat_service_priv_t serv_priv;
	long cb_ret;

	serv_priv.log_num = log_num;
	serv_priv.type = stat_type;
	MESA_htable_search_cb(g_pgvalve_info.htable_stat_serv, (unsigned char *)&serv_type, sizeof(serv_type), service_grule_statistic_count_cb, &serv_priv, &cb_ret);
}

static long service_grule_reach_limit_cb(void *data, const uchar *key, uint size, void *arg)
{
	stat_service_hnode_t *hnode = (stat_service_hnode_t *)data;
	
	return (hnode==NULL || hnode->cur_num<hnode->max_num)?0:1;
}

bool service_grule_reach_limit(int32_t serv_type)
{
	long cb_ret;
	
	MESA_htable_search_cb(g_pgvalve_info.htable_stat_serv, (unsigned char *)&serv_type, sizeof(serv_type), service_grule_reach_limit_cb, NULL, &cb_ret);
	return (cb_ret==1);
}

static long pz_trans_statistic_count_cb(void *data, const uchar *key, uint size, void *arg)
{
	statistic_incr_t *hnode = (statistic_incr_t *)data;
	stat_table_priv_t *htable_priv = (stat_table_priv_t *)arg;
	int ret;

	if(hnode == NULL)
	{
		hnode = (statistic_incr_t *)calloc(1, sizeof(statistic_incr_t));
		if((ret = MESA_htable_add(g_pgvalve_info.htable_stat_log, key, size, hnode)) < 0)
		{
			free(hnode);
			return -1;
		}
	}

	switch(htable_priv->type)
	{
		case STAT_FIELD_RECV:
			break;
		case STAT_FIELD_RERROR:
		case STAT_FIELD_RVALID:
		case STAT_FIELD_RINVALID:
			hnode->num[htable_priv->type] += htable_priv->log_num;
			hnode->num[STAT_FIELD_RECV] += htable_priv->log_num;
			break;
			
		default: 
			hnode->num[htable_priv->type] += htable_priv->log_num;
			break;
	}

	return 0;
}

void pz_trans_statistic_count(int32_t service_id, int32_t table_id, int32_t log_num, STAT_FIELD_INCR_t type)
{
	stat_table_key_t hash_key;
	stat_table_priv_t htable_priv;
	long cb_ret = 0;

	hash_key.service_id = service_id;
	hash_key.table_id = table_id;

	htable_priv.log_num = log_num;
	htable_priv.type = type;

	MESA_htable_search_cb(g_pgvalve_info.htable_stat_log, (unsigned char *)&hash_key, sizeof(stat_table_key_t), pz_trans_statistic_count_cb, (void*)&htable_priv, &cb_ret);
}

static long table_statistic_incr_cb(void *data, const uchar *key, uint size, void *arg)
{
	statistic_incr_t *hnode = (statistic_incr_t *)data;
	statistic_incr_t *statistic_incr = (statistic_incr_t *)arg;

	if(hnode != NULL)
	{
		for(int i=0;i<STAT_INCR_NUM; i++)
		{
			statistic_incr->num[i] = hnode->num[i];
			hnode->num[i] = 0;
		}
	}

	return 0;
}

static int table_onesw_exist_iterate(const uchar * key, uint size, void * data, void *user)
{
	table_hash_key_t *table_key = (table_hash_key_t *)key;
	iterator_table_priv_t *iterator_priv = (iterator_table_priv_t *)user;
	swtable_state_t sw_state;

	if(table_key->service_id==iterator_priv->table->service_id && table_key->table_id==iterator_priv->table->table_id_key)
	{
		onesw_config_hnode_t *hnode = (onesw_config_hnode_t *)data;

		iterator_priv->stat_out->num[STAT_FIELD_EXITS]   += hnode->full.size();
		if(!iterator_priv->table->parent->get_hnode_sw_action_recur(iterator_priv->table->parent, table_key->dsetid, table_key->did, &sw_state))
		{
			iterator_priv->stat_out->num[STAT_FIELD_PENDING] += hnode->full.size();
		}
		else if(sw_state.switcher==SW_STAT_DEACTIVATE)
		{
			iterator_priv->stat_out->num[STAT_FIELD_EINACTIVE] += hnode->full.size();
		}
		else
		{
			iterator_priv->stat_out->num[STAT_FIELD_EACTIVE] += hnode->full.size();
		}
	}
	return ITERATE_CB_RET_CONTINUE_FLAG;
}

static int64_t table_three_erase_did_cb(void *data, const uchar *key, uint size, void *arg)
{
	three_config_hnode_t *hnode = (three_config_hnode_t *)data;
	int64_t did = *(int64_t *)arg;

	if(hnode->didset.find(did) != hnode->didset.end())
	{
		hnode->didset.erase(did);
	}
	return 0;
}

void table_three_erase_did(configure_table_t *table_three, int64_t dsetid, int64_t did)
{
	table_hash_key_t hash_key;
	long cb_ret;

	hash_key.service_id = table_three->service_id;
	hash_key.table_id	= table_three->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= 0;

	MESA_htable_search_cb(table_three->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), table_three_erase_did_cb, &did, &cb_ret);
}

static int table_two_exist_iterate(const uchar * key, uint size, void * data, void *user)
{
	table_hash_key_t *table_key = (table_hash_key_t *)key;
	iterator_table_priv_t *iterator_priv = (iterator_table_priv_t *)user;

	if(table_key->service_id==iterator_priv->table->service_id && table_key->table_id==iterator_priv->table->table_id_key)
	{
		two_config_hnode_t *hnode = (two_config_hnode_t *)data;

		if(hnode->sw_status == SW_STAT_DEACTIVATE && (time(NULL)-hnode->last_invalid)>=g_pgvalve_info.sw_invalid_timeout)
		{
			if(iterator_priv->table->parent != NULL)
			{
				table_three_erase_did(iterator_priv->table->parent, hnode->dsetid, hnode->did);
			}
			MESA_htable_del(iterator_priv->table->hash_handle, key, size, two_destroy_hnode);
			return ITERATE_CB_RET_CONTINUE_FLAG;
		}

		iterator_priv->stat_out->num[STAT_FIELD_EXITS]   += 1;
		if(hnode->sw_status == SW_STAT_ACTIVATE)
		{
			iterator_priv->stat_out->num[STAT_FIELD_EACTIVE] += 1;
		}
		else
		{
			iterator_priv->stat_out->num[STAT_FIELD_EINACTIVE] += 1;
		}
	}
	return ITERATE_CB_RET_CONTINUE_FLAG;
}

static int64_t two_hnode_active_exist_cb(void *data, const uchar *key, uint size, void *arg)
{
	two_config_hnode_t *hnode = (two_config_hnode_t *)data;

	if(hnode != NULL && hnode->sw_status==SW_STAT_ACTIVATE)
	{
		return 1;
	}
	return 0;
}

static bool table_two_active_node_exist(configure_table_t *table_two_maybe, three_config_hnode_t *hnode)
{
	map<int64_t, int64_t>::iterator iter;
	long two_active;	
	table_hash_key_t hash_key;

	while(table_two_maybe != NULL)
	{
		if(table_two_maybe->child != NULL)
		{
			for(iter=hnode->didset.begin(); iter!=hnode->didset.end(); iter++)
			{
				hash_key.service_id = table_two_maybe->service_id;
				hash_key.table_id	= table_two_maybe->table_id_key;
				hash_key.dsetid 	= hnode->dsetid;
				hash_key.did		= iter->first;

				MESA_htable_search_cb(table_two_maybe->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), two_hnode_active_exist_cb, NULL, &two_active);
				if(two_active)
				{
					return true;
				}
			}
		}
		table_two_maybe = table_two_maybe->next;
	}

	return false;
}

static int table_three_exist_iterate(const uchar * key, uint size, void * data, void *user)
{
	table_hash_key_t *table_key = (table_hash_key_t *)key;
	iterator_table_priv_t *iterator_priv = (iterator_table_priv_t *)user;

	if(table_key->service_id==iterator_priv->table->service_id && table_key->table_id==iterator_priv->table->table_id_key)
	{
		three_config_hnode_t *hnode = (three_config_hnode_t *)data;

		if(!hnode->exist_before)
		{
			//有活跃二级表节点存在，就不能删除，否则三级节点生效到来，无法得知did集合
			if(!table_two_active_node_exist(iterator_priv->table->child, hnode))
			{
				MESA_htable_del(iterator_priv->table->hash_handle, key, size, three_destroy_hnode);
			}
			return ITERATE_CB_RET_CONTINUE_FLAG;
		}
		
		if(hnode->sw_status==SW_STAT_DEACTIVATE && (time(NULL)-hnode->last_invalid)>=g_pgvalve_info.sw_invalid_timeout 
			&& !table_two_active_node_exist(iterator_priv->table->child, hnode))
		{
			MESA_htable_del(iterator_priv->table->hash_handle, key, size, three_destroy_hnode);
			return ITERATE_CB_RET_CONTINUE_FLAG;
		}
		
		iterator_priv->stat_out->num[STAT_FIELD_EXITS]   += 1;
		if(hnode->sw_status == SW_STAT_ACTIVATE)
		{
			iterator_priv->stat_out->num[STAT_FIELD_EACTIVE] += 1;
		}
		else
		{
			iterator_priv->stat_out->num[STAT_FIELD_EINACTIVE] += 1;
		}
	}
	return ITERATE_CB_RET_CONTINUE_FLAG;
}

void valve_statistic_log_output(map<string, configure_table_t *> &tables_one, map<string, configure_table_t *> &tables_sw)
{
	statistic_incr_t statistic_incr, statistic_incr_tt;
	statistic_exist_t statistic_exist, statistic_exist_tt;
	map<string, configure_table_t *>::iterator iter;
	configure_table_t *table;
	stat_table_key_t hash_key;
	iterator_table_priv_t iterator_priv;
	long cb_ret;

	MESA_handle_runtime_log(g_pgvalve_info.log_statistic, RLOG_LV_FATAL, "STAT_INFO_TABLE", "---------------------------------------------------------------------------------------------------------------------------------");
	//先SW表统计，能够刷新其状态
	memset(&statistic_incr_tt, 0, sizeof(statistic_incr_t));
	memset(&statistic_exist_tt, 0, sizeof(statistic_exist_t));
	for(iter=tables_sw.begin(); iter!=tables_sw.end(); iter++)
	{
		memset(&statistic_incr, 0, sizeof(statistic_incr_t));
		memset(&statistic_exist, 0, sizeof(statistic_exist_t));

		table = iter->second;
		hash_key.service_id = table->service_id;
		hash_key.table_id   = table->table_id_key;
		MESA_htable_search_cb(g_pgvalve_info.htable_stat_log, (uchar*)&hash_key, sizeof(stat_table_key_t), table_statistic_incr_cb, (void *)&statistic_incr, &cb_ret);
		iterator_priv.table = table;
		iterator_priv.stat_out = &statistic_exist;
		if(is_table_three(table))
		{
			MESA_htable_iterate_bytime(table->hash_handle, ITERATE_TYPE_OLDEST_FIRST, table_three_exist_iterate, (void *)&iterator_priv);
		}
		else
		{
			MESA_htable_iterate_bytime(table->hash_handle, ITERATE_TYPE_OLDEST_FIRST, table_two_exist_iterate, (void *)&iterator_priv);
		}

		MESA_handle_runtime_log(g_pgvalve_info.log_statistic, RLOG_LV_FATAL, "STAT_INFO_TABLE_SWT", 
			"%-20s-->RECV: %4llu, ERROR: %4llu, RVALID: %4llu, RINVALID: %4llu, DISP_SUCC: %4llu, DISP_FAIL: %4llu, DISP_LIMIT: %4llu; EXIST: %4llu, EACTIVE: %4llu, EINACTIVE: %4llu, PENDING: %4llu",
			table->table_name, statistic_incr.num[STAT_FIELD_RECV], statistic_incr.num[STAT_FIELD_RERROR], statistic_incr.num[STAT_FIELD_RVALID], 
			statistic_incr.num[STAT_FIELD_RINVALID], statistic_incr.num[STAT_FIELD_DISP_SUCC], statistic_incr.num[STAT_FIELD_DISP_FAIL], statistic_incr.num[STAT_FIELD_DISP_LIMIT],
			statistic_exist.num[STAT_FIELD_EXITS], statistic_exist.num[STAT_FIELD_EACTIVE], statistic_exist.num[STAT_FIELD_EINACTIVE], statistic_exist.num[STAT_FIELD_PENDING]);

		for(int j=0; j<STAT_INCR_NUM; j++)
		{
			statistic_incr_tt.num[j] += statistic_incr.num[j];
			if(g_pgvalve_info.fsstatid_trig)
			{
				FS_operate(g_pgvalve_info.fsstat_handle, table->statid_table, g_pgvalve_info.statid_incr[j], FS_OP_ADD, statistic_incr.num[j]);
			}
		}
		for(int j=0; j<STAT_EXIST_NUM; j++)
		{
			statistic_exist_tt.num[j] += statistic_exist.num[j];
			if(g_pgvalve_info.fsstatid_trig)
			{
				FS_operate(g_pgvalve_info.fsstat_handle, table->statid_table, g_pgvalve_info.statid_exist[j], FS_OP_SET, statistic_exist.num[j]);
			}
		}
	}
	MESA_handle_runtime_log(g_pgvalve_info.log_statistic, RLOG_LV_FATAL, "STAT_INFO_TOTAL_SWT", 
		"---------------------->RECV: %4llu, ERROR: %4llu, RVALID: %4llu, RINVALID: %4llu, DISP_SUCC: %4llu, DISP_FAIL: %4llu, DISP_LIMIT: %4llu; EXIST: %4llu, EACTIVE: %4llu, EINACTIVE: %4llu, PENDING: %4llu",
		statistic_incr_tt.num[STAT_FIELD_RECV], statistic_incr_tt.num[STAT_FIELD_RERROR], statistic_incr_tt.num[STAT_FIELD_RVALID], 
		statistic_incr_tt.num[STAT_FIELD_RINVALID], statistic_incr_tt.num[STAT_FIELD_DISP_SUCC], statistic_incr_tt.num[STAT_FIELD_DISP_FAIL], statistic_incr_tt.num[STAT_FIELD_DISP_LIMIT],
		statistic_exist_tt.num[STAT_FIELD_EXITS], statistic_exist_tt.num[STAT_FIELD_EACTIVE], statistic_exist_tt.num[STAT_FIELD_EINACTIVE], statistic_exist_tt.num[STAT_FIELD_PENDING]);
	if(g_pgvalve_info.fsstatid_trig)
	{
		for(int j=0; j<STAT_INCR_NUM; j++)
		{
			FS_operate(g_pgvalve_info.fsstat_handle, g_pgvalve_info.statid_table_sw, g_pgvalve_info.statid_incr[j], FS_OP_ADD, statistic_incr_tt.num[j]);
		}
		for(int j=0; j<STAT_EXIST_NUM; j++)
		{
			FS_operate(g_pgvalve_info.fsstat_handle, g_pgvalve_info.statid_table_sw, g_pgvalve_info.statid_exist[j], FS_OP_SET, statistic_exist_tt.num[j]);
		}
	}

	//ONE表统计
	memset(&statistic_incr_tt, 0, sizeof(statistic_incr_t));
	memset(&statistic_exist_tt, 0, sizeof(statistic_exist_t));
	for(iter=tables_one.begin(); iter!=tables_one.end(); iter++)
	{
		memset(&statistic_incr, 0, sizeof(statistic_incr_t));
		memset(&statistic_exist, 0, sizeof(statistic_exist_t));

		table = iter->second;
		hash_key.service_id = table->service_id;
		hash_key.table_id   = table->table_id_key;
		MESA_htable_search_cb(g_pgvalve_info.htable_stat_log, (uchar*)&hash_key, sizeof(stat_table_key_t), table_statistic_incr_cb, (void *)&statistic_incr, &cb_ret);
		if(table->parent != NULL)
		{
			iterator_priv.table = table;
			iterator_priv.stat_out = &statistic_exist;
			MESA_htable_iterate_bytime(table->hash_handle, ITERATE_TYPE_OLDEST_FIRST, table_onesw_exist_iterate, (void *)&iterator_priv);
		}
		else
		{
			statistic_exist.num[STAT_FIELD_EXITS] = MESA_htable_get_elem_num(table->hash_handle);
		}

		MESA_handle_runtime_log(g_pgvalve_info.log_statistic, RLOG_LV_FATAL, "STAT_INFO_TABLE_ONE", 
			"%-20s-->RECV: %4llu, ERROR: %4llu, RVALID: %4llu, RINVALID: %4llu, DISP_SUCC: %4llu, DISP_FAIL: %4llu, DISP_LIMIT: %4llu; EXIST: %4llu, EACTIVE: %4llu, EINACTIVE: %4llu, PENDING: %4llu",
			table->table_name, statistic_incr.num[STAT_FIELD_RECV], statistic_incr.num[STAT_FIELD_RERROR], statistic_incr.num[STAT_FIELD_RVALID], 
			statistic_incr.num[STAT_FIELD_RINVALID], statistic_incr.num[STAT_FIELD_DISP_SUCC], statistic_incr.num[STAT_FIELD_DISP_FAIL], statistic_incr.num[STAT_FIELD_DISP_LIMIT],
			statistic_exist.num[STAT_FIELD_EXITS], statistic_exist.num[STAT_FIELD_EACTIVE], statistic_exist.num[STAT_FIELD_EINACTIVE], statistic_exist.num[STAT_FIELD_PENDING]);

		for(int j=0; j<STAT_INCR_NUM; j++)
		{
			statistic_incr_tt.num[j] += statistic_incr.num[j];
			if(g_pgvalve_info.fsstatid_trig)
			{
				FS_operate(g_pgvalve_info.fsstat_handle, table->statid_table, g_pgvalve_info.statid_incr[j], FS_OP_ADD, statistic_incr.num[j]);
			}
		}
		for(int j=0; j<STAT_EXIST_NUM; j++)
		{
			statistic_exist_tt.num[j] += statistic_exist.num[j];
			if(g_pgvalve_info.fsstatid_trig)
			{
				FS_operate(g_pgvalve_info.fsstat_handle, table->statid_table, g_pgvalve_info.statid_exist[j], FS_OP_SET, statistic_exist.num[j]);
			}
		}
	}
	MESA_handle_runtime_log(g_pgvalve_info.log_statistic, RLOG_LV_FATAL, "STAT_INFO_TOTAL_ONE", 
		"---------------------->RECV: %4llu, ERROR: %4llu, RVALID: %4llu, RINVALID: %4llu, DISP_SUCC: %4llu, DISP_FAIL: %4llu, DISP_LIMIT: %4llu; EXIST: %4llu, EACTIVE: %4llu, EINACTIVE: %4llu, PENDING: %4llu",
		statistic_incr_tt.num[STAT_FIELD_RECV], statistic_incr_tt.num[STAT_FIELD_RERROR], statistic_incr_tt.num[STAT_FIELD_RVALID], 
		statistic_incr_tt.num[STAT_FIELD_RINVALID], statistic_incr_tt.num[STAT_FIELD_DISP_SUCC], statistic_incr_tt.num[STAT_FIELD_DISP_FAIL], statistic_incr_tt.num[STAT_FIELD_DISP_LIMIT],
		statistic_exist_tt.num[STAT_FIELD_EXITS], statistic_exist_tt.num[STAT_FIELD_EACTIVE], statistic_exist_tt.num[STAT_FIELD_EINACTIVE], statistic_exist_tt.num[STAT_FIELD_PENDING]);
	if(g_pgvalve_info.fsstatid_trig)
	{
		for(int j=0; j<STAT_INCR_NUM; j++)
		{
			FS_operate(g_pgvalve_info.fsstat_handle, g_pgvalve_info.statid_table_one, g_pgvalve_info.statid_incr[j], FS_OP_ADD, statistic_incr_tt.num[j]);
		}
		for(int j=0; j<STAT_EXIST_NUM; j++)
		{
			FS_operate(g_pgvalve_info.fsstat_handle, g_pgvalve_info.statid_table_one, g_pgvalve_info.statid_exist[j], FS_OP_SET, statistic_exist_tt.num[j]);
		}
	}
	
	//Service统计输出
	MESA_htable_iterate_bytime(g_pgvalve_info.htable_stat_serv, ITERATE_TYPE_OLDEST_FIRST, service_config_limit_iterator, NULL);
	if(g_pgvalve_info.fsstatid_trig)
	{
		FS_passive_output(g_pgvalve_info.fsstat_handle);
	}
}

