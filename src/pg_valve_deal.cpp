#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <signal.h>

#include <MESA/MESA_htable.h>
#include <MESA/field_stat2.h>
#include <MESA/Maat_rule.h>

#include "pg_valve_deal.h"
#include "pg_valve_main.h"
#include "pg_valve_maat.h"
#include "pg_valve_stat.h"

extern pgvavle_global_info_t g_pgvalve_info;

SSCANF_ERROR_NO_t _wrap_grule_check(grule_t *grule);

const char*sscanf_error_string(SSCANF_ERROR_NO_t type)
{
	switch(type)
	{
		case SSCANF_ERROR_NUM:		return "filed num wrong";
		case SSCANF_ERROR_DID:		return "did is null";
		case SSCANF_ERROR_DSETID:	return "appid is null";
		case SSCANF_ERROR_SERVICE:	return "service unrecognized";
		case SSCANF_ERROR_IP:		return "ipaddr format wrong";
		case SSCANF_ERROR_TUPLE:	return "tuple combination invalid";
		case SSCANF_ERROR_LIMIT:	return "limit rate is null";
		case SSCANF_ERROR_RULE:		return "ip/port and/or mask content invalid";
		default: return "unknown";
	}
}

SSCANF_ERROR_NO_t fill_in_dsetid_did_limitid(const char *user_region, int64_t *did,int64_t *dsetid, int32_t *limit_rate)
{
	const char *pos;
	
	if(did!=NULL && NULL!=(pos = strcasestr(user_region, "DOMAIN_ID=")))
	{
		if(sscanf(pos+strlen("DOMAIN_ID="), "%ld", did) != 1)
		{
			return SSCANF_ERROR_DID;
		}
	}
	
	if(dsetid!=NULL && NULL!=(pos = strcasestr(user_region, "APP_ID=")))
	{
		if(sscanf(pos+strlen("APP_ID="), "%ld", dsetid) != 1)
		{
			return SSCANF_ERROR_DSETID;
		}
	}
	
	if(limit_rate!=NULL && NULL!=(pos = strcasestr(user_region, "RATE_LIMIT=")))
	{
		if(sscanf(pos+strlen("RATE_LIMIT="), "%d", limit_rate) != 1)
		{
			return SSCANF_ERROR_LIMIT;
		}
	}

	return SSCANF_OK;
}

void one_destroy_hnode(void *data)
{
	free(data);
}

//以Ruleid为KEY
//Return: 1-下发；0-不下发
int64_t one_deal_config_incr_cb(void *data, const uchar *key, uint size, void *arg)
{
	one_config_hnode_t *hnode = (one_config_hnode_t *)data;
	htable_privdata_t  *priv  = (htable_privdata_t  *)arg;
	configure_table_t *table = priv->table;
	int32_t ret;

	if(hnode != NULL)
	{
		priv->iprule.disp_status = hnode->disp_status;
	}
	
	//保证增量一定推送一次，如果有失败，下次推增量重试
	ret = dispatch_config_to_c3(priv->table->table_name, priv->table->service_id, priv->table->table_id_key, priv->iprule);
	if(hnode != NULL)
	{
		//如果删除失败，会残留内存，占用一个空间，检查日志查找这个情况
		if(priv->iprule.disp_status==0 && priv->iprule.grule.action == GRULE_ACTION_DEL)
		{
			MESA_htable_del(table->hash_handle, key, size, one_destroy_hnode);
		}
		else
		{
			if(priv->iprule.grule.action == GRULE_ACTION_DEL) //未删除成功的，标记为删除状态
			{
				hnode->grule.action = GRULE_ACTION_DEL;
			}
			hnode->disp_status = priv->iprule.disp_status;
		}
	}
	else if(ret != DISP_LIMIT && (priv->iprule.grule.action == GRULE_ACTION_ADD))
	{
		hnode = (one_config_hnode_t *)calloc(1, sizeof(one_config_hnode_t));
		if((ret = MESA_htable_add(table->hash_handle, key, size, hnode)) < 0)
		{
			free(hnode);
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s, MESA_htable_add failed: %d, ruleid: %u", table->table_name, ret, priv->iprule.grule.rule_id);
			pz_trans_statistic_count(table->service_id, table->table_id_key, 1, STAT_FIELD_DISP_FAIL);
			return -1;
		}
		hnode->grule = priv->iprule.grule;
		hnode->disp_status = priv->iprule.disp_status;
	}
	
	return ret;
}

void one_maat_start_callback(int32_t update_type, void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;

	maat_data->update_type = update_type;
	
	if(maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_FULL))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s recv another full config, restart.", maat_data->table->table_name);
		exit(10);
	}
	if(!maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_INC))
	{
		maat_data->table->over_flag = true;
	}
}

SSCANF_ERROR_NO_t fill_in_region_grule_ip(const char* table_line, one_config_hnode_t *iprule)
{
	int32_t ret, addr_type, protocol, direction, is_valid, action, service, limit_rate=0;
	int64_t region_id, group_id;
	char src_ip[128], src_ip_mask[128], src_port[20], src_port_mask[20];
	char dst_ip[128], dst_ip_mask[128], dst_port[20], dst_port_mask[20], user_region[4096]={0};
	grule_map_info_t gmap_info;

	user_region[0] = 0;
	ret = sscanf(table_line, "%ld\t%ld\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s",
			&region_id, &group_id, &addr_type,
			src_ip, src_ip_mask, src_port, src_port_mask,
			dst_ip, dst_ip_mask, dst_port, dst_port_mask,
			&protocol, &direction, &is_valid,
			&action, &service, user_region); 
	if(ret != 16 && ret!=17) //user_region只有限速表有
	{
		return SSCANF_ERROR_NUM;
	}
	iprule->disp_status = 0;
	iprule->grule.rule_id = region_id;
	if(fill_in_dsetid_did_limitid(user_region, NULL, NULL, &limit_rate))
		return SSCANF_ERROR_LIMIT;
	if(service_to_c3_servtype(service, (limit_rate/10)*10, &gmap_info))
		return SSCANF_ERROR_SERVICE;
	iprule->grule.srv_type = gmap_info.serv_type;
	iprule->grule.rule_scope = gmap_info.rule_scope;
	iprule->grule.durable = 1;
	iprule->grule.action = is_valid?GRULE_ACTION_ADD:GRULE_ACTION_DEL;
	iprule->grule.rule_type.grule_type = 0;
	iprule->grule.rule_type.ddir_flag = (direction==G_DIR_DOUBLE)?1:0;

	switch(addr_type)
	{
		case 4:
			if(inet_pton(AF_INET, src_ip, &iprule->grule.m4.sip) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, src_ip_mask, &iprule->grule.m4.sip_mask) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, dst_ip, &iprule->grule.m4.dip) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, dst_ip_mask, &iprule->grule.m4.dip_mask) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			iprule->grule.m4.sport = ntohs(atoi(src_port));
			iprule->grule.m4.sport_mask = ntohs(atoi(src_port_mask));
			iprule->grule.m4.dport = ntohs(atoi(dst_port));
			iprule->grule.m4.dport_mask = ntohs(atoi(dst_port_mask));
			iprule->grule.m4.proto = protocol;
			iprule->grule.m4.proto_mask = ~0;
			iprule->grule.big_type = GRULE_BIG_TYPE_MASK4;

			iprule->grule.rule_type.sip_flag = (iprule->grule.m4.sip!=0)?1:0;
			iprule->grule.rule_type.sipmsk_flag = (iprule->grule.m4.sip!=0&&iprule->grule.m4.sip_mask!=0)?1:0;
			iprule->grule.rule_type.dip_flag = (iprule->grule.m4.dip!=0)?1:0;
			iprule->grule.rule_type.dipmsk_flag = (iprule->grule.m4.dip!=0&&iprule->grule.m4.dip_mask!=0)?1:0;
			iprule->grule.rule_type.sport_flag = (iprule->grule.m4.sport!=0)?1:0;
			iprule->grule.rule_type.spmsk_flag = (iprule->grule.m4.sport!=0&&iprule->grule.m4.sport_mask!=0)?1:0;
			iprule->grule.rule_type.dport_flag = (iprule->grule.m4.dport!=0)?1:0;
			iprule->grule.rule_type.dpmsk_flag= (iprule->grule.m4.dport!=0&&iprule->grule.m4.dport_mask!=0)?1:0;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.rule_type.pmsk_flag = ((iprule->grule.rule_type.sipmsk_flag||iprule->grule.rule_type.dipmsk_flag) && protocol!=0)?1:0;
			break;
			
		case 6:
			if(inet_pton(AF_INET6, src_ip, iprule->grule.m6.sip.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, src_ip_mask, iprule->grule.m6.sip_mask.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, dst_ip, iprule->grule.m6.dip.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, dst_ip_mask, iprule->grule.m6.dip_mask.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			iprule->grule.m6.sport = ntohs(atoi(src_port));
			iprule->grule.m6.sport_mask = ntohs(atoi(src_port_mask));
			iprule->grule.m6.dport = ntohs(atoi(dst_port));
			iprule->grule.m6.dport_mask = ntohs(atoi(dst_port_mask));
			iprule->grule.m6.proto = protocol;
			iprule->grule.m6.proto_mask = ~0;
			iprule->grule.big_type = GRULE_BIG_TYPE_MASK6;

			iprule->grule.rule_type.sip_flag = (iprule->grule.m6.sip.ip6_l[0] | iprule->grule.m6.sip.ip6_l[1])?1:0;
			iprule->grule.rule_type.sipmsk_flag = ((iprule->grule.m6.sip.ip6_l[0] | iprule->grule.m6.sip.ip6_l[1])&&(iprule->grule.m6.sip_mask.ip6_l[0] | iprule->grule.m6.sip_mask.ip6_l[1]))?1:0;
			iprule->grule.rule_type.dip_flag = (iprule->grule.m6.dip.ip6_l[0] | iprule->grule.m6.dip.ip6_l[1])?1:0;
			iprule->grule.rule_type.dipmsk_flag = ((iprule->grule.m6.dip.ip6_l[0] | iprule->grule.m6.dip.ip6_l[1])&&(iprule->grule.m6.dip_mask.ip6_l[0] | iprule->grule.m6.dip_mask.ip6_l[1]))?1:0;
			iprule->grule.rule_type.sport_flag = (iprule->grule.m6.sport!=0)?1:0;
			iprule->grule.rule_type.spmsk_flag = (iprule->grule.m6.sport!=0&&iprule->grule.m6.sport_mask!=0)?1:0;
			iprule->grule.rule_type.dport_flag = (iprule->grule.m6.dport!=0)?1:0;
			iprule->grule.rule_type.dpmsk_flag= (iprule->grule.m6.dport!=0&&iprule->grule.m6.dport_mask!=0)?1:0;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.rule_type.pmsk_flag = ((iprule->grule.rule_type.sipmsk_flag||iprule->grule.rule_type.dipmsk_flag) && protocol!=0)?1:0;
			break;
		default: 
			assert(0);
			return SSCANF_ERROR_PROTOCOL;
	}

	return SSCANF_OK;
}

SSCANF_ERROR_NO_t fill_in_region_grule_pool(const char* table_line, one_config_hnode_t *iprule)
{
	int32_t ret, addr_type, direction, location, is_valid, service, protocol, limit_rate=0;
	int64_t region_id;
	char ipaddr[128], port[8], user_region[4096];
	grule_map_info_t gmap_info;

	ret = sscanf(table_line, "%ld\t%d\t%d\t%s\t%s\t%d\t%s\t%d\t%d\t%d", 
		&region_id, &addr_type, &protocol, ipaddr, port, &direction, user_region, &location, &is_valid, &service);
	if(ret != 10)
	{
		return SSCANF_ERROR_NUM;
	}
	iprule->disp_status = 0;
	iprule->grule.rule_id = region_id;
	if(fill_in_dsetid_did_limitid(user_region, NULL, NULL, &limit_rate))
		return SSCANF_ERROR_LIMIT;
	if(service_to_c3_servtype(service, (limit_rate/10)*10, &gmap_info))
		return SSCANF_ERROR_SERVICE;
	iprule->grule.srv_type = gmap_info.serv_type;
	iprule->grule.rule_scope = gmap_info.rule_scope;
	iprule->grule.durable = 1;
	iprule->grule.action = is_valid?GRULE_ACTION_ADD:GRULE_ACTION_DEL;
	iprule->grule.rule_type.grule_type = 0;
	iprule->grule.rule_type.ddir_flag = (direction==G_DIR_DOUBLE)?1:0;

	switch(addr_type)
	{
		case 4:
			if(direction == G_DIR_S2C)
			{
				if(inet_pton(AF_INET, ipaddr, &iprule->grule.s4.dip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s4.dport = ntohs(atoi(port));
				iprule->grule.rule_type.dip_flag = (iprule->grule.s4.dip!=0)?1:0;
				iprule->grule.rule_type.dport_flag = (iprule->grule.s4.dport!=0)?1:0;
			}
			else
			{
				if(inet_pton(AF_INET, ipaddr, &iprule->grule.s4.sip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s4.sport = ntohs(atoi(port));
				iprule->grule.rule_type.sip_flag = (iprule->grule.s4.sip!=0)?1:0;
				iprule->grule.rule_type.sport_flag = (iprule->grule.s4.sport!=0)?1:0;
			}
			iprule->grule.s4.proto = protocol;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.big_type = GRULE_BIG_TYPE_SIMPLE4;
			break;
			
		case 6:
			if(direction == G_DIR_S2C)
			{
				if(inet_pton(AF_INET6, ipaddr, &iprule->grule.s6.dip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s6.dport = ntohs(atoi(port));
				iprule->grule.rule_type.dip_flag = (iprule->grule.s6.dip.ip6_l[0] | iprule->grule.s6.dip.ip6_l[1])?1:0;
				iprule->grule.rule_type.dport_flag = (iprule->grule.s6.dport!=0)?1:0;
			}
			else
			{
				if(inet_pton(AF_INET6, ipaddr, &iprule->grule.s6.sip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s6.sport = ntohs(atoi(port));
				iprule->grule.rule_type.sip_flag = (iprule->grule.s6.sip.ip6_l[0] | iprule->grule.s6.sip.ip6_l[1])?1:0;
				iprule->grule.rule_type.sport_flag = (iprule->grule.s6.sport!=0)?1:0;
			}
			iprule->grule.s6.proto = protocol;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.big_type = GRULE_BIG_TYPE_SIMPLE6;
			break;
		default: 
			return SSCANF_ERROR_PROTOCOL;
	}

	return SSCANF_OK;
}

void one_maat_update_callback(int32_t table_id, const char* table_line, void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;
	table_hash_key_t hash_key;
	htable_privdata_t  priv;
	int64_t cb_ret;
	SSCANF_ERROR_NO_t code, check;

	memset(&priv, 0 ,sizeof(htable_privdata_t));
	switch(maat_data->table->region_type)
	{
		case REGION_TYPE_IP:
			code = fill_in_region_grule_ip(table_line, &priv.iprule);
			break;
		case REGION_TYPE_POOL:
			code = fill_in_region_grule_pool(table_line, &priv.iprule);
			break;
		default: 
			assert(0);return;
	}
	if(code!=SSCANF_OK || (check=_wrap_grule_check(&priv.iprule.grule)))
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: %s, table %s, line: %s", 
			sscanf_error_string((code!=SSCANF_OK)?code:check), maat_data->table->table_name, table_line);
		return ;
	}
	pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, (priv.iprule.grule.action==GRULE_ACTION_ADD)?STAT_FIELD_RVALID:STAT_FIELD_RINVALID);
	
	priv.table	= maat_data->table;
	priv.dsetid = 0;
	priv.did	= 0;

	hash_key.service_id = maat_data->table->service_id;
	hash_key.table_id	= maat_data->table->table_id_key;
	hash_key.dsetid 	= 0;
	hash_key.did		= priv.iprule.grule.rule_id;

	pthread_rwlock_rdlock(&g_pgvalve_info.rwlock);
 	MESA_htable_search_cb(maat_data->table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), one_deal_config_incr_cb, (void*)&priv, &cb_ret);
	pthread_rwlock_unlock(&g_pgvalve_info.rwlock);
}

void one_maat_finish_callback(void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;
	//int32_t last_table = 0;
	//int64_t version;

	//如果没有全量，会不会调用?
	if(maat_data->update_type == MAAT_RULE_UPDATE_TYPE_FULL)
	{
		maat_data->table->over_flag = true;
	}
	
	/*更新版本号，暂时不做
	Maat_read_state(maat_data->maat_service->get_maat_feather(), MAAT_STATE_LAST_UPDATING_TABLE, &last_table, sizeof(last_table));
	if(last_table)
	{
		Maat_read_state(maat_data->maat_service->get_maat_feather(), MAAT_STATE_VERSION, &version, sizeof(version));
		maat_data->maat_service->store_latest_version(version);
	}*/
}

configure_table_t *new_table_instance_one(const char *table_name, int32_t service_id, int32_t table_id, int32_t region_type, MESA_htable_handle hash_handle)
{
	configure_table_t *table_one;

	table_one = (configure_table_t *)calloc(1, sizeof(configure_table_t));
	table_one->table_name	= table_name;
	table_one->service_id	= service_id;
	table_one->hash_handle	= hash_handle;
	table_one->over_flag	= false;
	table_one->region_type  = region_type;
	table_one->table_id_key = table_id;

	table_one->maat_start_cb = one_maat_start_callback;
	table_one->maat_update_cb= one_maat_update_callback;
	table_one->maat_finish_cb= one_maat_finish_callback;
	return table_one;
}

//disp_active统一控制生效和失效的配置(针对新增的配置)
//新来的增量配置，保证iprule.disp_status为0
static int32_t onesw_update_config_set_full(const char *table_name, int service_id, int table_id, onesw_config_hnode_t *hnode, one_config_hnode_t &iprule, bool disp_active)
{
	int ret = 0;
	
	if(iprule.grule.action == GRULE_ACTION_ADD)
	{
		if(hnode->full.find(iprule.grule.rule_id) != hnode->full.end())
		{
			hnode->full[iprule.grule.rule_id].grule = iprule.grule; //新加的覆盖(若原来存在是DEL，不能覆盖下发状态)
		}
		else
		{
			hnode->full[iprule.grule.rule_id] = iprule;
		}
		if(disp_active)
		{
			ret = dispatch_config_to_c3(table_name, service_id, table_id, hnode->full[iprule.grule.rule_id]);
			if(ret==DISP_LIMIT && hnode->full[iprule.grule.rule_id].disp_status==0) //到达上限，且之前未下发
			{
				hnode->full.erase(iprule.grule.rule_id);
			}
		}
	}
	else
	{
		if(disp_active)
		{
			if(hnode->full.find(iprule.grule.rule_id) != hnode->full.end())
			{
				iprule.disp_status = hnode->full[iprule.grule.rule_id].disp_status;
				ret = dispatch_config_to_c3(table_name, service_id, table_id, iprule);
				hnode->full[iprule.grule.rule_id].disp_status = iprule.disp_status;
			}
			else
			{
				ret = dispatch_config_to_c3(table_name, service_id, table_id, iprule);
			}
		}

		//未删除成功，保留它；不然下次失效该配置时，无法减少上限计数
		if(hnode->full.find(iprule.grule.rule_id) != hnode->full.end())
		{
			if(hnode->full[iprule.grule.rule_id].disp_status == 0) 
			{
				hnode->full.erase(iprule.grule.rule_id);
			}
			else
			{	//未删除成功的，标记为删除状态
				hnode->full[iprule.grule.rule_id].grule.action = GRULE_ACTION_DEL;
			}
		}
	}
	
	return ret;
}

//处理首次全量以及后续增量
int64_t onesw_deal_config_incr_cb(void *data, const uchar *key, uint size, void *arg)
{
	onesw_config_hnode_t *hnode = (onesw_config_hnode_t *)data;
	htable_privdata_t  *priv  = (htable_privdata_t  *)arg;
	configure_table_t *table = priv->table;
	int32_t ret;
	swtable_state_t sw_state;

	if(hnode == NULL)
	{
		hnode = new __onesw_config_hnode();
		if((ret = MESA_htable_add(table->hash_handle, key, size, hnode)) < 0)
		{
			delete hnode;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s, MESA_htable_add failed: %d, ruleid: %u", table->table_name, ret, priv->iprule.grule.rule_id);
			pz_trans_statistic_count(table->service_id, table->table_id_key, 1, STAT_FIELD_DISP_FAIL);
			return -1;
		}
		hnode->dsetid= priv->dsetid;
		hnode->did	 = priv->did;
	}

	if(!table->parent->get_hnode_sw_action_recur(table->parent, priv->dsetid, priv->did, &sw_state))
	{
		onesw_update_config_set_full(priv->table->table_name, priv->table->service_id, priv->table->table_id_key, hnode, priv->iprule, false);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: onesw table %s dsetid=%lu;did=%lu;cfgid=%lu dont dispatch because parent is not exist.", 
			table->table_name, priv->dsetid, priv->did, priv->iprule.grule.rule_id);
		return 0;
	}

	priv->iprule.grule.srv_type = sw_state.gmap_info.serv_type;
	priv->iprule.grule.rule_scope = sw_state.gmap_info.rule_scope;
	if(sw_state.switcher == SW_STAT_DEACTIVATE)
	{
		onesw_update_config_set_full(priv->table->table_name, priv->table->service_id, priv->table->table_id_key, hnode, priv->iprule, false);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: onesw table %s dsetid=%lu;did=%lu;cfgid=%lu dont dispatch because parent is closed.", 
			table->table_name, priv->dsetid, priv->did, priv->iprule.grule.rule_id);
		return 0;
	}

	onesw_update_config_set_full(priv->table->table_name, priv->table->service_id, priv->table->table_id_key, hnode, priv->iprule, true);
	return 1;
}

//二级开关驱动DID集合开关
static int64_t onesw_drive_full_cfg_by_two_cb(void *data, const uchar *key, uint size, void *arg)
{
	onesw_config_hnode_t *hnode = (onesw_config_hnode_t *)data;
	htable_privdata_t *priv = (htable_privdata_t *)arg;
	map<int64_t, one_config_hnode_t>::iterator iter;
	int ret=0;

	if(hnode != NULL)
	{
		for(iter=hnode->full.begin(); iter!=hnode->full.end() && ret!=DISP_RETRY; )
		{
			one_config_hnode_t iprule = iter->second; //存储的可能有失效的(删除未成功)

			iprule.grule.srv_type = priv->gmap_info.serv_type;
			iprule.grule.rule_scope = priv->gmap_info.rule_scope;
			if(priv->did_switch == SW_STAT_DEACTIVATE)
			{
				iprule.grule.action = GRULE_ACTION_DEL;
			}

			ret = dispatch_config_to_c3(priv->table->table_name, priv->table->service_id, priv->table->table_id_key, iprule);
			iter->second.disp_status = iprule.disp_status;
			if(iprule.disp_status == 0 && (iter->second.grule.action == GRULE_ACTION_DEL || ret==DISP_LIMIT))
			{
				hnode->full.erase(iter++); //map遍历删除的做法
			}
			else
			{
				 iter++;
			}
		}
	}

	return ret;
}

int32_t onesw_drive_full_cfg_by_two(configure_table_t *table, int64_t dsetid, int64_t did, swtable_state_t *sw_state)
{
	table_hash_key_t hash_key;
	htable_privdata_t  priv;
 	int64_t cb_ret;

	hash_key.service_id = table->service_id;
	hash_key.table_id	= table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= did;

	priv.table = table;
	priv.dsetid = dsetid;
	priv.did = did;
	priv.did_switch = sw_state->switcher;
	priv.gmap_info = sw_state->gmap_info;
	
 	MESA_htable_search_cb(table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), onesw_drive_full_cfg_by_two_cb, (void*)&priv, &cb_ret);
	return cb_ret;
}

void onesw_maat_start_callback(int32_t update_type,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;

	maat_data->update_type = update_type;
	
	if(maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_FULL))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s recv another full config, restart.", maat_data->table->table_name);
		exit(10);
	}
	if(!maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_INC))
	{
		maat_data->table->over_flag = true;
	}
}

SSCANF_ERROR_NO_t onesw_fill_in_region_grule_ip(const char* table_line, one_config_hnode_t *iprule, int64_t *did, int64_t *dsetid)
{
	int32_t ret, addr_type, protocol, direction, is_valid, action, service;
	int64_t region_id, group_id;
	char src_ip[128], src_ip_mask[128], src_port[8], src_port_mask[8];
	char dst_ip[128], dst_ip_mask[128], dst_port[8], dst_port_mask[8];
	char user_region[4096];

	ret = sscanf(table_line, "%ld\t%ld\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s",
			&region_id, &group_id, &addr_type,
			src_ip, src_ip_mask, src_port, src_port_mask,
			dst_ip, dst_ip_mask, dst_port, dst_port_mask,
			&protocol, &direction, &is_valid,
			&action, &service, user_region);
	if(ret != 17)
	{
		return SSCANF_ERROR_NUM;
	}
	iprule->disp_status = 0;
	iprule->grule.rule_id = region_id;
	iprule->grule.durable = 1;
	iprule->grule.action = is_valid?GRULE_ACTION_ADD:GRULE_ACTION_DEL;
	iprule->grule.rule_type.grule_type = 0;
	iprule->grule.rule_type.ddir_flag = (direction==G_DIR_DOUBLE)?1:0;

	switch(addr_type)
	{
		case 4:
			if(inet_pton(AF_INET, src_ip, &iprule->grule.m4.sip) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, src_ip_mask, &iprule->grule.m4.sip_mask) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, dst_ip, &iprule->grule.m4.dip) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET, dst_ip_mask, &iprule->grule.m4.dip_mask) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			iprule->grule.m4.sport = ntohs(atoi(src_port));
			iprule->grule.m4.sport_mask = ntohs(atoi(src_port_mask));
			iprule->grule.m4.dport = ntohs(atoi(dst_port));
			iprule->grule.m4.dport_mask = ntohs(atoi(dst_port_mask));
			iprule->grule.m4.proto = protocol;
			iprule->grule.m4.proto_mask = ~0;
			iprule->grule.big_type = GRULE_BIG_TYPE_MASK4;
			
			iprule->grule.rule_type.sip_flag = (iprule->grule.m4.sip!=0)?1:0;
			iprule->grule.rule_type.sipmsk_flag = (iprule->grule.m4.sip!=0&&iprule->grule.m4.sip_mask!=0)?1:0;
			iprule->grule.rule_type.dip_flag = (iprule->grule.m4.dip!=0)?1:0;
			iprule->grule.rule_type.dipmsk_flag = (iprule->grule.m4.dip!=0&&iprule->grule.m4.dip_mask!=0)?1:0;
			iprule->grule.rule_type.sport_flag = (iprule->grule.m4.sport!=0)?1:0;
			iprule->grule.rule_type.spmsk_flag = (iprule->grule.m4.sport!=0&&iprule->grule.m4.sport_mask!=0)?1:0;
			iprule->grule.rule_type.dport_flag = (iprule->grule.m4.dport!=0)?1:0;
			iprule->grule.rule_type.dpmsk_flag= (iprule->grule.m4.dport!=0&&iprule->grule.m4.dport_mask!=0)?1:0;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.rule_type.pmsk_flag = ((iprule->grule.rule_type.sipmsk_flag||iprule->grule.rule_type.dipmsk_flag) && protocol!=0)?1:0;
			break;
			
		case 6:
			if(inet_pton(AF_INET6, src_ip, iprule->grule.m6.sip.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, src_ip_mask, iprule->grule.m6.sip_mask.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, dst_ip, iprule->grule.m6.dip.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			if(inet_pton(AF_INET6, dst_ip_mask, iprule->grule.m6.dip_mask.ip6_c) != 1)
			{
				return SSCANF_ERROR_IP;
			}
			iprule->grule.m6.sport = ntohs(atoi(src_port));
			iprule->grule.m6.sport_mask = ntohs(atoi(src_port_mask));
			iprule->grule.m6.dport = ntohs(atoi(dst_port));
			iprule->grule.m6.dport_mask = ntohs(atoi(dst_port_mask));
			iprule->grule.m6.proto = protocol;
			iprule->grule.m6.proto_mask = ~0;
			iprule->grule.big_type = GRULE_BIG_TYPE_MASK6;

			iprule->grule.rule_type.sip_flag = (iprule->grule.m6.sip.ip6_l[0] | iprule->grule.m6.sip.ip6_l[1])?1:0;
			iprule->grule.rule_type.sipmsk_flag = ((iprule->grule.m6.sip.ip6_l[0] | iprule->grule.m6.sip.ip6_l[1])&&(iprule->grule.m6.sip_mask.ip6_l[0] | iprule->grule.m6.sip_mask.ip6_l[1]))?1:0;
			iprule->grule.rule_type.dip_flag = (iprule->grule.m6.dip.ip6_l[0] | iprule->grule.m6.dip.ip6_l[1])?1:0;
			iprule->grule.rule_type.dipmsk_flag = ((iprule->grule.m6.dip.ip6_l[0] | iprule->grule.m6.dip.ip6_l[1])&&(iprule->grule.m6.dip_mask.ip6_l[0] | iprule->grule.m6.dip_mask.ip6_l[1]))?1:0;
			iprule->grule.rule_type.sport_flag = (iprule->grule.m6.sport!=0)?1:0;
			iprule->grule.rule_type.spmsk_flag = (iprule->grule.m6.sport!=0&&iprule->grule.m6.sport_mask!=0)?1:0;
			iprule->grule.rule_type.dport_flag = (iprule->grule.m6.dport!=0)?1:0;
			iprule->grule.rule_type.dpmsk_flag= (iprule->grule.m6.dport!=0&&iprule->grule.m6.dport_mask!=0)?1:0;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.rule_type.pmsk_flag = ((iprule->grule.rule_type.sipmsk_flag||iprule->grule.rule_type.dipmsk_flag) && protocol!=0)?1:0;
			break;
		default: 
			return SSCANF_ERROR_PROTOCOL;
	}

	return fill_in_dsetid_did_limitid(user_region, did, dsetid, NULL);
}

SSCANF_ERROR_NO_t onesw_fill_in_region_grule_find(const char* table_line, one_config_hnode_t *iprule, int64_t *did,int64_t *dsetid)
{
	int32_t ret, addr_type, protocol, direction, location, is_valid;
	int64_t region_id;
	char ipaddr[128], port[8], user_region[4096];

	ret = sscanf(table_line, "%ld\t%d\t%d\t%s\t%s\t%d\t%s\t%d\t%d", 
		&region_id, &addr_type, &protocol, ipaddr, port, &direction, user_region, &location, &is_valid);
	if(ret != 9)
	{
		return SSCANF_ERROR_NUM;
	}
	iprule->disp_status = 0;
	iprule->grule.rule_id = region_id;
	iprule->grule.durable = 1;
	iprule->grule.action = is_valid?GRULE_ACTION_ADD:GRULE_ACTION_DEL;
	iprule->grule.rule_type.grule_type = 0;
	iprule->grule.rule_type.ddir_flag = (direction==G_DIR_DOUBLE)?1:0;

	switch(addr_type)
	{
		case 4:
			if(direction == G_DIR_S2C)
			{
				if(inet_pton(AF_INET, ipaddr, &iprule->grule.s4.dip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s4.dport = ntohs(atoi(port));
				iprule->grule.rule_type.dip_flag = (iprule->grule.s4.dip!=0)?1:0;
				iprule->grule.rule_type.dport_flag = (iprule->grule.s4.dport!=0)?1:0;
			}
			else
			{
				if(inet_pton(AF_INET, ipaddr, &iprule->grule.s4.sip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s4.sport = ntohs(atoi(port));
				iprule->grule.rule_type.sip_flag = (iprule->grule.s4.sip!=0)?1:0;
				iprule->grule.rule_type.sport_flag = (iprule->grule.s4.sport!=0)?1:0;
			}
			iprule->grule.s4.proto = protocol;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.big_type = GRULE_BIG_TYPE_SIMPLE4;
			break;
			
		case 6:
			if(direction == G_DIR_S2C)
			{
				if(inet_pton(AF_INET6, ipaddr, &iprule->grule.s6.dip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s6.dport = ntohs(atoi(port));
				iprule->grule.rule_type.dip_flag = (iprule->grule.s6.dip.ip6_l[0] | iprule->grule.s6.dip.ip6_l[1])?1:0;
				iprule->grule.rule_type.dport_flag = (iprule->grule.s6.dport!=0)?1:0;
			}
			else
			{
				if(inet_pton(AF_INET6, ipaddr, &iprule->grule.s6.sip) != 1)
				{
					return SSCANF_ERROR_IP;
				}
				iprule->grule.s6.sport = ntohs(atoi(port));
				iprule->grule.rule_type.sip_flag = (iprule->grule.s6.sip.ip6_l[0] | iprule->grule.s6.sip.ip6_l[1])?1:0;
				iprule->grule.rule_type.sport_flag = (iprule->grule.s6.sport!=0)?1:0;
			}
			iprule->grule.s6.proto = protocol;
			iprule->grule.rule_type.proto_flag = (protocol!=0)?1:0;
			iprule->grule.big_type = GRULE_BIG_TYPE_SIMPLE6;
			break;
		default: 
			return SSCANF_ERROR_PROTOCOL;
	}

	return fill_in_dsetid_did_limitid(user_region, did, dsetid, NULL);
}

void onesw_maat_update_callback(int32_t table_id,const char* table_line,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;
	table_hash_key_t hash_key;
	htable_privdata_t  priv;
	int64_t cb_ret, dsetid=0, did=0;
	SSCANF_ERROR_NO_t code, check;

	memset(&priv, 0 ,sizeof(htable_privdata_t));
	switch(maat_data->table->region_type)
	{
		case REGION_TYPE_IP:
			code = onesw_fill_in_region_grule_ip(table_line, &priv.iprule, &did, &dsetid);
			break;
		case REGION_TYPE_FIND:
			code = onesw_fill_in_region_grule_find(table_line, &priv.iprule, &did, &dsetid);
			break;
		default: return;
	}
	if(code!=SSCANF_OK || (did==0 && dsetid==0) || (check=_wrap_grule_check(&priv.iprule.grule)))
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: %s, table %s, line: %s", 
			sscanf_error_string(code!=SSCANF_OK?code:((did==0 && dsetid==0)?SSCANF_ERROR_DID:check)), maat_data->table->table_name, table_line);
		return ;
	}	
	pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, (priv.iprule.grule.action==GRULE_ACTION_ADD)?STAT_FIELD_RVALID:STAT_FIELD_RINVALID);

	priv.table	= maat_data->table;
	priv.dsetid = dsetid;
	priv.did	= did;

	hash_key.service_id = maat_data->table->service_id;
	hash_key.table_id	= maat_data->table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= (maat_data->table->parent->parent!=NULL)?did:0;

	pthread_rwlock_rdlock(&g_pgvalve_info.rwlock);
 	MESA_htable_search_cb(maat_data->table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), onesw_deal_config_incr_cb, (void*)&priv, &cb_ret);
	pthread_rwlock_unlock(&g_pgvalve_info.rwlock);
}

void onesw_maat_finish_callback(void* u_para)
{
	one_maat_finish_callback(u_para);
}

configure_table_t *new_table_instance_onesw(const char *table_name, int32_t service_id, int32_t table_id, int32_t region_type, MESA_htable_handle hash_handle)
{
	configure_table_t *table_onesw;

	table_onesw = (configure_table_t *)calloc(1, sizeof(configure_table_t));
	table_onesw->table_name	= table_name;
	table_onesw->service_id	= service_id;
	table_onesw->hash_handle	= hash_handle;
	table_onesw->over_flag	= false;
	table_onesw->region_type  = region_type;
	table_onesw->table_id_key = table_id;

	table_onesw->drive_full_cfg_by_parent = onesw_drive_full_cfg_by_two;

	table_onesw->maat_start_cb = onesw_maat_start_callback;
	table_onesw->maat_update_cb= onesw_maat_update_callback;
	table_onesw->maat_finish_cb= onesw_maat_finish_callback;
	return table_onesw;
}

void two_destroy_hnode(void *data)
{
	two_config_hnode_t *hnode = (two_config_hnode_t *)data;
	delete hnode;
}

//添加二级开关表哈希元素，返回开关状态
static int64_t two_get_hnode_sw_action_cb(void *data, const uchar *key, uint size, void *arg)
{
	two_config_hnode_t *hnode = (two_config_hnode_t *)data;
	swtable_state_t *sw_state  = (swtable_state_t  *)arg;

	if(hnode == NULL)
	{
		return 0;
	}

	sw_state->switcher = hnode->sw_status;
	sw_state->gmap_info = hnode->gmap_info;
	return 1;
}

int32_t two_get_hnode_sw_action(configure_table_t *table, int64_t dsetid, int64_t did, swtable_state_t *sw_state)
{
	table_hash_key_t hash_key;
	int64_t exist_two;
	
	hash_key.service_id = table->service_id;
	hash_key.table_id	= table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= did;

	MESA_htable_search_cb(table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), two_get_hnode_sw_action_cb, (void*)sw_state, &exist_two);
	if(exist_two == 0)
	{
		return 0;
	}

	if(table->parent != NULL)
	{
		swtable_state_t sw_state_three;
		if(!table->parent->get_hnode_sw_action_recur(table->parent, dsetid, did, &sw_state_three))
		{
			return 0;
		}
		sw_state->gmap_info = sw_state_three.gmap_info;
		sw_state->switcher = (sw_state_three.switcher==SW_STAT_DEACTIVATE)?SW_STAT_DEACTIVATE:sw_state->switcher;
	}

	return 1;
}

//KEY: ServiceID+TableID+DSET+DID
int64_t two_deal_config_incr_cb(void *data, const uchar *key, uint size, void *arg)
{
	two_config_hnode_t *hnode = (two_config_hnode_t *)data;
	htable_privdata_t  *priv  = (htable_privdata_t  *)arg;
	configure_table_t *table = priv->table;
	int32_t ret;
	swtable_state_t sw_state;
	bool sw_parent= true;

	if(hnode == NULL)
	{
		hnode = new __two_config_hnode();
		if((ret = MESA_htable_add(table->hash_handle, key, size, hnode)) < 0)
		{
			delete hnode;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s, MESA_htable_add failed: %d, ruleid: %u", table->table_name, ret, priv->iprule.grule.rule_id);
			pz_trans_statistic_count(table->service_id, table->table_id_key, 1, STAT_FIELD_DISP_FAIL);
			return -1;
		}
		hnode->dsetid= priv->dsetid;
		hnode->did	 = priv->did;
	}
	sw_state.gmap_info = hnode->gmap_info = priv->gmap_info;
	sw_state.switcher = hnode->sw_status = priv->did_switch;
	if(hnode->sw_status == SW_STAT_DEACTIVATE)
	{
		hnode->last_invalid = time(NULL);
	}
	
	if(table->parent != NULL)
	{
		swtable_state_t sw_state_three;

		//父节点集合
		table->parent->update_hnode_dset(table->parent, priv->dsetid, priv->did);
		//父开关
		if(!table->parent->get_hnode_sw_action_recur(table->parent, priv->dsetid, priv->did, &sw_state_three))
		{
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: table two %s, dsetid=%lu;did=%lu dont drive child because parent is not exist.", table->table_name, priv->dsetid, priv->did);
			return 0;
		}
		sw_state.gmap_info = sw_state_three.gmap_info;
		sw_state.switcher = (sw_state_three.switcher==SW_STAT_DEACTIVATE)?SW_STAT_DEACTIVATE:hnode->sw_status;
		sw_parent = (sw_state_three.switcher==SW_STAT_ACTIVATE)?true:false;
	}

	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: table two %s dsetid=%lu;did=%lu, %s.", 
		table->table_name, priv->dsetid, priv->did, sw_parent?"drive onesw":"dont drive onesw because parent is closed");
	if(sw_parent)
	{		
		configure_table_t *child = table->child;
		while(child != NULL)
		{
			child->drive_full_cfg_by_parent(child, hnode->dsetid, hnode->did, &sw_state);
			child = child->next;
		}
	}
	return 1;
}

int32_t two_drive_did_full_by_three(configure_table_t *table, int64_t dsetid, int64_t did, swtable_state_t *sw_state)
{
	table_hash_key_t hash_key;
 	int64_t two_exist;
	swtable_state_t sw_state_two;
	configure_table_t *child = table->child;

	hash_key.service_id = table->service_id;
	hash_key.table_id	= table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= did;

 	MESA_htable_search_cb(table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), two_get_hnode_sw_action_cb, (void*)&sw_state_two, &two_exist);
	if(!two_exist)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: table two %s desetid=%lu;did=%lu, drive full by three: drive onesw end becase two not exist.", 
			table->table_name, dsetid, did);
		return 0;
	}
	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_DEBUG, MODULE_NAME, "pz_dispatch: table two %s desetid=%lu;did=%lu, drive full by three: %s.", 
		table->table_name, dsetid, did, (sw_state_two.switcher == SW_STAT_ACTIVATE)?"drive onesw":"drive onesw end because two is closed");

	//对于生效下发失败的情况，只能再推一次增量来重试了
	//sw_state指的是三级表的开关，此处它是增量，可以当作二级表的开关
	if(sw_state_two.switcher == SW_STAT_ACTIVATE)
	{
		while(child != NULL)
		{
			child->drive_full_cfg_by_parent(child, dsetid, did, sw_state);
			child = child->next;
		}
	}
	return 0;
}

void two_maat_start_callback(int32_t update_type,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;

	maat_data->update_type = update_type;
	
	if(maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_FULL))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s recv another full config, restart.", maat_data->table->table_name);
		exit(10);
	}
	if(!maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_INC))
	{
		maat_data->table->over_flag = true;
	}
}

void two_maat_update_callback(int32_t table_id,const char* table_line,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;
	table_hash_key_t hash_key;
	htable_privdata_t  priv;
	int64_t cb_ret, dsetid=0, did=0;
	int32_t region_id, group_id, expr_type, match_method,is_hexbin,is_valid, service, action, limit_rate=0;
	char keywods[1024], user_region[4096];

	memset(&priv, 0 ,sizeof(htable_privdata_t));
	cb_ret = sscanf(table_line, "%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s", 
		&region_id, &group_id, keywods, &expr_type, &match_method, &is_hexbin, &is_valid, &action, &service, user_region);
	if(cb_ret!=10 || fill_in_dsetid_did_limitid(user_region, &did, &dsetid, &limit_rate) || did==0 || (maat_data->table->parent!=NULL && dsetid==0))
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: table %s invalid line: %s", maat_data->table->table_name, table_line);
		return ;
	}
	if(maat_data->table->parent==NULL && service_to_c3_servtype(service, (limit_rate/10)*10, &priv.gmap_info))
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: table %s service type error: %s", maat_data->table->table_name, table_line);
		return ;
	}
	pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, is_valid?STAT_FIELD_RVALID:STAT_FIELD_RINVALID);

	priv.table	= maat_data->table;
	priv.dsetid = dsetid;
	priv.did	= did;
	priv.did_switch = is_valid?SW_STAT_ACTIVATE:SW_STAT_DEACTIVATE;

	hash_key.service_id = maat_data->table->service_id;
	hash_key.table_id	= maat_data->table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= did;

	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_recv: table %s, region_id: %u, is_valid: %d, user_region: %s", 
		maat_data->table->table_name, region_id, is_valid, user_region);
	
	pthread_rwlock_rdlock(&g_pgvalve_info.rwlock);
 	MESA_htable_search_cb(maat_data->table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), two_deal_config_incr_cb, (void*)&priv, &cb_ret);
	pthread_rwlock_unlock(&g_pgvalve_info.rwlock);
}

void two_maat_finish_callback(void* u_para)
{
	one_maat_finish_callback(u_para);
}

configure_table_t *new_table_instance_two(const char *table_name, int32_t service_id, int32_t table_id, MESA_htable_handle hash_handle)
{
	configure_table_t *table_two;

	table_two = (configure_table_t *)calloc(1, sizeof(configure_table_t));
	table_two->table_name	= table_name;
	table_two->service_id	= service_id;
	table_two->hash_handle	= hash_handle;
	table_two->over_flag	= false;
	table_two->table_id_key = table_id;

	table_two->get_hnode_sw_action_recur = two_get_hnode_sw_action;

	table_two->drive_full_cfg_by_parent = two_drive_did_full_by_three;

	table_two->maat_start_cb = two_maat_start_callback;
	table_two->maat_update_cb= two_maat_update_callback;
	table_two->maat_finish_cb= two_maat_finish_callback;
	return table_two;
}

void three_destroy_hnode(void *data)
{
	three_config_hnode_t *hnode = (three_config_hnode_t *)data;
	delete hnode;
}

static int64_t three_update_hnode_dset_cb(void *data, const uchar *key, uint size, void *arg)
{
	three_config_hnode_t *hnode = (three_config_hnode_t *)data;
	htable_privdata_t  *priv  = (htable_privdata_t	*)arg;
	int32_t ret;

	if(hnode == NULL)
	{
		hnode = new __three_config_hnode();
		if((ret = MESA_htable_add(priv->table->hash_handle, key, size, hnode)) < 0)
		{
			delete hnode;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s, MESA_htable_add failed: %d, ruleid: %u", priv->table->table_name, ret, priv->iprule.grule.rule_id);
			return -1;
		}
		hnode->dsetid = priv->dsetid;
		hnode->exist_before = false;
	}

	if(hnode->didset.find(priv->did) == hnode->didset.end())
	{
		hnode->didset[priv->did] = priv->did;
	}

	return 1;
}

int32_t three_update_hnode_dset(configure_table_t *table, int64_t dsetid, int64_t did)
{
	table_hash_key_t hash_key;
	htable_privdata_t priv;
	int64_t cb_ret;

	hash_key.service_id = table->service_id;
	hash_key.table_id	= table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= 0;

	memset(&priv, 0 ,sizeof(htable_privdata_t));
	priv.table	= table;
	priv.dsetid = dsetid;
	priv.did	= did;

	MESA_htable_search_cb(table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), three_update_hnode_dset_cb, (void*)&priv, &cb_ret);
	return cb_ret;
}

int64_t three_get_hnode_sw_action_cb(void *data, const uchar *key, uint size, void *arg)
{
	three_config_hnode_t *hnode = (three_config_hnode_t *)data;
	swtable_state_t *sw_state  = (swtable_state_t  *)arg;

	if(hnode == NULL || !hnode->exist_before)
	{
		return 0;
	}

	sw_state->switcher = hnode->sw_status;
	sw_state->gmap_info = hnode->gmap_info;
	return 1;
}

//更新顶级开关表，每个DSET的DID集合，返回开关状态
int32_t three_get_hnode_sw_action(configure_table_t *table, int64_t dsetid, int64_t did, swtable_state_t *sw_state)
{
	table_hash_key_t hash_key;
	int64_t cb_ret;

	hash_key.service_id = table->service_id;
	hash_key.table_id	= table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= 0;

	MESA_htable_search_cb(table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), three_get_hnode_sw_action_cb, (void*)sw_state, &cb_ret);
	return cb_ret;
}

//三次开关表首次全量和增量
int64_t three_deal_config_incr_cb(void *data, const uchar *key, uint size, void *arg)
{
	three_config_hnode_t *hnode = (three_config_hnode_t *)data;
	htable_privdata_t  *priv  = (htable_privdata_t	*)arg;
	configure_table_t *table = priv->table;
	int32_t ret;
	swtable_state_t sw_state;

	if(hnode == NULL)
	{
		hnode = new __three_config_hnode();
		if((ret = MESA_htable_add(table->hash_handle, key, size, hnode)) < 0)
		{
			delete hnode;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s, MESA_htable_add failed: %d, ruleid: %u", table->table_name, ret, priv->iprule.grule.rule_id);
			pz_trans_statistic_count(table->service_id, table->table_id_key, 1, STAT_FIELD_DISP_FAIL);
			return -1;
		}
		hnode->dsetid = priv->dsetid;
	}
	sw_state.switcher = hnode->sw_status = priv->did_switch;
	sw_state.gmap_info = hnode->gmap_info = priv->gmap_info;
	if(hnode->sw_status == SW_STAT_DEACTIVATE)
	{
		hnode->last_invalid = time(NULL);
	}
	
	configure_table_t *child = table->child;
	map<int64_t, int64_t>::iterator iter;
	int64_t did; //驱动two表时是DID，驱动onesw表时是DSET
	while(child != NULL)
	{
		if(child->child != NULL)
		{
			for(iter=hnode->didset.begin(); iter!=hnode->didset.end(); iter++)
			{
				did = iter->first;
				child->drive_full_cfg_by_parent(child, hnode->dsetid, did, &sw_state);
			}
		}
		else
		{
			child->drive_full_cfg_by_parent(child, hnode->dsetid, 0, &sw_state);
		}
		child = child->next;
	}
	
	hnode->exist_before = true;
	return 0;
}

void three_maat_start_callback(int32_t update_type,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;

	maat_data->update_type = update_type;
	
	if(maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_FULL))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pz_error: table %s recv another full config, restart.", maat_data->table->table_name);
		exit(10);
	}
	if(!maat_data->table->over_flag && (update_type == MAAT_RULE_UPDATE_TYPE_INC))
	{
		maat_data->table->over_flag = true;
	}
}

void three_maat_update_callback(int32_t table_id,const char* table_line,void* u_para)
{
	maat_callback_data_t *maat_data = (maat_callback_data_t *)u_para;
	table_hash_key_t hash_key;
	htable_privdata_t  priv;
	int64_t cb_ret, dsetid=0, did=0;
	int32_t expr_type, match_method,is_hexbin,is_valid, service, action, limit_rate=0;
	int64_t region_id, group_id;
	char keywods[1024], user_region[4096];

	cb_ret = sscanf(table_line, "%ld\t%ld\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s", 
		&region_id, &group_id, keywods, &expr_type, &match_method, &is_hexbin, &is_valid, &action, &service, user_region);
	if((cb_ret != 10) || fill_in_dsetid_did_limitid(user_region, &did, &dsetid, &limit_rate) || dsetid==0)
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: table %s invalid line: %s", maat_data->table->table_name, table_line);
		return ;
	}

	memset(&priv, 0 ,sizeof(htable_privdata_t));
	priv.table	= maat_data->table;
	priv.dsetid = dsetid;
	priv.did	= did;
	priv.did_switch = is_valid?SW_STAT_ACTIVATE:SW_STAT_DEACTIVATE;
	if(service_to_c3_servtype(service, (limit_rate/10)*10, &priv.gmap_info))
	{
		pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, STAT_FIELD_RERROR);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_error: table %s service type error: %s", maat_data->table->table_name, table_line);
		return ;
	}
	pz_trans_statistic_count(maat_data->table->service_id, maat_data->table->table_id_key, 1, is_valid?STAT_FIELD_RVALID:STAT_FIELD_RINVALID);

	hash_key.service_id = maat_data->table->service_id;
	hash_key.table_id	= maat_data->table->table_id_key;
	hash_key.dsetid 	= dsetid;
	hash_key.did		= 0;

	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_INFO, MODULE_NAME, "pz_recv: table %s, region_id: %u, is_valid: %d, user_region: %s", 
		maat_data->table->table_name, region_id, is_valid, user_region);
	
	pthread_rwlock_rdlock(&g_pgvalve_info.rwlock);
 	MESA_htable_search_cb(maat_data->table->hash_handle, (unsigned char *)&hash_key, sizeof(table_hash_key_t), three_deal_config_incr_cb, (void*)&priv, &cb_ret);
	pthread_rwlock_unlock(&g_pgvalve_info.rwlock);
}

void three_maat_finish_callback(void* u_para)
{
	one_maat_finish_callback(u_para);
}

configure_table_t *new_table_instance_three(const char *table_name, int32_t service_id, int32_t table_id, MESA_htable_handle hash_handle)
{
	configure_table_t *table_three;

	table_three = (configure_table_t *)calloc(1, sizeof(configure_table_t));
	table_three->table_name	= table_name;
	table_three->service_id	= service_id;
	table_three->hash_handle	= hash_handle;
	table_three->over_flag	= false;
	table_three->table_id_key = table_id;

	table_three->update_hnode_dset = three_update_hnode_dset;
	table_three->get_hnode_sw_action_recur = three_get_hnode_sw_action;

	table_three->maat_start_cb = three_maat_start_callback;
	table_three->maat_update_cb= three_maat_update_callback;
	table_three->maat_finish_cb= three_maat_finish_callback;
	return table_three;
}

static int one_drive_full_iterate_cb(const uchar * key, uint size, void * data, void *user)
{
	table_hash_key_t *table_key = (table_hash_key_t *)key;
	one_config_hnode_t *hnode;
	configure_table_t *table = (configure_table_t *)user;

	if(table_key->service_id!=table->service_id || table_key->table_id!=table->table_id_key)
	{
		return ITERATE_CB_RET_CONTINUE_FLAG;
	}
	
	hnode = (one_config_hnode_t *)data;
	hnode->disp_status = 0;
	if(hnode->grule.action == GRULE_ACTION_ADD)
	{
		dispatch_config_to_c3(table->table_name, table->service_id, table->table_id_key, *hnode);
	}
	else
	{
		MESA_htable_del(table->hash_handle, key, size, one_destroy_hnode);
	}
	return ITERATE_CB_RET_CONTINUE_FLAG;
}

static int onesw_drive_full_iterate_cb(const uchar * key, uint size, void * data, void *user)
{
	table_hash_key_t *table_key = (table_hash_key_t *)key;
	onesw_config_hnode_t *hnode;
	configure_table_t *table = (configure_table_t *)user;
	map<int64_t, one_config_hnode_t>::iterator iter;
	swtable_state_t sw_state;

	if(table_key->service_id!=table->service_id || table_key->table_id!=table->table_id_key)
	{
		return ITERATE_CB_RET_CONTINUE_FLAG;
	}
	
	hnode = (onesw_config_hnode_t *)data;
	if(!table->parent->get_hnode_sw_action_recur(table->parent, hnode->dsetid, hnode->did, &sw_state))
	{
		return ITERATE_CB_RET_CONTINUE_FLAG;
	}

	for(iter=hnode->full.begin(); iter!=hnode->full.end(); )
	{
		if(iter->second.grule.action==GRULE_ACTION_DEL)
		{
			hnode->full.erase(iter++);
		}
		else
		{
			if(sw_state.switcher == SW_STAT_ACTIVATE)
			{
				iter->second.disp_status = 0;
				iter->second.grule.srv_type = sw_state.gmap_info.serv_type;
				iter->second.grule.rule_scope = sw_state.gmap_info.rule_scope;
				dispatch_config_to_c3(table->table_name, table->service_id, table->table_id_key, iter->second);
			}
			iter++;
		}
	}

	return ITERATE_CB_RET_CONTINUE_FLAG;
}

//链接重新建立，只下发生效全量
void* thread_dispatch_full_config(void *arg)
{
	struct __tables_map_ref *table_map = (struct __tables_map_ref *)arg;
	map<string, configure_table_t *>::iterator iter;
	configure_table_t *table;
	sigset_t sigmask;
	int signo;

	prctl(PR_SET_NAME, "pgvalve_dispfull");
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	if(pthread_sigmask(SIG_BLOCK, &sigmask, NULL))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "pthread_sigmask failed.");
		exit(1);
	}
	
	while(1)
	{
		if(sigwait(&sigmask, &signo) || signo != SIGUSR1)
		{
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "sigwait SIGUSR1 failed.");
			sleep(10);
			continue;
		}
		
		pthread_rwlock_wrlock(&g_pgvalve_info.rwlock);
		clear_c3_first_status();
		service_config_clear();
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "--------------Attention: reconnect to c3, drive all tables full start.--------------");
		for(iter=table_map->tables_one.begin(); iter!=table_map->tables_one.end(); iter++)
		{
			table = iter->second;
			if(table->parent != NULL) //onesw由父表驱动
			{
				MESA_htable_iterate_bytime(table->hash_handle, ITERATE_TYPE_OLDEST_FIRST, onesw_drive_full_iterate_cb, (void *)table);
			}
			else
			{
				MESA_htable_iterate_bytime(table->hash_handle, ITERATE_TYPE_OLDEST_FIRST, one_drive_full_iterate_cb, (void *)table);
			}
		}
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "--------------Attention: reconnect to c3, drive all tables full over.--------------");
		pthread_rwlock_unlock(&g_pgvalve_info.rwlock);
	}

	return NULL;
}

