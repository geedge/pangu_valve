#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>

#include "pg_valve_c3.h"
#include "pg_valve_main.h"
#include "check_ip_legal.h"

extern pgvavle_global_info_t g_pgvalve_info;
pg_grule_handle_t g_grule_handle;

int authdata_hex2mem(const char *source, int srclen, char* dest)
{
	int i,j;
	unsigned char c,h4bit,l4bit;

	if( NULL == source || NULL==dest || srclen<=0 )
	{
		return -1;
	}

	for(i=0,j=0; i<srclen; )
	{
		c = source[i];
		if(c >= '0' && c <= '9')
			h4bit = c - '0';
		else if(c >= 'A' && c <= 'F')
			h4bit = c - 'A' + 10;
		else if(c >= 'a' && c <= 'f')
			h4bit = c - 'a' + 10;
		else
		{
			if(i == srclen -1)//the last c is 0a
			{
				return j;
			}
			else
			{
				return -1;
			}
		}
		++i;

		if(i>=srclen)
		{
			return -1;
		}

		c = source[i];
		if(c >= '0' && c <= '9')
			l4bit = c - '0';
		else if(c >= 'A' && c <= 'F')
			l4bit = c - 'A' + 10;
		else if(c >= 'a' && c <= 'f')
			l4bit = c - 'a' + 10;
		else
		{
			return -1;
		}
		dest[j]= (h4bit<<4)|l4bit;				

		j++;
		i++;
	}
	dest[j] = '\0';

	return j;
}

const char *get_disp_status_str(int disp_status)
{
	switch(disp_status)
	{
		case DISP_SUCC: 		return "succ";
		case DISP_FAIL_C3:		return "fail_c3";
		case DISP_FAIL_C3_CHECK:return "fail_c3_check";
		case DISP_LIMIT:		return "fail_reach_limit";
		case DISP_RETRY:		return "fail_wait_full";
		default: 				return "unknown";
	}
}

void write_grule_log(const char *table_name, grule_t &grule, int disp_status, int errcode)
{
	char sip[128], dip[128], smask[128], dmask[128];
	u_int16_t sport, dport;

	switch(grule.big_type)
	{
		case GRULE_BIG_TYPE_SIMPLE4:
			inet_ntop(AF_INET, &grule.s4.sip, sip, 128);
			inet_ntop(AF_INET, &grule.s4.dip, dip, 128);
			sport = grule.s4.sport;
			dport = grule.s4.dport;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_dispatch_%s: %s, simple4, rule_id: 0x%lx-%lu, double_dir: %s, action: %s, rule_type: 0x%hx, serv_type: %d, tuple4: %s_%d>%s_%d(%s)",
				get_disp_status_str(disp_status), table_name, grule.rule_id, grule.rule_id, grule.rule_type.ddir_flag?"yes":"no", grule.action==GRULE_ACTION_ADD?"ADD":"DEL", grule.rule_type, grule.srv_type, sip, ntohs(sport), dip, ntohs(dport), errcode?grule_error_str(errcode):"");
			break;
			
		case GRULE_BIG_TYPE_SIMPLE6:
			inet_ntop(AF_INET6, &grule.s6.sip.ip6_c, sip, 128);
			inet_ntop(AF_INET6, &grule.s6.dip.ip6_c, dip, 128);
			sport = grule.s6.sport;
			dport = grule.s6.dport;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_dispatch_%s: %s, simple6, rule_id: 0x%lx-%lu, double_dir: %s, action: %s, rule_type: 0x%hx, serv_type: %d, tuple4: %s_%d>%s_%d(%s)",
				get_disp_status_str(disp_status), table_name, grule.rule_id, grule.rule_id, grule.rule_type.ddir_flag?"yes":"no", grule.action==GRULE_ACTION_ADD?"ADD":"DEL", grule.rule_type, grule.srv_type, sip, ntohs(sport), dip, ntohs(dport), errcode?grule_error_str(errcode):"");
			break;

		case GRULE_BIG_TYPE_MASK4:
			inet_ntop(AF_INET, &grule.m4.sip, sip, 128);
			inet_ntop(AF_INET, &grule.m4.dip, dip, 128);
			inet_ntop(AF_INET, &grule.m4.sip_mask, smask, 128);
			inet_ntop(AF_INET, &grule.m4.dip_mask, dmask, 128);
			sport = grule.m4.sport;
			dport = grule.m4.dport;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_dispatch_%s: %s, mask4, rule_id: 0x%lx-%lu, double_dir: %s, action: %s, rule_type: 0x%hx, serv_type: %d, tuple4: %s_%d>%s_%d, mask4: %s_%d>%s_%d(%s)",
				get_disp_status_str(disp_status), table_name, grule.rule_id, grule.rule_id, grule.rule_type.ddir_flag?"yes":"no", grule.action==GRULE_ACTION_ADD?"ADD":"DEL", grule.rule_type, grule.srv_type, sip, ntohs(sport), dip, ntohs(dport), smask, ntohs(grule.m4.sport_mask), dmask, ntohs(grule.m4.dport_mask), errcode?grule_error_str(errcode):"");
			break;

		case GRULE_BIG_TYPE_MASK6:
			inet_ntop(AF_INET6, &grule.m6.sip.ip6_c, sip, 128);
			inet_ntop(AF_INET6, &grule.m6.dip.ip6_c, dip, 128);
			inet_ntop(AF_INET6, &grule.m6.sip_mask.ip6_c, smask, 128);
			inet_ntop(AF_INET6, &grule.m6.dip_mask.ip6_c, dmask, 128);
			sport = grule.m6.sport;
			dport = grule.m6.dport;
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "pz_dispatch_%s: %s, mask6, rule_id: 0x%lx-%lu, double_dir: %s, action: %s, rule_type: 0x%hx, serv_type: %d, tuple4: %s_%d>%s_%d, mask4: %s_%d>%s_%d(%s)",
				get_disp_status_str(disp_status), table_name, grule.rule_id, grule.rule_id, grule.rule_type.ddir_flag?"yes":"no", grule.action==GRULE_ACTION_ADD?"ADD":"DEL", grule.rule_type, grule.srv_type, sip, ntohs(sport), dip, ntohs(dport), smask, ntohs(grule.m6.sport_mask), dmask, ntohs(grule.m6.dport_mask), errcode?grule_error_str(errcode):"");
			break;
	}
}

int mask4_ip_is_valid(u_int32_t ip, u_int32_t ipmask)
{
	if((ip&0x000000FF)==0 || ipmask<0x000000FF || (ipmask&0x000000FF)<0x000000FF)
	{
		return 0;
	}
	return 1;
}

SSCANF_ERROR_NO_t _wrap_grule_check(grule_t *grule)
{
	grule_type_t rule_type;
	grule_t tmpgrule;

	rule_type = grule->rule_type;
	rule_type.ddir_flag = 0;
	switch(rule_type.grule_type)
	{
		case DIP:
		case DIP_PROTO:
		case DIP_DPORT_PROTO:
		case DIP_SPORT_PROTO:
		case DIP_SPORT_DPORT_PROTO:
		case SIP:
		case SIP_PROTO:
		case SIP_DPORT_PROTO:
		case SIP_SPORT_PROTO:
		case SIP_SPORT_DPORT_PROTO:
		case SIP_DIP:
		case SIP_DIP_PROTO:
		case SIP_DIP_DPORT_PROTO:
		case SIP_DIP_SPORT_PROTO:
		case SIP_DIP_SPORT_DPORT_PROTO:
		case DIP_MDIP:
		case DIP_MDIP_PROTO_MPROTO:
		case DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO:
		case DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO:
		case DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO:
		case SIP_MSIP:
		case SIP_MSIP_PROTO_MPROTO:
		case SIP_MSIP_DPORT_MDPORT_PROTO_MPROTO:
		case SIP_MSIP_SPORT_MSPORT_PROTO_MPROTO:
		case SIP_MSIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO:
		case SIP_MSIP_DIP_MDIP:
		case SIP_MSIP_DIP_MDIP_PROTO_MPROTO:
		case SIP_MSIP_DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO:
		case SIP_MSIP_DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO:
		case SIP_MSIP_DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO:
			break;

		default: return SSCANF_ERROR_TUPLE;
	}

	switch(grule->big_type)
	{
		case GRULE_BIG_TYPE_SIMPLE4:
			if((grule->rule_type.sip_flag && (grule->s4.sip&0x000000FF)==0) || (grule->rule_type.dip_flag && (grule->s4.dip&0x000000FF)==0))
			{
				return SSCANF_ERROR_RULE;
			}
			break;
		case GRULE_BIG_TYPE_SIMPLE6:
			if((grule->rule_type.sip_flag && ipv6_valid(grule->s6.sip.ip6_c)!=IPV6_OK) || (grule->rule_type.dip_flag && ipv6_valid(grule->s6.dip.ip6_c)!=IPV6_OK))
			{
				return SSCANF_ERROR_RULE;
			}
			break;
		case GRULE_BIG_TYPE_MASK4:
			tmpgrule = *grule;
			if(tmpgrule.rule_type.sipmsk_flag)
			{
				tmpgrule.m4.sip &= tmpgrule.m4.sip_mask;  //修正掩码
				if(!mask4_ip_is_valid(tmpgrule.m4.sip, tmpgrule.m4.sip_mask))
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.spmsk_flag) 
			{
				tmpgrule.m4.sport &= tmpgrule.m4.sport_mask;
				if(tmpgrule.m4.sport == 0)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.dipmsk_flag)
			{
				tmpgrule.m4.dip &= tmpgrule.m4.dip_mask;
				if(!mask4_ip_is_valid(tmpgrule.m4.dip, tmpgrule.m4.dip_mask))
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.dpmsk_flag)
			{
				tmpgrule.m4.dport &= tmpgrule.m4.dport_mask;
				if(tmpgrule.m4.dport == 0)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			grule_mask2flexible(&tmpgrule, grule);
			break;
		case GRULE_BIG_TYPE_MASK6:
			tmpgrule = *grule;
			if(tmpgrule.rule_type.spmsk_flag)
			{
				tmpgrule.m6.sport &= tmpgrule.m6.sport_mask;
				if(tmpgrule.m6.sport == 0)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.dpmsk_flag)
			{
				tmpgrule.m6.dport &= tmpgrule.m6.dport_mask;
				if(tmpgrule.m6.dport == 0)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.sipmsk_flag)
			{
				tmpgrule.m6.sip.ip6_l[0] &= tmpgrule.m6.sip_mask.ip6_l[0];
				tmpgrule.m6.sip.ip6_l[1] &= tmpgrule.m6.sip_mask.ip6_l[1];
				if(ipv6m_valid(tmpgrule.m6.sip.ip6_c, tmpgrule.m6.sip_mask.ip6_c) != IPV6_OK)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			if(tmpgrule.rule_type.dipmsk_flag)
			{
				tmpgrule.m6.dip.ip6_l[0] &= tmpgrule.m6.dip_mask.ip6_l[0];
				tmpgrule.m6.dip.ip6_l[1] &= tmpgrule.m6.dip_mask.ip6_l[1];
				if(ipv6m_valid(tmpgrule.m6.dip.ip6_c, tmpgrule.m6.dip_mask.ip6_c) != IPV6_OK)
				{
					return SSCANF_ERROR_RULE;
				}
			}
			grule_mask2flexible(&tmpgrule, grule);
			if(grule->big_type == GRULE_BIG_TYPE_SIMPLE6 && ((grule->rule_type.sip_flag && ipv6_valid(grule->s6.sip.ip6_c)!=IPV6_OK)
				|| (grule->rule_type.dip_flag && ipv6_valid(grule->s6.dip.ip6_c)!=IPV6_OK)))
			{
				return SSCANF_ERROR_RULE;
			}
			break;
		default: break;
	}
	return SSCANF_OK;
}

int do_dispatch_config_to_c3(grule_t &grule, int *errcode)
{
	int ret = DISP_SUCC;
	
	while(grule_app_status(g_grule_handle.grule_handle) == GRULE_APP_STATUS_IDLE)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "grule_app_status GRULE_APP_STATUS_IDLE, retry 2 seconds later.");
		sleep(2);
	}

	pthread_mutex_lock(&g_grule_handle.mutex_lock);
	if(g_grule_handle.first_connect)
	{
		pthread_mutex_unlock(&g_grule_handle.mutex_lock);
		return DISP_RETRY;
	}
	
	if(grule_app_firstconnect_status(g_grule_handle.grule_handle) == GRULE_SERVER_FIRST_CONNECT)
	{
		g_grule_handle.first_connect = 1;
		if(pthread_kill(g_grule_handle.signal_thid, SIGUSR1))
		{
			MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "--------------Attention: pthread_kill failed, restart now.--------------");
			exit(10);
		}
		pthread_mutex_unlock(&g_grule_handle.mutex_lock);
		return DISP_RETRY;
	}
	
	if(grule_send(g_grule_handle.grule_handle, &grule, 1, 0) != 1)
	{
		*errcode = grule_errno(g_grule_handle.grule_handle);
		pthread_mutex_unlock(&g_grule_handle.mutex_lock);
		return DISP_FAIL_C3;
	}
	//int num = grule_cache_size(g_grule_handle.grule_handle);
	
	pthread_mutex_unlock(&g_grule_handle.mutex_lock);
	
	return ret;
}

int wrap_dispatch_config_to_c3(const char *table_name, int service_id, int table_id, grule_t &grule)
{
	int ret, errcode=0;

	ret = do_dispatch_config_to_c3(grule, &errcode);
	if(ret != DISP_SUCC)
	{
		pz_trans_statistic_count(service_id, table_id, 1, STAT_FIELD_DISP_FAIL);
	}
	else
	{
		pz_trans_statistic_count(service_id, table_id, 1, STAT_FIELD_DISP_SUCC);
	}

	write_grule_log(table_name, grule, ret, errcode);	
	return ret;
}

STAT_SERVICE_TYPE_t update_grule_status(int32_t &status, int disp_ret, int action)
{
	if(disp_ret != DISP_SUCC)
	{
		if(disp_ret == DISP_RETRY && action==GRULE_ACTION_DEL)
		{
			status = 0; //链接重建时，是删除的配置，则清空下发状态
		}
		return STAT_SERVICE_NONE;
	}
	
	if((action==GRULE_ACTION_ADD) && status==0)
	{
		status = 1;
		return STAT_SERVICE_ADD;
	}
	else if((action==GRULE_ACTION_DEL) && status!=0)
	{
		status = 0;
		return STAT_SERVICE_DEL;
	}
	return STAT_SERVICE_NONE;
}

//会修改下发的状态，调用者注意更新该状态
int dispatch_config_to_c3(const char *table_name, int service_id, int table_id, one_config_hnode_t &config_node)
{
	int ret;
	STAT_SERVICE_TYPE_t type;

	//全新的新增配置才检查上限，config_node.disp_status为0表示全新ADD配置或者DEL已经删除成功的配置
	//避免动态大量配置DEL的情况
	if(g_pgvalve_info.service_limit_sw && config_node.disp_status==0 && (config_node.grule.action==GRULE_ACTION_DEL || service_grule_reach_limit(config_node.grule.srv_type)))
	{
		write_grule_log(table_name, config_node.grule, DISP_LIMIT, 0);	
		pz_trans_statistic_count(service_id, table_id, 1, STAT_FIELD_DISP_LIMIT);
		return DISP_LIMIT;
	}
	
	ret = wrap_dispatch_config_to_c3(table_name, service_id, table_id, config_node.grule);
	type = update_grule_status(config_node.disp_status, ret, config_node.grule.action);
	if(type != STAT_SERVICE_NONE)
	{
		service_grule_statistic_count(config_node.grule.srv_type, config_node.grule.rule_type.ddir_flag?2:1, type); //双向规则占用两个空间
	}
	return ret;
}

void clear_c3_first_status(void)
{
	pthread_mutex_lock(&g_grule_handle.mutex_lock);
	g_grule_handle.first_connect = 0;
	pthread_mutex_unlock(&g_grule_handle.mutex_lock);
}

bool global_init_grule_handle(const char *auth_data_str, int len, const char *ccc_list, pthread_t signal_thid)
{
	char authdata[16];
	pthread_mutexattr_t attr; 
	int attr_type;
	
	if(C3CLIENTLEN != authdata_hex2mem(auth_data_str, len, authdata))
	{
		assert(0);
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "C3_AUTH_DATA format error.");
		return false;
	}
	g_grule_handle.first_connect = 0;
	g_grule_handle.grule_handle = grule_open();
	if(g_grule_handle.grule_handle == NULL)
	{
		return false;
	}
	if(grule_opt_set(g_grule_handle.grule_handle, GRULE_SOL_PROTO, GRULE_TYPE_AUTH, authdata, C3CLIENTLEN))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "grule_opt_set GRULE_TYPE_AUTH error.");
		return false;
	}
	if(grule_connect(g_grule_handle.grule_handle, ccc_list))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "grule_connect %s error: %s.", ccc_list, grule_error_str(grule_errno(g_grule_handle.grule_handle)));
		return false;
	}
	
	while(grule_app_status(g_grule_handle.grule_handle) == GRULE_APP_STATUS_IDLE)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "grule_app_status GRULE_APP_STATUS_IDLE, retry 2 seconds later.");
		sleep(2);
	}
	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "grule real connect %s success.", ccc_list);
	grule_app_firstconnect_status(g_grule_handle.grule_handle); //首次启动时忽略第一次连接状态

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_gettype(&attr, &attr_type);
	attr_type |= PTHREAD_MUTEX_RECURSIVE_NP; /* can be recursive call */
	pthread_mutexattr_settype(&attr, attr_type);
	if(pthread_mutex_init(&g_grule_handle.mutex_lock, &attr))
	{
		return false;
	}
	g_grule_handle.signal_thid = signal_thid;
	return true;
}

