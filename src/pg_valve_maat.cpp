#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>

#include "pg_valve_maat.h"

extern pgvavle_global_info_t g_pgvalve_info;

//无开关运行中全量事件

//有开关运行中域配置全量事件

int maat_start_config_table(configure_table_t *table, MaatService *maat_service)
{
	int ret;
	maat_callback_data_t *maat_data;
	Maat_feather_t feather = maat_service->get_maat_feather();
	
	table->table_id_maat = Maat_table_register(feather, table->table_name);
	if(table->table_id_maat < 0)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "Maat_table_register table %s failed.", table->table_name);
		assert(0);
		return -1;
	}
	
	maat_data = (maat_callback_data_t *)malloc(sizeof(maat_callback_data_t));
	maat_data->table = table;
	maat_data->update_type = 0;
	maat_data->maat_service = maat_service;
	ret = Maat_table_callback_register(feather, (short)table->table_id_maat, table->maat_start_cb, table->maat_update_cb, table->maat_finish_cb, maat_data);
	if(ret != 1)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "Maat_table_callback_register table %s failed.", table->table_name);
		assert(0);
		return -2;
	}
	return 0;
}

long long MaatService::read_last_version(void)
{
	if(access(table_relate->version_file, R_OK))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_INFO, MODULE_NAME, "read_last_version %s failed: %s, using default version 0.", table_relate->version_file, strerror(errno));
		return 0;
	}
	FILE *fp = fopen(table_relate->version_file, "r");
	if(fp==NULL)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "read_last_version open %s failed: %s.", table_relate->version_file, strerror(errno));
		assert(0);
		return -1;
	}
	if(fscanf(fp, "%llu\n", &version) != 1)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "read_last_version fscanf %s failed: %s.", table_relate->version_file, strerror(errno));
		fclose(fp);
		assert(0);
		return -1;
	}
	else
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "read_last_version %s success, version: %u.", table_relate->version_file, version);
	}
	fclose(fp);
	return version;
}

int MaatService::store_latest_version(long long ver)
{
	char verbuf[48];

	version = ver;
	FILE *fp = fopen(table_relate->version_file, "w");
	if(fp==NULL)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "Open version file %s failed: %s.", table_relate->version_file, strerror(errno));
		return -1;
	}

	sprintf(verbuf, "%llu\n", version);
	if(fwrite(verbuf, 1, strlen(verbuf), fp) != strlen(verbuf))
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "fwrite version file %s failed: %s, version: %u.", table_relate->version_file, strerror(errno), version);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime,RLOG_LV_FATAL, MODULE_NAME, "store_latest_version %s success, version: %u.", table_relate->version_file, version);
	return 0;
}

int MaatService::maat_feather_start(void)
{	
	char tmp_buffer[1024];
	int ret;

	feather = Maat_feather(1, g_pgvalve_info.maat_table_info, g_pgvalve_info.log_runtime);
	if(feather == NULL)
	{
		return -1;
	}

	snprintf(tmp_buffer, 1024, "%s/maat_stat_%s.log", g_pgvalve_info.root_log_dir, table_relate->instance_name);
	ret = Maat_set_feather_opt(feather, MAAT_OPT_STAT_FILE_PATH, tmp_buffer, strlen(tmp_buffer)+1);
	ret |= Maat_set_feather_opt(feather, MAAT_OPT_STAT_ON, NULL, 0);
	ret |= Maat_set_feather_opt(feather, MAAT_OPT_PERF_ON, NULL, 0);

	ret |= Maat_set_feather_opt(feather, MAAT_OPT_INSTANCE_NAME, table_relate->instance_name, strlen(table_relate->instance_name)+1);
	if(strlen(g_pgvalve_info.effective_range)>0)
	{
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_ACCEPT_TAGS, g_pgvalve_info.effective_range, strlen(g_pgvalve_info.effective_range)+1);
	}
	if(g_pgvalve_info.maat_source == MAAT_CONFIG_FILE)
	{
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_FULL_CFG_DIR, table_relate->full_dir, strlen(table_relate->full_dir)+1);
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_INC_CFG_DIR, table_relate->incr_dir, strlen(table_relate->incr_dir)+1);
	}
	else
	{
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_REDIS_IP, table_relate->redisip, strlen(table_relate->redisip)+1);
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_REDIS_PORT, &table_relate->redisport, sizeof(table_relate->redisport));
		ret |= Maat_set_feather_opt(feather, MAAT_OPT_REDIS_INDEX, &table_relate->redis_index, sizeof(table_relate->redis_index));
	}
	
	if(ret || Maat_initiate_feather(feather) < 0)
	{
		MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "Maat_initiate_feather instance %s failed.", table_relate->instance_name);
		return -2;
	}

	MESA_HANDLE_RUNTIME_LOGV2(g_pgvalve_info.log_runtime, RLOG_LV_FATAL, MODULE_NAME, "maat_feather_start instance %s success.", table_relate->instance_name);
	return 0;
}

