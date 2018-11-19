#ifndef __PANGU_VALVE_H_MAAT_H__
#define __PANGU_VALVE_H_MAAT_H__

#include <MESA/MESA_htable.h>
#include <MESA/field_stat2.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/Maat_rule.h>

#include "pg_valve_tools.h"
#include "pg_valve_deal.h"
#include "pg_valve_main.h"

#define MAAT_CONFIG_FILE	1
#define MAAT_CONFIG_REDIS	2

class MaatService
{
private:
	struct maat_table_relation *table_relate;
	Maat_feather_t feather;
	long long version;

public:
	MaatService(struct maat_table_relation *table_relation)
	{
		table_relate = table_relation;
	}
	virtual ~MaatService(void)
	{
		Maat_burn_feather(feather);
	}

	Maat_feather_t get_maat_feather(void) {return feather;}

	const char *get_instance_name(void) {return table_relate->instance_name;}
	int store_latest_version(long long ver);
	long long read_last_version(void);
	int maat_feather_start(void);
};

typedef struct __maat_callback_data
{
	configure_table_t *table;
	MaatService *maat_service;;
	int update_type;
}maat_callback_data_t;

int maat_start_config_table(configure_table_t *table, MaatService *maat_service);

#endif

