#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>

#include "grule_for_view.h"

int grule_app_status(grule_hdl_t hdl)
{
	return GRULE_APP_STATUS_CONNECTED;
}

grule_hdl_t grule_open()
{
	return malloc(1);
}

int grule_mask2flexible(const grule_t * src, grule_t * dst)
{
	return 0;
}

int grule_opt_set(grule_hdl_t hdl, int level, int type, const void * opt, size_t opt_size)
{
	return 0;
}

int grule_connect(grule_hdl_t hdl, const char * addr)
{
	return 0;
}

int grule_send(grule_hdl_t hdl, grule_t *rules, size_t rule_num, int flags)
{
	return rule_num;
}

int grule_cache_size(grule_hdl_t hdl)
{
	return 0;
}

const char * grule_error_str(int err_no)
{
	return "";
}

int grule_errno(grule_hdl_t hdl)
{
	return 0;
}


#define FILE_NAME "./firstconnect.txt"

#define GRULE_SERVER_FIRST_CONNECT 1
#define GRULE_SERVER_NONFIRST_CONNECT 0
int grule_app_firstconnect_status(grule_hdl_t client)
{
	int first;
	
	if(access(FILE_NAME, R_OK))
	{
		return GRULE_SERVER_NONFIRST_CONNECT;
	}
	
	FILE *fp = fopen(FILE_NAME, "r");
	if(fp==NULL)
	{
		return GRULE_SERVER_NONFIRST_CONNECT;
	}
	if(fscanf(fp, "%u\n", &first) != 1)
	{
		fclose(fp);
		return GRULE_SERVER_NONFIRST_CONNECT;
	}
	fclose(fp);

	fp = fopen(FILE_NAME, "w");
	if(fp==NULL)
	{
		return GRULE_SERVER_NONFIRST_CONNECT;
	}	
	fwrite("0\n", 1, 2, fp);
	fclose(fp);
	
	return first?GRULE_SERVER_FIRST_CONNECT:GRULE_SERVER_NONFIRST_CONNECT;
}

char * parse_rule_str_full(grule_t * rule, char * buf, size_t *size)
{
	return buf;
}


