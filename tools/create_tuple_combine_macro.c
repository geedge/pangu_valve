#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include "grule_for_view.h"

char macro[30][1024] = {
"DIP",
"DIP_PROTO",
"DIP_DPORT_PROTO",
"DIP_SPORT_PROTO",
"DIP_SPORT_DPORT_PROTO",
"SIP",
"SIP_PROTO",
"SIP_DPORT_PROTO",
"SIP_SPORT_PROTO",
"SIP_SPORT_DPORT_PROTO",
"SIP_DIP",
"SIP_DIP_PROTO",
"SIP_DIP_DPORT_PROTO",
"SIP_DIP_SPORT_PROTO",
"SIP_DIP_SPORT_DPORT_PROTO",
"DIP_MDIP",
"DIP_MDIP_PROTO_MPROTO",
"DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO",
"DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO",
"DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO",
"SIP_MSIP",
"SIP_MSIP_PROTO_MPROTO",
"SIP_MSIP_DPORT_MDPORT_PROTO_MPROTO",
"SIP_MSIP_SPORT_MSPORT_PROTO_MPROTO",
"SIP_MSIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO",
"SIP_MSIP_DIP_MDIP",
"SIP_MSIP_DIP_MDIP_PROTO_MPROTO",
"SIP_MSIP_DIP_MDIP_DPORT_MDPORT_PROTO_MPROTO",
"SIP_MSIP_DIP_MDIP_SPORT_MSPORT_PROTO_MPROTO",
"SIP_MSIP_DIP_MDIP_SPORT_MSPORT_DPORT_MDPORT_PROTO_MPROTO",
};

int main(int argc, char **argv)
{
	char *ptmp, *save_ptr;
	grule_t grule;
	char tmpstr[1024];

	for(int i =0; i<30; i++)
	{
		save_ptr=NULL;
		grule.rule_type.grule_type = 0;
		sprintf(tmpstr, "%s", macro[i]);
		for(ptmp = strtok_r(tmpstr, "_", &save_ptr); ptmp != NULL; ptmp = strtok_r(NULL, "_", &save_ptr))
		{
			if(!strcmp(ptmp, "SIP"))
			{
				grule.rule_type.sip_flag = 1;
			}
			else if(!strcmp(ptmp, "MSIP"))
			{
				grule.rule_type.sipmsk_flag= 1;
			}
			else if(!strcmp(ptmp, "DIP"))
			{
				grule.rule_type.dip_flag= 1;
			}
			else if(!strcmp(ptmp, "MDIP"))
			{
				grule.rule_type.dipmsk_flag= 1;
			}
			else if(!strcmp(ptmp, "SPORT"))
			{
				grule.rule_type.sport_flag= 1;
			}
			else if(!strcmp(ptmp, "MSPORT"))
			{
				grule.rule_type.spmsk_flag= 1;
			}
			else if(!strcmp(ptmp, "DPORT"))
			{
				grule.rule_type.dport_flag= 1;
			}
			else if(!strcmp(ptmp, "MDPORT"))
			{
				grule.rule_type.dpmsk_flag= 1;
			}
			else if(!strcmp(ptmp, "PROTO"))
			{
				grule.rule_type.proto_flag= 1;
			}
			else if(!strcmp(ptmp, "MPROTO"))
			{
				grule.rule_type.pmsk_flag= 1;
			}
			else 
			{
				assert(0);
			}
		}
		printf("#define %s 0x%x\n", macro[i], grule.rule_type.grule_type);
	}

	printf("\n");
	for(int i =0; i<30; i++)
	{
		printf("case %s:\n", macro[i]);
	}

	return 0;
}

