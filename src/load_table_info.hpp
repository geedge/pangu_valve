#ifndef __LOAD_TABLE_INFO_COMMON_H__
#define __LOAD_TABLE_INFO_COMMON_H__

#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h>

using namespace std;

template <class table_info_type>
class LoadTableInfo{
private:
	char table_path[256];
	char *get_filecont_line(char *line_content, int32_t cont_size, FILE *fp);
	int32_t (*fill_cb)(char *line_content, table_info_type *table, int32_t table_index);
	
public:
	LoadTableInfo(const char *table_confile, int32_t (*fill_table_info_cb)(char *line_content, table_info_type *table, int32_t table_index))
	{
		snprintf(table_path, 256, "%s", table_confile);
		fill_cb = fill_table_info_cb;
	}
	virtual ~LoadTableInfo()
	{
	}
	
	int load_table_info(table_info_type **table_lists, int *num);
};

template <class table_info_type>
char *LoadTableInfo<table_info_type>::get_filecont_line(char *line_content, int32_t cont_size, FILE *fp)
{
	int line_len;
	char *content=NULL;
	
	while(NULL!=fgets(line_content, cont_size, fp) && !feof(fp))
	{
		line_len = strlen(line_content);
		if((line_len+1 == cont_size) || (line_content[line_len-1] != '\n'))
		{
			printf("This line data is too long!\n");
			assert(0);
			return NULL;
		}
		content = line_content;
		
		while(line_len>0 && (*content==' ' || *content=='\t'))
		{
			content++;
			line_len--;
		}
		if(line_len==0 || *content=='#' || *content=='\r' || *content=='\n')
		{
			continue;
		}
		
		return content;	
	}

	return NULL;
}

template <class table_info_type>
int LoadTableInfo<table_info_type>::load_table_info(table_info_type **table_lists, int *num)
{
#define MALLOC_TABLE_ARRAY_NUM 8
	table_info_type *maat_list;
	char *line_content, *cur_content;
	FILE *fp_user;
	int maat_num=0, maat_max_num=MALLOC_TABLE_ARRAY_NUM;

	fp_user = fopen(table_path, "r");
	if(fp_user==NULL)
	{
		assert(0);
		return -1;
	}
	line_content = (char *)calloc(1, 4096);
	maat_list = (table_info_type *)calloc(1, maat_max_num*sizeof(table_info_type));

	while((cur_content=get_filecont_line(line_content, 4096, fp_user))!=NULL)
	{
		if(maat_num >= maat_max_num)
		{
			maat_max_num += MALLOC_TABLE_ARRAY_NUM;
			maat_list = (table_info_type *)realloc(maat_list, maat_max_num*sizeof(table_info_type));
			memset(maat_list+maat_num, 0, MALLOC_TABLE_ARRAY_NUM*sizeof(table_info_type));
		}

		if((*fill_cb)(cur_content, &maat_list[maat_num], maat_num))
		{
			fclose(fp_user);
			free(line_content);
			return -1;
		}
		maat_num += 1;
	}
	*num = maat_num;
	*table_lists = maat_list;
	
	fclose(fp_user);
	free(line_content);
	return 0;
}

#endif

