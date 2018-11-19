#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>

#include <MESA/MESA_handle_logger.h>

#include "cJSON.h"
#include "pg_valve_consul.h"
#include "pg_valve_tools.h"

CURLSH *curl_shared_handle;

static size_t write_response_to_string_cb(void *ptr, size_t size, size_t count, void *buff)
{
	struct easy_string* estr=(struct easy_string*)buff;
	if(estr->size-estr->len<size*count+1)
	{
		estr->size+=size*count*2+1;
		estr->buff=(char*)realloc(estr->buff,estr->size);
	}
	memcpy(estr->buff+estr->len,ptr,size*count);
	estr->len+=size*count;
	estr->buff[estr->len]='\0';
	return size*count;
}

static size_t read_body_to_send_cb(void *ptr, size_t size, size_t count, void *buff)
{
	size_t len;
	struct easy_string *request = (struct easy_string *)buff;

	if(size==0 || count==0 || request->len>=request->size)
	{
		return 0;
	}

	len = request->size - request->len; //剩余待上传的长度
	if(len > size * count)
	{
		len = size * count;
	}

	memcpy(ptr, request->buff + request->len, len);
	request->len += len;
	return len;
}

bool http_put_request(const char* url, const char *body, int timeout_s, struct easy_string* response)
{
	CURL *curl;
	CURLcode res1, res2;
	long res_code;
	struct easy_string request;
	
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5); 
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL,1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS,3);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_to_string_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(curl, CURLOPT_SHARE, curl_shared_handle);
	curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 600L); //10分钟才进行一次DNS解析

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	if(body != NULL)
	{
		request.size = strlen(body); //总大小
		request.len = 0;			 //已上传长度
		request.buff = (char *)body; //内容
		curl_easy_setopt(curl, CURLOPT_INFILESIZE, request.size);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_body_to_send_cb);
		curl_easy_setopt(curl, CURLOPT_READDATA, &request);
	}

	res1 = curl_easy_perform(curl);
	res2 = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);
	curl_easy_cleanup(curl);
	if(res1==CURLE_OK && res2==CURLE_OK && res_code==200)
	{
		return true;
	}
	return false;
}

bool consul_renew_session(const char *session_id, int timeout_s)
{
	char reg_url[156];
	struct easy_string response;
	cJSON *session, *json;

	snprintf(reg_url, 256, "http://localhost:8500/v1/session/renew/%s", session_id);
	memset(&response,0,sizeof(response));
	if(!http_put_request(reg_url, NULL, timeout_s, &response))
	{
		free(response.buff);
		return false;
	}
	
	if(NULL == (session=cJSON_Parse(response.buff)))
	{
		free(response.buff);
		return false;
	}
	free(response.buff);
	if(NULL == (json=cJSON_GetObjectItem(session->child, "ID")))
	{
		cJSON_Delete(session);
		return false;
	}
	if(strcmp(session_id, json->valuestring))
	{
		cJSON_Delete(session);
		return false;
	}
	
	cJSON_Delete(session);
	return true;
}

bool consul_create_session(int lock_delay_s, int ttl_s, char *session_id, int size, void *runlog)
{
	cJSON *session, *json;
	char tmpbuf[128], *body;
	const char* reg_url="http://localhost:8500/v1/session/create";
	struct easy_string response;

	curl_global_init(CURL_GLOBAL_NOTHING);
	curl_shared_handle = curl_share_init();
	curl_share_setopt(curl_shared_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

	session = cJSON_CreateObject();
	sprintf(tmpbuf, "%us", lock_delay_s);
	cJSON_AddStringToObject(session, "LockDelay", tmpbuf);
	sprintf(tmpbuf, "%us", ttl_s);
	cJSON_AddStringToObject(session, "TTL", tmpbuf);
	cJSON_AddStringToObject(session, "Name", "pg_valve_session");
	cJSON_AddStringToObject(session, "Behavior", "release");

	body = cJSON_Print(session);
	cJSON_Delete(session);
	memset(&response,0,sizeof(response));
	while(!http_put_request(reg_url, body, 5, &response))
	{
		free(response.buff);
		memset(&response,0,sizeof(response)); //需要清空，否则第一次失败后，第二次的时候有野指针
		MESA_HANDLE_RUNTIME_LOGV2(runlog, RLOG_LV_FATAL, "CONSUL", "consul_create_session failed, retry after 10 seconds.");
		sleep(10);
	}
	free(body);

	if(NULL == (session=cJSON_Parse(response.buff)))
	{
		free(response.buff);
		return false;
	}
	free(response.buff);
	if(NULL == (json=cJSON_GetObjectItem(session, "ID")))
	{
		cJSON_Delete(session);
		return false;
	}
	
	snprintf(session_id, size, "%s", json->valuestring);
	cJSON_Delete(session);
	return true;
}

bool consul_try_get_lock(const char *session_id, const char *key, const char *value, int timeout_s)
{
	char reg_url[156];
	struct easy_string response;

	snprintf(reg_url, 256, "http://localhost:8500/v1/kv/%s?acquire=%s", key, session_id);
	memset(&response,0,sizeof(response));
	if(!http_put_request(reg_url, value, timeout_s, &response))
	{
		free(response.buff);
		return false;
	}

	if(!strcasecmp(response.buff, "true"))
	{
		free(response.buff);
		return true;
	}
	free(response.buff);
	return false;
}

