#ifndef __PANGU_VALVE_CONSUL_H__
#define __PANGU_VALVE_CONSUL_H__

#include <sys/types.h>

struct easy_string
{
	char* buff;
	size_t len;
	size_t size;
};

bool consul_try_get_lock(const char *session_id, const char *key, const char *value, int timeout_s);
bool consul_renew_session(const char *session_id, int timeout_s);
bool consul_create_session(int lock_delay_s, int ttl_s, char *session_id, int size, void *runlog);

#endif

