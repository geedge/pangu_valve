#ifndef __PANGU_VALVE_TOOLS_H__
#define __PANGU_VALVE_TOOLS_H__

#include <MESA/MESA_handle_logger.h>

#define MESA_HANDLE_RUNTIME_LOGV2(handle, lv, mod, fmt, args...)   \
    MESA_handle_runtime_log((handle), (lv), (mod), "%s:%d, " fmt, __FILE__, __LINE__, ##args)

int mkdir_according_path(const char * path);


#endif

