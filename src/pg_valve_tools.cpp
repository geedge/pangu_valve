#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int mkdir_according_path(const char * path)
{
	char buffer[256];
	const char *ps=path, *pc;

	if(*ps == '/')
		ps += 1;
	
	while((pc = strchr(ps, '/')) != NULL)
	{
		while(*(pc+1) == '/')
			pc++;
			
		memcpy(buffer, path, pc - path);
		buffer[pc-path] = '\0';
		
		if(access(buffer, F_OK))
		{
			if(mkdir(buffer, 0777))
			{
				return -1;
			}
		}

		ps = pc + 1;
	}
	if(access(path, F_OK))
	{
		if(mkdir(path, 0777))
		{
			return -1;
		}
	}
	return 0;
}

	
