#ifndef __CHECK_IP_LEGAL_H__
#define __CHECK_IP_LEGAL_H__

#if defined __GNUC__ || defined __llvm__
#define likely(x) __builtin_expect ((x), 1)
#define unlikely(x) __builtin_expect ((x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif


#ifndef IPV6_PREFIX_MIN
	#define IPV6_PREFIX_MIN 48
#endif

#define IPV6_OK  			0
#define IPV6_ILLEGAL    	2
#define IPV6_PREFIX_LEN_ERR 3
#define IPV6_PREFIX_NONPRE 	4	//前缀掩码不对
#define IPV6_PREFIX_ERR    	5	//同4
#define IPV6_IP_PREFIX_ERR 	6	//掩过后不等于自己

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int ipv6_valid(uint8_t * ipv6);
extern int ipv6m_valid(uint8_t * ipv6, uint8_t * mask);

#endif

