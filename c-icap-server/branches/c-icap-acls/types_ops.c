#include "common.h"
#include "c-icap.h"
#include "net_io.h"
#include "mem.h"
#include "lookup_table.h"
#include "debug.h"

/*string operators */
void *stringdup(const char *str, ci_mem_allocator_t *allocator)
{
    char *new_s = allocator->alloc(allocator,strlen(str)+1);
    if(new_s)
      strcpy(new_s, str);
    return new_s;
}

int stringcmp(void *key1,void *key2)
{
    return strcmp((char *)key1,(char *)key2);
}

int stringequal(void *key1,void *key2)
{
    return strcmp((char *)key1,(char *)key2)==0;
}

size_t stringlen(void *key)
{
    return strlen((const char *)key)+1;
}

void stringfree(void *key, ci_mem_allocator_t *allocator)
{
    allocator->free(allocator, key);
}

ci_type_ops_t  ci_str_ops = {
    stringdup,
    stringfree,
    stringcmp,
    stringlen,
    stringequal,
};


/*int32 operators*/

void *int32_dup(const char *str, ci_mem_allocator_t *allocator)
{
    int i;
    i = strtol(str, NULL, 10);
    return (void *)i;
}

int int32_cmp(void *key1,void *key2)
{
    return (key1-key2);
}

int int32_equal(void *key1,void *key2)
{
    return key1 == key2;
}

size_t int32_len(void *key)
{
    return (size_t)4;
}

void int32_free(void *key, ci_mem_allocator_t *allocator)
{
    /*nothing*/
}

ci_type_ops_t  ci_int32_ops = {
    int32_dup,
    int32_free,
    int32_cmp,
    int32_len,
    int32_equal
};


/*IP operators*/
#ifdef HAVE_IPV6

void ci_list_ipv4_to_ipv6();

#define ci_ipv4_inaddr_is_zero(addr) ((addr).ipv4_addr.s_addr==0)
#define ci_ipv4_inaddr_are_equal(addr1,addr2) ((addr1).ipv4_addr.s_addr == (addr2).ipv4_addr.s_addr)
#define ci_ipv4_inaddr_zero(addr) ((addr).ipv4_addr.s_addr=0)

#define ci_ipv6_inaddr_is_zero(addr) ( ci_in6_addr_u32(addr)[0]==0 && \
				       ci_in6_addr_u32(addr)[1]==0 &&  \
				       ci_in6_addr_u32(addr)[2]==0 &&  \
				       ci_in6_addr_u32(addr)[3]==0)

#define ci_ipv6_inaddr_are_equal(addr1,addr2) ( ci_in6_addr_u32(addr1)[0]==ci_in6_addr_u32(addr2)[0] && \
						ci_in6_addr_u32(addr1)[1]==ci_in6_addr_u32(addr2)[1] && \
						ci_in6_addr_u32(addr1)[2]==ci_in6_addr_u32(addr2)[2] && \
						ci_in6_addr_u32(addr1)[3]==ci_in6_addr_u32(addr2)[3])


#define ci_ipv6_inaddr_is_v4mapped(addr) (ci_in6_addr_u32(addr)[0]==0 &&\
					  ci_in6_addr_u32(addr)[1]==0 && \
					  ci_in6_addr_u32(addr)[2]== htonl(0xFFFF))


#define ci_ipv4_inaddr_check_net(addr1,addr2,mask) (((addr1).ipv4_addr.s_addr & (mask).ipv4_addr.s_addr)==((addr2).ipv4_addr.s_addr & (mask).ipv4_addr.s_addr))
#define ci_ipv6_inaddr_check_net(addr1,addr2,mask) ((ci_in6_addr_u32(addr1)[0] & ci_in6_addr_u32(mask)[0])==(ci_in6_addr_u32(addr2)[0] & ci_in6_addr_u32(mask)[0]) &&\
						    (ci_in6_addr_u32(addr1)[1] & ci_in6_addr_u32(mask)[1])==(ci_in6_addr_u32(addr2)[1] & ci_in6_addr_u32(mask)[1]) && \
						    (ci_in6_addr_u32(addr1)[2] & ci_in6_addr_u32(mask)[2])==(ci_in6_addr_u32(addr2)[2] & ci_in6_addr_u32(mask)[2]) && \
						    (ci_in6_addr_u32(addr1)[3] & ci_in6_addr_u32(mask)[3])==(ci_in6_addr_u32(addr2)[3] & ci_in6_addr_u32(mask)[3]))
#define ci_ipv4_in_ipv6_check_net(addr1, addr2, mask) (ci_in6_addr_u32(addr2)[0]==0 && \
						       ci_in6_addr_u32(addr2)[1]==0 && \
						       ci_in6_addr_u32(addr2)[2]== htonl(0xFFFF) && \
						       ((addr1).ipv4_addr.s_addr & (mask).ipv4_addr.s_addr)==(ci_in6_addr_u32(addr2)[3] & (mask).ipv4_addr.s_addr))
#define ci_ipv6_in_ipv4_check_net(addr1, addr2, mask) (ci_in6_addr_u32(addr1)[0]==0 && \
						       ci_in6_addr_u32(addr1)[1]==0 && \
						       ci_in6_addr_u32(addr1)[2]== htonl(0xFFFF) && \
						       (ci_in6_addr_u32(addr1)[3] & (mask).ipv4_addr.s_addr) == ((addr2).ipv4_addr.s_addr & (mask).ipv4_addr.s_addr))


/*We can do this because ipv4_addr in practice exists in s6_addr[0]*/
#define ci_inaddr_ipv4_to_ipv6(addr)( ci_in6_addr_u32(addr)[3]=(addr).ipv4_addr.s_addr,\
				      ci_in6_addr_u32(addr)[0]=0,	\
				      ci_in6_addr_u32(addr)[1]=0,	\
				      ci_in6_addr_u32(addr)[2]= htonl(0xFFFF))
#define ci_netmask_ipv4_to_ipv6(addr)(ci_in6_addr_u32(addr)[3]=(addr).ipv4_addr.s_addr,	\
				      ci_in6_addr_u32(addr)[0]= htonl(0xFFFFFFFF), \
				      ci_in6_addr_u32(addr)[1]= htonl(0xFFFFFFFF), \
				      ci_in6_addr_u32(addr)[2]= htonl(0xFFFFFFFF))
#else                           /*if no HAVE_IPV6 */

#define ci_ipv4_inaddr_is_zero(addr) ((addr).s_addr==0)
#define ci_ipv4_inaddr_are_equal(addr1,addr2) ((addr1).s_addr == (addr2).s_addr)
#define ci_ipv4_inaddr_check_net(addr1,addr2,mask) (((addr1).s_addr & (mask).s_addr)==((addr2).s_addr & (mask).s_addr))

#define ci_ipv4_inaddr_hostnetmask(addr)((addr).s_addr=htonl(0xFFFFFFFF))
#define ci_ipv4_inaddr_zero(addr) ((addr).s_addr=0)

#endif                          /*ifdef HAVE_IPV6 */




void *ip_dup(const char *value,  ci_mem_allocator_t *allocator){
    int socket_family, len;
    ci_ip_t *ip;
    char str_addr[CI_IPLEN+1], str_netmask[CI_IPLEN+1];
    char *pstr;
    ci_in_addr_t address, netmask;

    ci_inaddr_zero(address);
    ci_inaddr_zero(netmask);

#ifdef HAVE_IPV6
    if(strchr(value,':'))
	socket_family = AF_INET6;
    else
#endif
	socket_family = AF_INET;

    if ((pstr=strchr(value,'/'))){
	len=(pstr-value);
	if (len >= CI_IPLEN){
	    ci_debug_printf(1,"Invalid ip address (len>%d): %s\n", CI_IPLEN, value);
	    return NULL;
	}
	strncpy(str_addr,value,len);
	str_addr[len] = '\0';

	if(!ci_inet_aton(socket_family, str_addr, &address)){
	    ci_debug_printf(1,"Invalid ip address in network %s definition\n", value);
	    return NULL;
	}
	
	strncpy(str_netmask, pstr+1, CI_IPLEN);
	str_netmask[CI_IPLEN] = '\0';

	if(!ci_inet_aton(socket_family, str_netmask, &netmask)){
	    ci_debug_printf(1,"Invalid netmask in network %s definition\n", value);
	    return NULL;
	}
    }
    else { /*No netmask defined is a host ip*/
	if(!ci_inet_aton(socket_family, value, &address)){
	    ci_debug_printf(1,"Invalid ip address: %s\n", value);
	    return NULL;
	}
#ifdef HAVE_IPV6
	if(socket_family==AF_INET)
	    ci_ipv4_inaddr_hostnetmask(netmask);
	else
	    ci_ipv6_inaddr_hostnetmask(netmask);
#else
	ci_ipv4_inaddr_hostnetmask(netmask);
#endif
    }
    
    ip= allocator->alloc(allocator, sizeof(ci_ip_t));
    ip->family = socket_family;
    
    ci_inaddr_copy(ip->address, address);
    ci_inaddr_copy(ip->netmask, netmask); 
    
    return ip;
}

void ip_free(void *data, ci_mem_allocator_t *allocator) {
    allocator->free(allocator, data);
}

size_t ip_len(void *key)
{
    return sizeof(ci_ip_t);
}

int ip_cmp(void *ref_key, void *key_check) {
    /*Not implemented*/
    return 0;
}

int ip_equal(void *ref_key, void *key_check) {
    const ci_ip_t *ip_ref = (ci_ip_t *)ref_key;
    ci_ip_t *ip_check = (ci_ip_t *)key_check;
    char buf[128],buf1[128],buf2[128];
    ci_debug_printf(9,"going to check addresses  ip address: %s %s/%s\n",
		    ci_inet_ntoa(ip_check->family,&ip_check->address, buf, 128),
		    ci_inet_ntoa(ip_ref->family,&ip_ref->address, buf1, 128),
		    ci_inet_ntoa(ip_ref->family,&ip_ref->netmask, buf2, 128)
	);
#ifdef HAVE_IPV6
    if(ip_check->family == AF_INET){
	if(ip_ref->family == AF_INET)
	    return ci_ipv4_inaddr_check_net(ip_ref->address, ip_check->address, ip_ref->netmask);
	//else add->family == AF_INET6
	return ci_ipv6_in_ipv4_check_net(ip_ref->address, ip_check->address, ip_ref->netmask);
    }
    //else assuming  ip_check->family == AF_INET6 
    if(ip_ref->family == AF_INET6)
	return ci_ipv6_inaddr_check_net(ip_ref->address, ip_check->address, ip_ref->netmask);
    //else ip->family == AF_INET
    return ci_ipv4_in_ipv6_check_net(ip_ref->address, ip_check->address, ip_ref->netmask);
#else
    return ci_ipv4_inaddr_check_net(ip_ref->address, ip_check->address, ip_ref->netmask);
#endif

}

int ip_sockaddr_cmp(void *ref_key, void *key_check) {
    /*Not implemented*/
    return 1;
}

int ip_sockaddr_equal(void *ref_key, void *key_check) {
    const ci_ip_t *ip_ref = (ci_ip_t *)ref_key;
    ci_sockaddr_t *ip_check = (ci_sockaddr_t *)key_check;
    char buf[128],buf1[128],buf2[128];
    ci_debug_printf(9,"going to check addresses  ip address: %s %s/%s\n",
		    ci_inet_ntoa(ip_check->ci_sin_family,ip_check->ci_sin_addr, buf, 128),
		    ci_inet_ntoa(ip_ref->family,&ip_ref->address, buf1, 128),
		    ci_inet_ntoa(ip_ref->family,&ip_ref->netmask, buf2, 128)
	);
#ifdef HAVE_IPV6
    if(ip_check->ci_sin_family == AF_INET){
	if(ip_ref->family == AF_INET)
	    return ci_ipv4_inaddr_check_net(ip_ref->address, *(ci_in_addr_t *)ip_check->ci_sin_addr, ip_ref->netmask);
	//else add->family == AF_INET6
	return ci_ipv6_in_ipv4_check_net(ip_ref->address, *(ci_in_addr_t *)ip_check->ci_sin_addr, ip_ref->netmask);
    }
    //else assuming  ip_check->ci_sin_family == AF_INET6 
    if(ip_ref->family == AF_INET6)
	return ci_ipv6_inaddr_check_net(ip_ref->address, *(ci_in_addr_t *)ip_check->ci_sin_addr, ip_ref->netmask);
    //else ip->family == AF_INET
    return ci_ipv4_in_ipv6_check_net(ip_ref->address, *(ci_in_addr_t *)ip_check->ci_sin_addr, ip_ref->netmask);
#else
    return ci_ipv4_inaddr_check_net(ip_ref->address, *(ci_in_addr_t *)ip_check->ci_sin_addr, ip_ref->netmask);
#endif

}



ci_type_ops_t  ci_ip_ops = {
    ip_dup,
    ip_free,
    ip_cmp,
    ip_len,
    ip_equal
};



ci_type_ops_t ci_ip_sockaddr_ops = {
    ip_dup,
    ip_free,
    ip_sockaddr_cmp,
    ip_len,
    ip_sockaddr_equal
};