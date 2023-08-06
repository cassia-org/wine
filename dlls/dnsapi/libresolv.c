/*
 * Unix interface for libresolv
 *
 * Copyright 2021 Hans Leidekker for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#if defined(HAVE_RESOLV) || defined(__ANDROID__)
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"
#include "windns.h"
#define USE_WS_PREFIX
#include "ws2def.h"
#include "ws2ipdef.h"

#include "wine/debug.h"
#include "dnsapi.h"

WINE_DEFAULT_DEBUG_CHANNEL(dnsapi);

#ifdef HAVE_RESOLV

/* call res_init() just once because of a bug in Mac OS X 10.4 */
/* call once per thread on systems that have per-thread _res */
static void init_resolver( void )
{
    if (!(_res.options & RES_INIT)) res_init();
}

static unsigned long map_options( DWORD options )
{
    unsigned long ret = 0;

    if (options == DNS_QUERY_STANDARD)
        return RES_DEFAULT;

    if (options & DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE)
        ret |= RES_IGNTC;
    if (options & DNS_QUERY_USE_TCP_ONLY)
        ret |= RES_USEVC;
    if (options & DNS_QUERY_NO_RECURSION)
        ret &= ~RES_RECURSE;
    if (options & DNS_QUERY_NO_LOCAL_NAME)
        ret &= ~RES_DNSRCH;
    if (options & DNS_QUERY_NO_HOSTS_FILE)
        ret |= RES_NOALIASES;
    if (options & DNS_QUERY_TREAT_AS_FQDN)
        ret &= ~RES_DEFNAMES;

    if (options & DNS_QUERY_DONT_RESET_TTL_VALUES)
        FIXME( "option DNS_QUERY_DONT_RESET_TTL_VALUES not implemented\n" );
    if (options & DNS_QUERY_RESERVED)
        FIXME( "option DNS_QUERY_RESERVED not implemented\n" );
    if (options & DNS_QUERY_WIRE_ONLY)
        FIXME( "option DNS_QUERY_WIRE_ONLY not implemented\n" );
    if (options & DNS_QUERY_NO_WIRE_QUERY)
        FIXME( "option DNS_QUERY_NO_WIRE_QUERY not implemented\n" );
    if (options & DNS_QUERY_BYPASS_CACHE)
        FIXME( "option DNS_QUERY_BYPASS_CACHE not implemented\n" );
    if (options & DNS_QUERY_RETURN_MESSAGE)
        FIXME( "option DNS_QUERY_RETURN_MESSAGE not implemented\n" );

    if (options & DNS_QUERY_NO_NETBT)
        TRACE( "netbios query disabled\n" );

    return ret;
}

static DNS_STATUS map_h_errno( int error )
{
    switch (error)
    {
    case NO_DATA:
    case HOST_NOT_FOUND: return DNS_ERROR_RCODE_NAME_ERROR;
    case TRY_AGAIN:      return DNS_ERROR_RCODE_SERVER_FAILURE;
    case NO_RECOVERY:    return DNS_ERROR_RCODE_REFUSED;
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL: return DNS_ERROR_RCODE;
#endif
    default:
        FIXME( "unmapped error code: %d\n", error );
        return DNS_ERROR_RCODE_NOT_IMPLEMENTED;
    }
}

static NTSTATUS resolv_get_searchlist( void *args )
{
    const struct get_searchlist_params *params = args;
    WCHAR *list = params->list;
    DWORD i, needed = 0;
    WCHAR *ptr, *end;

    init_resolver();

    for (i = 0; i < MAXDNSRCH + 1 && _res.dnsrch[i]; i++)
        needed += (strlen(_res.dnsrch[i]) + 1) * sizeof(WCHAR);
    needed += sizeof(WCHAR); /* null terminator */

    if (!list || *params->len < needed)
    {
        *params->len = needed;
        return !list ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }

    *params->len = needed;

    ptr = list;
    end = ptr + needed / sizeof(WCHAR);
    for (i = 0; i < MAXDNSRCH + 1 && _res.dnsrch[i]; i++)
        ptr += ntdll_umbstowcs( _res.dnsrch[i], strlen(_res.dnsrch[i]) + 1, ptr, end - ptr );
    *ptr = 0; /* null terminator */
    return ERROR_SUCCESS;
}


static inline int filter( unsigned short sin_family, USHORT family )
{
    if (sin_family != AF_INET && sin_family != AF_INET6) return TRUE;
    if (sin_family == AF_INET6 && family == WS_AF_INET) return TRUE;
    if (sin_family == AF_INET && family == WS_AF_INET6) return TRUE;

    return FALSE;
}

#ifdef HAVE_RES_GETSERVERS

static NTSTATUS resolv_get_serverlist( void *args )
{
    const struct get_serverlist_params *params = args;
    DNS_ADDR_ARRAY *addrs = params->addrs;
    struct __res_state *state = &_res;
    DWORD i, found, total, needed;
    union res_sockaddr_union *buf;

    init_resolver();

    total = res_getservers( state, NULL, 0 );
    if (!total) return DNS_ERROR_NO_DNS_SERVERS;

    if (!addrs && params->family != WS_AF_INET && params->family != WS_AF_INET6)
    {
        *params->len = FIELD_OFFSET(DNS_ADDR_ARRAY, AddrArray[total]);
        return ERROR_SUCCESS;
    }

    buf = malloc( total * sizeof(union res_sockaddr_union) );
    if (!buf) return ERROR_NOT_ENOUGH_MEMORY;

    total = res_getservers( state, buf, total );

    for (i = 0, found = 0; i < total; i++)
    {
        if (filter( buf[i].sin.sin_family, params->family )) continue;
        found++;
    }
    if (!found)
    {
        free( buf );
        return DNS_ERROR_NO_DNS_SERVERS;
    }

    needed = FIELD_OFFSET(DNS_ADDR_ARRAY, AddrArray[found]);
    if (!addrs || *params->len < needed)
    {
        free( buf );
        *params->len = needed;
        return !addrs ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }
    *params->len = needed;
    memset( addrs, 0, needed );
    addrs->AddrCount = addrs->MaxCount = found;

    for (i = 0, found = 0; i < total; i++)
    {
        if (filter( buf[i].sin.sin_family, params->family )) continue;

        if (buf[i].sin6.sin6_family == AF_INET6)
        {
            SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *)addrs->AddrArray[found].MaxSa;
            sa->sin6_family = WS_AF_INET6;
            memcpy( &sa->sin6_addr, &buf[i].sin6.sin6_addr, sizeof(sa->sin6_addr) );
            addrs->AddrArray[found].Data.DnsAddrUserDword[0] = sizeof(*sa);
        }
        else
        {
            SOCKADDR_IN *sa = (SOCKADDR_IN *)addrs->AddrArray[found].MaxSa;
            sa->sin_family = WS_AF_INET;
            sa->sin_addr.WS_s_addr = buf[i].sin.sin_addr.s_addr;
            addrs->AddrArray[found].Data.DnsAddrUserDword[0] = sizeof(*sa);
        }
        found++;
    }

    free( buf );
    return ERROR_SUCCESS;
}

#else

static NTSTATUS resolv_get_serverlist( void *args )
{
    const struct get_serverlist_params *params = args;
    DNS_ADDR_ARRAY *addrs = params->addrs;
    DWORD needed, found, i;

    init_resolver();

    if (!_res.nscount) return DNS_ERROR_NO_DNS_SERVERS;
    if (!addrs && params->family != WS_AF_INET && params->family != WS_AF_INET6)
    {
        *params->len = FIELD_OFFSET(DNS_ADDR_ARRAY, AddrArray[_res.nscount]);
        return ERROR_SUCCESS;
    }

    for (i = 0, found = 0; i < _res.nscount; i++)
    {
        unsigned short sin_family = AF_INET;
#ifdef HAVE_STRUCT___RES_STATE__U__EXT_NSCOUNT6
        if (_res._u._ext.nsaddrs[i]) sin_family = _res._u._ext.nsaddrs[i]->sin6_family;
#endif
        if (filter( sin_family, params->family )) continue;
        found++;
    }
    if (!found) return DNS_ERROR_NO_DNS_SERVERS;

    needed = FIELD_OFFSET(DNS_ADDR_ARRAY, AddrArray[found]);
    if (!addrs || *params->len < needed)
    {
        *params->len = needed;
        return !addrs ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }
    *params->len = needed;
    memset( addrs, 0, needed );
    addrs->AddrCount = addrs->MaxCount = found;

    for (i = 0, found = 0; i < _res.nscount; i++)
    {
        unsigned short sin_family = AF_INET;
#ifdef HAVE_STRUCT___RES_STATE__U__EXT_NSCOUNT6
        if (_res._u._ext.nsaddrs[i]) sin_family = _res._u._ext.nsaddrs[i]->sin6_family;
#endif
        if (filter( sin_family, params->family )) continue;

#ifdef HAVE_STRUCT___RES_STATE__U__EXT_NSCOUNT6
        if (sin_family == AF_INET6)
        {
            SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *)addrs->AddrArray[found].MaxSa;
            sa->sin6_family = WS_AF_INET6;
            memcpy( &sa->sin6_addr, &_res._u._ext.nsaddrs[i]->sin6_addr, sizeof(sa->sin6_addr) );
            addrs->AddrArray[found].Data.DnsAddrUserDword[0] = sizeof(*sa);
        }
        else
#endif
        {
            SOCKADDR_IN *sa = (SOCKADDR_IN *)addrs->AddrArray[found].MaxSa;
            sa->sin_family = WS_AF_INET;
            sa->sin_addr.WS_s_addr = _res.nsaddr_list[i].sin_addr.s_addr;
            addrs->AddrArray[found].Data.DnsAddrUserDword[0] = sizeof(*sa);
        }
        found++;
    }

    return ERROR_SUCCESS;
}
#endif

static NTSTATUS resolv_set_serverlist( void *args )
{
    const IP4_ARRAY *addrs = args;
    int i;

    init_resolver();

    if (!addrs || !addrs->AddrCount) return ERROR_SUCCESS;
    if (addrs->AddrCount > MAXNS)
    {
        WARN( "too many servers: %d only using the first: %d\n",
              (UINT)addrs->AddrCount, MAXNS );
        _res.nscount = MAXNS;
    }
    else _res.nscount = addrs->AddrCount;

    for (i = 0; i < _res.nscount; i++)
        _res.nsaddr_list[i].sin_addr.s_addr = addrs->AddrArray[i];

    return ERROR_SUCCESS;
}

static NTSTATUS resolv_query( void *args )
{
    const struct query_params *params = args;
    DNS_STATUS ret = ERROR_SUCCESS;
    int len;

    init_resolver();
    _res.options |= map_options( params->options );

    if ((len = res_query( params->name, ns_c_in, params->type, params->buf, *params->len )) < 0)
        ret = map_h_errno( h_errno );
    else
        *params->len = len;
    return ret;
}

#endif  /* HAVE_RESOLV */

#ifdef __ANDROID__

#include <dlfcn.h>

enum ResNsendFlags : uint32_t {
    ANDROID_RESOLV_NO_RETRY = 1 << 0,
    ANDROID_RESOLV_NO_CACHE_STORE = 1 << 1,
    ANDROID_RESOLV_NO_CACHE_LOOKUP = 1 << 2,
};

typedef uint64_t net_handle_t;

#define NETWORK_UNSPECIFIED ((net_handle_t)0)

static int (*p_android_res_nsend)(net_handle_t network, const uint8_t *msg, size_t msglen,
                      uint32_t flags);

static int (*p_android_res_nresult)(int fd, int *rcode, uint8_t *answer, size_t anslen);

static BOOL android_resolv_init( void )
{
    static BOOL init_done = FALSE;
    if (!init_done)
    {
        void *android_handle = dlopen( "libandroid.so", RTLD_NOW );
        if (!android_handle) {
            TRACE( "failed to load libandroid.so: %s\n", dlerror() );
            init_done = TRUE;
            return FALSE;
        }

#define LOAD_FUNCPTR(f) p_##f = dlsym(android_handle, #f)
        LOAD_FUNCPTR(android_res_nsend);
        LOAD_FUNCPTR(android_res_nresult);
#undef LOAD_FUNCPTR
        init_done = TRUE;
    }

    return p_android_res_nsend && p_android_res_nresult;
}

static NTSTATUS resolv_get_searchlist( void *args )
{
    /* Android NDK networking doesn't have DNS suffixes/searchlists */
    const struct get_searchlist_params *params = args;
    WCHAR *list = params->list;

    if (!list || *params->len < sizeof(WCHAR))
    {
        *params->len = sizeof(WCHAR);
        return !list ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }

    *list = 0; /* null terminator */
    *params->len = sizeof(WCHAR);

    return ERROR_SUCCESS;
}

static NTSTATUS resolv_get_serverlist( void *args )
{
    /* Android NDK networking doesn't support retrieving the nameservers */ 
    TRACE( "resolv_get_serverlist not supported on Android\n" );
    return DNS_ERROR_NO_DNS_SERVERS;
}

static NTSTATUS resolv_set_serverlist( void *args )
{
    /* Android NDK networking doesn't support changing the nameservers */ 
    TRACE( "resolv_set_serverlist not supported on Android\n" );
    return ERROR_SUCCESS;
}

static NTSTATUS resolv_query( void *args )
{
    const struct query_params *params = args;
    uint8_t msg[NS_PACKETSZ];
    int msglen, res, rcode = 0;
    HEADER *header;
    uint32_t flags = 0;

    if (!android_resolv_init())
        return DNS_ERROR_RCODE_NOT_IMPLEMENTED; /* The host libandroid doesn't
                                                   seem to implement the NDK
                                                   networking functions */

    msglen = res_mkquery( ns_o_query, params->name, ns_c_in, params->type,
                          NULL, 0, NULL, msg, NS_PACKETSZ );

    header = (HEADER *)msg;
    header->rd = !(params->options & DNS_QUERY_NO_RECURSION);
    header->ad = (params->options & DNS_QUERY_DNSSEC_OK);

    if (params->options & DNS_QUERY_BYPASS_CACHE)
        flags = ANDROID_RESOLV_NO_CACHE_STORE | ANDROID_RESOLV_NO_CACHE_LOOKUP;

    if ((res = (*p_android_res_nsend)( NETWORK_UNSPECIFIED, msg, msglen, flags )) < 0)
        return DNS_ERROR_RCODE_REFUSED; /* The query failed, the results provided
                                           by this don't properly translate to
                                           WinAPI ones */

    if ((res = (*p_android_res_nresult)( res, &rcode, params->buf,
                                        *params->len )) < 0)
        return DNS_ERROR_RCODE_REFUSED;

    if (rcode == ns_r_noerror)
    {
        *params->len = res;
        return ERROR_SUCCESS;
    }
    else
    {
        switch (rcode) {
            case ns_r_formerr:
                return DNS_ERROR_RCODE_FORMAT_ERROR;
            case ns_r_servfail:
                return DNS_ERROR_RCODE_SERVER_FAILURE;
            case ns_r_nxdomain:
                return DNS_ERROR_RCODE_NAME_ERROR;
            case ns_r_notimpl:
                return DNS_ERROR_RCODE_NOT_IMPLEMENTED;
            case ns_r_refused:
                return DNS_ERROR_RCODE_REFUSED;
            case ns_r_yxdomain:
                return DNS_ERROR_RCODE_YXDOMAIN;
            case ns_r_yxrrset:
                return DNS_ERROR_RCODE_YXRRSET;
            case ns_r_nxrrset:
                return DNS_ERROR_RCODE_NXRRSET;
            case ns_r_notauth:
                return DNS_ERROR_RCODE_NOTAUTH;
            case ns_r_notzone:
                return DNS_ERROR_RCODE_NOTZONE;
            case ns_r_badsig:
                return DNS_ERROR_RCODE_BADSIG;
            case ns_r_badkey:
                return DNS_ERROR_RCODE_BADKEY;
            case ns_r_badtime:
                return DNS_ERROR_RCODE_BADTIME;
            default:
                return DNS_ERROR_RCODE_NOT_IMPLEMENTED;
        }
    }
}

#endif

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    resolv_get_searchlist,
    resolv_get_serverlist,
    resolv_set_serverlist,
    resolv_query,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );

#ifdef _WIN64

typedef ULONG PTR32;

static NTSTATUS wow64_resolv_get_searchlist( void *args )
{
    struct
    {
        PTR32  list;
        PTR32  len;
    } const *params32 = args;

    struct get_searchlist_params params =
    {
        ULongToPtr(params32->list),
        ULongToPtr(params32->len)
    };

    return resolv_get_searchlist( &params );
}

static NTSTATUS wow64_resolv_get_serverlist( void *args )
{
    struct
    {
        USHORT family;
        PTR32  addrs;
        PTR32  len;
    } const *params32 = args;

    struct get_serverlist_params params =
    {
        params32->family,
        ULongToPtr(params32->addrs),
        ULongToPtr(params32->len)
    };

    return resolv_get_serverlist( &params );
}

static NTSTATUS wow64_resolv_query( void *args )
{
    struct
    {
        PTR32  name;
        WORD   type;
        DWORD  options;
        PTR32  buf;
        PTR32  len;
    } const *params32 = args;

    struct query_params params =
    {
        ULongToPtr(params32->name),
        params32->type,
        params32->options,
        ULongToPtr(params32->buf),
        ULongToPtr(params32->len)
    };

    return resolv_query( &params );
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    wow64_resolv_get_searchlist,
    wow64_resolv_get_serverlist,
    resolv_set_serverlist,
    wow64_resolv_query,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_wow64_funcs) == unix_funcs_count );

#endif  /* _WIN64 */

#endif /* defined(HAVE_RESOLV) || defined(__ANDROID__) */
