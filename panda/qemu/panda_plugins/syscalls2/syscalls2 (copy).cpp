/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

extern "C" {
#define __STDC_FORMAT_MACROS

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
}
//#include <fstream>
//#include <sstream>
#include <cassert>
#include <functional>
#include <string>
#include <map>
#include <queue>
#include <algorithm>
#include <memory>
#include "syscalls2.h"
#include <fstream>
#include <sstream>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong));

// PPP code
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_boilerplate_enter.cpp"
#include "gen_syscall_ppp_boilerplate_return.cpp"
#include "gen_syscall_ppp_register_enter.cpp"
#include "gen_syscall_ppp_register_return.cpp"

}

std::ofstream faros_syscall;

// Forward declarations
target_ulong get_pointer_32bit(CPUState *env, uint32_t argnum);
target_ulong get_pointer_64bit(CPUState *env, uint32_t argnum);
target_ulong get_return_pointer_32bit(CPUState *env, uint32_t argnum);
target_ulong get_return_pointer_64bit(CPUState *env, uint32_t argnum);
int32_t get_s32_generic(CPUState *env, uint32_t argnum);
int64_t get_s64_generic(CPUState *env, uint32_t argnum);
int32_t get_return_s32_generic(CPUState *env, uint32_t argnum);
int64_t get_return_s64_generic(CPUState *env, uint32_t argnum);

// Reinterpret the ulong as a long. Arch and host specific.
target_long get_return_val_x86(CPUState *env){
#if defined(TARGET_I386)
    return static_cast<target_long>(env->regs[R_EAX]);
#endif
    return 0;
}

target_long get_return_val_arm(CPUState *env){
#if defined(TARGET_ARM)
    return static_cast<target_long>(env->regs[0]);
#endif
    return 0;
}

target_ulong mask_retaddr_to_pc(target_ulong retaddr){
    target_ulong mask = std::numeric_limits<target_ulong>::max() -1;
    return retaddr & mask;
}

// Return address calculations
target_ulong calc_retaddr_windows_x86(CPUState* env, target_ulong pc) {
#if defined(TARGET_I386)
    target_ulong retaddr = 0;
    panda_virtual_memory_rw(env, EDX, (uint8_t *) &retaddr, 4, false);
    return retaddr;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_x86(CPUState* env, target_ulong pc) {
#if defined(TARGET_I386)
    return pc+11;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_arm(CPUState* env, target_ulong pc) {
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    // Except that we haven't run the SWI instruction yet! LR is where libc will return to!
    //return mask_retaddr_to_pc(env->regs[14]);

    // Fork, exec
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    return mask_retaddr_to_pc(pc + offset);
#else
    // shouldnt happen
    assert (1==0);
#endif
}

// Argument getting (at syscall entry)
uint32_t get_linux_x86_argnum(CPUState *env, uint32_t argnum) {
#if defined(TARGET_I386)
    switch (argnum) {
    case 0: 
        return env->regs[R_EBX];
        break;
    case 1:
        return env->regs[R_ECX];
        break;
    case 2:
        return env->regs[R_EDX];
        break;
    case 3:
        return env->regs[R_ESI];
        break;
    case 4:
        return env->regs[R_EDI];
        break;
    case 5:
        return env->regs[R_EBP];
        break;
    }
    assert (1==0);
#endif
    return 0;
}

static uint32_t get_win_syscall_arg(CPUState* env, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t arg = 0;
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#endif
    return 0;
}

/* <MN FAROS> */
static uint32_t get_win_syscall_arg_pointer (CPUState* env, int nr, void **buffer, uint32_t len, uint32_t *pointer_addr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t pt = 0;
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &pt, 4, false);
    if(pt == 0)
        return 0;
    *buffer = malloc(len);
    if(*buffer == NULL)
        return 0;
    panda_virtual_memory_rw(env, pt,
                            (uint8_t *) *buffer, len, false);
                            
    *pointer_addr = env->regs[R_EDX] + 8 + (4*nr);
    return pt;
#endif
    return 0;
}



/**
 * String helpers
 *
 * These helpers are used to unescape strings.
 */
/*static void wchar_to_utf8(uint16_t wchar, char *buffer, size_t buffer_length)
{
    if (wchar <= 0x007F) {
        //BUG_ON(buffer_length < 2);

        buffer[0] = wchar & 0x7F;
        buffer[1] = 0;
    } else if (wchar <= 0x07FF) {
        //BUG_ON(buffer_length < 3);

        buffer[0] = 0xC0 | ((wchar >> 6) & 0x1F);
        buffer[1] = 0x80 | (wchar & 0x3F);
        buffer[2] = 0;
    } else {
       // BUG_ON(buffer_length < 4);

        buffer[0] = 0xE0 | ((wchar >> 12) & 0x0F);
        buffer[1] = 0x80 | ((wchar >> 6) & 0x3F);
        buffer[2] = 0x80 | (wchar & 0x3F);
        buffer[3] = 0;
    }
}
*/

/* unicode -> ISO-8859-1 */
/*static int
uni2asc( char *astr, const unsigned char *ustr, int ustrlen, int maxlen )
{
        int len;

        if( maxlen <= 0 )
                return 0;

        for( len=0; ustrlen-- > 0 && len < maxlen-1 ; ustr += 2 ) {

                if( ustr[0] || !ustr[1] )
                        continue;
                if( ustr[1] < 0x20 || ustr[1] >= 0x7f )
                    *astr++ = '?';
                else
                    *astr++ = ustr[1];
                len++;
        }
        *astr = 0;
        //std::string str(astr);
        //faros_syscall << "\n astr: " << str;
        return len;
}*/

#define PTR uint32_t

/* <MN FAROS> */
// Gets a unicode string. Does its own mem allocation.
// Output is a null-terminated UTF8 string
char * get_unicode_str(CPUState *env, PTR ustr) {
    uint16_t size = 0;
    PTR str_ptr = 0;
    if (-1 == panda_virtual_memory_rw(env, ustr, (uint8_t *)&size, 2, false)) {
        return NULL;//make_pagedstr();
    }
    // Clamp size
    if (size > 1024) size = 1024;
    if (-1 == panda_virtual_memory_rw(env, ustr+4, (uint8_t *)&str_ptr, 4, false)) {
        return NULL;//make_pagedstr();
    }
    gchar *in_str = (gchar *)g_malloc0(size);
    if (-1 == panda_virtual_memory_rw(env, str_ptr, (uint8_t *)in_str, size, false)) {
        g_free(in_str);
        return NULL;//make_pagedstr(); 
    }

    GError *error = NULL;
    
    gsize bytes_written = 0;
     if(in_str == NULL || size == 0){
           // faros_syscall << "\n error: str is NULL!" ;
           // faros_syscall.flush();
            return NULL;
    }
    gchar *out_str = g_convert(in_str, size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, &error);

    if(error){
        std::string str(error->message);
        faros_syscall << "\n error: " << str ;
        faros_syscall.flush();
        return NULL;
    }
    
    if(out_str == NULL){
        faros_syscall << "\n error: out_str == NULL";
        faros_syscall.flush();
        return NULL;
    }
    // An abundance of caution: we copy it over to something allocated
    // with our own malloc. In the future we need to provide a way for
    // someone else to free the memory allocated in here...
    char *ret = (char *)malloc(bytes_written+1);
    memcpy(ret, out_str, bytes_written+1);
    g_free(in_str);
    g_free(out_str);
    return ret;
}


/* <MN FAROS> */
static char * get_win_syscall_arg_struct_obj_attr (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to _OBJECT_ATTRIBUTES
    uint32_t uptr = 0; // Pointer to _UNICODE_STRING
    char *obj_name;
    
    // Read/Get _OBJECT_ATTRIBUTES's pointer content
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    
    if(ptr == 0)
        return NULL;
    // Read/Get _OBJECT_ATTRIBUTES's structure size
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) struct_size, 4, false);

    if (*struct_size == 0) // Return is the structure is empty
        return NULL;
   
    *struct_content = malloc(*struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, *struct_size, false);
    
    // Read/Get _UNICODE_STRING's pointer content
    panda_virtual_memory_rw(env, ptr + 8,
                            (uint8_t *) &uptr, 4, false);
    if(!uptr)
        return NULL;
    // Read/Get _UNICODE_STRING's wstring size
    panda_virtual_memory_rw(env, uptr, (uint8_t *) ustr_size, 2, false);
   
    // Get the unicode string and convert it to char *
    obj_name = get_unicode_str(env, uptr);
    
    /*std::string str((char *)obj_name);
    
    faros_syscall << "\n str: " << str;
    faros_syscall.flush();*/
    
    *struct_addr = ptr;
    *ustr_addr = uptr;
    
    return obj_name;
#endif
    return NULL;
}

char out[150000];

std::string to_hex_str_buff(char *buf, uint32_t size) {
    uint32_t i,j;
    out[0] = '\0';

    if(size >= 100000){
        std::string str_null("");
        return str_null;
    }
/*
    for (i = size - 1,j = 0; i >= 0 ; i--, j++)
        sprintf( out + j*2, "%02X", buf[i]);
*/
    for (i = 0,j = 0; i < size; i++, j++)
        sprintf( out + j*2, "%02X", buf[i]);
        
    out[j*2] = '\0';

    std::string str(out);    

    return str;
}

// The following functions (starting with get_afd*) SHOULD be static

#define MAX_INFO_BUFF 200
#define MAX_SHORT_INFO_BUFF 100
#define MAX_EXTRACTED_BUFF 1000
/*
struct sockaddr {
    unsigned short    sa_family;    // address family, AF_xxx
    char              sa_data[14];  // 14 bytes of protocol address
};


struct sockaddr_in{
   short sin_family;
   unsigned short sin_port;
   struct in_addr sin_addr;
   char sin_zero[8];
};

struct sockaddr_un {
               sa_family_t sun_family;               // AF_UNIX (unsigned short)
               char        sun_path[108];            // pathname 
           };
           
typedef struct _AFD_BIND_DATA {
    ULONG				ShareType;
    SOCKADDR    	    Address;
} AFD_BIND_DATA, *PAFD_BIND_DATA;
size:20
*/
/* <MN FAROS> */
static char * get_afd_bind_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_BIND_DATA
    char *buffer = 0;
    
    // Read/Get AFD_BIND_DATA's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_BIND_DATA's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
    // Read/Get protocol family number
    uint32_t family = 0;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &family, 4, false);
    
    switch(family){
        case AF_INET:{
            unsigned short port = 0;
            struct in_addr addr;
            panda_virtual_memory_rw(env, ptr + 2,
                                   (uint8_t *) &port, 2, false);
            panda_virtual_memory_rw(env, ptr + 8,
                                   (uint8_t *) &addr, 4, false);
                                   
            char *ip_adress = inet_ntoa(addr);

            std::string ip((char *)ip_adress);
            
            buffer = (char *)malloc(MAX_INFO_BUFF);
            if (addr.s_addr == INADDR_ANY)
                sprintf(buffer,"IOCTL_AFD_BIND<<family:AF_INET@port:%d@address:INADDR_ANY>>", port);
            else
                sprintf(buffer,"IOCTL_AFD_BIND<<family:AF_INET@port:%d@address:%s>>", port, ip_adress);
            
            //faros_syscall << "\n BIND => " <<"family: " << family << ", port: " << port << ", address: " << ip;
            break;
        }
        case AF_UNSPEC:{
            /*char sa_data[14];
            panda_virtual_memory_rw(env, ptr + 6,
                                   (uint8_t *) sa_data, 14, false);

            std::string sa_data_str((char *)sa_data);
            
            buffer = (char *)malloc(100);
            sprintf(buffer,"BIND::family:AF_UNSPEC,sa_data:%s", sa_data);           
            
            faros_syscall << "\n BIND => " << "size: " << struct_size <<"family: AF_UNSPEC" << ", address: " << sa_data_str;
            break;*/   
             
            buffer = (char *)malloc(MAX_SHORT_INFO_BUFF);
            sprintf(buffer,"%s","IOCTL_AFD_BIND<<family:AF_UNSPEC>>");
            break;
        }
        case AF_UNIX:{
            char sun_path[108];
            panda_virtual_memory_rw(env, ptr + 6,
                                   (uint8_t *) sun_path, 108, false);

            std::string sun_path_str((char *)sun_path);
            
            buffer = (char *)malloc(MAX_INFO_BUFF);
            sprintf(buffer,"IOCTL_AFD_BIND<<family:AF_UNIX@path:%s>>", sun_path);           
            
            //faros_syscall << "\n BIND => " << "size: " << struct_size <<"family: AF_UNIX" << ", address: " << sun_path_str;
            break;
        }
        case AF_INET6:{
            buffer = (char *)malloc(MAX_SHORT_INFO_BUFF);
            sprintf(buffer,"%s","IOCTL_AFD_BIND<<family:AF_INET6>>");
            // TO DO
            break;
        }
        default:{
            buffer = (char *)malloc(MAX_SHORT_INFO_BUFF);
            sprintf(buffer,"%s","IOCTL_AFD_BIND<<family:UNKNOWN>>");
            break;        
        }
            
    }
    faros_syscall.flush();
       

    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
struct sockaddr_in{
   short sin_family;
   unsigned short sin_port;
   struct in_addr sin_addr;
   char sin_zero[8];
};

typedef struct  _AFD_CONNECT_INFO {
    BOOLEAN				UseSAN;
    ULONG				Root;
    ULONG				Unknown;
    SOCKADDR    	    RemoteAddress;
} AFD_CONNECT_INFO , *PAFD_CONNECT_INFO ;
*/

/* <MN FAROS> */
static char * get_afd_connect_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_CONNECT_INFO
    char *buffer = 0;
    
    // Read/Get AFD_CONNECT_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_CONNECT_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
    
    // Read/Get sa_data
    struct sockaddr_in sin;
   
    panda_virtual_memory_rw(env, ptr+12,
                            (uint8_t *) &sin, sizeof(struct sockaddr_in), false);
  
    char *ip_adress = inet_ntoa(sin.sin_addr);
    std::string ip((char *)ip_adress);
    
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_CONNECT<<family:%d@port:%d@address:%s>>", sin.sin_family, sin.sin_port, ip_adress);
    
    //faros_syscall << "\n CONNECT => " << "family: " << sin.sin_family << ", port: " << sin.sin_port << ", address: " << ip;
    //faros_syscall.flush();    

    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_ACCEPT_DATA {
    uint32_t				UseSAN;
    uint32_t				SequenceNumber;
    uint32_t				ListenHandle;
} AFD_ACCEPT_DATA, *PAFD_ACCEPT_DATA;
size:12
*/

/* <MN FAROS> */
static char * get_afd_accept_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_ACCEPT_DATA
    char *buffer = 0;
    
    // Read/Get AFD_ACCEPT_DATA's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_ACCEPT_DATA's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
    
    uint32_t UseSAN = 0;
    uint32_t SequenceNumber = 0;
    uint32_t ListenHandle = 0;
 
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &UseSAN, 4, false);
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &SequenceNumber, 4, false);
    panda_virtual_memory_rw(env, ptr + 8,
                            (uint8_t *) &ListenHandle, 4, false);
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_ACCEPT<<UseSAN:%d@SequenceNumber:%d@ListenHandle:%d>>", UseSAN, SequenceNumber, ListenHandle);

    //faros_syscall << "\n ACCEPT => " << "size" << struct_size << "UseSAN:" << UseSAN << ", SequenceNumber: " << SequenceNumber << ", ListenHandle: " << ListenHandle;
    //faros_syscall.flush();    

    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

char ascii_out_buf[2*MAX_EXTRACTED_BUFF];

// Returns a null-terminated string
void extract_asscii_str(char *in_buf, uint32_t in_buf_len){

    //char *out_buf;
    //uint32_t out_buf_size = in_buf_len + 200;
    //out_buf  = (char *)malloc(1000);
    //uint32_t j = 0, w;
    uint32_t len = 0,inuse_cap = 0, index;
    for (uint32_t i = 0; i < in_buf_len; i++){

        for (index = 0, len = 0;isprint((int)in_buf[i + index]); index++)
            len++;
        if ( len + inuse_cap > MAX_EXTRACTED_BUFF && len > 8){
            len = MAX_EXTRACTED_BUFF - inuse_cap;
            memcpy((void *)((char *)(ascii_out_buf + inuse_cap)), (void *)((char *)(in_buf + i)), len);
            inuse_cap += len;
            break;
        }
        if (len > 8){
            memcpy((void *)((char *)(ascii_out_buf + inuse_cap)), (void *)((char *)(in_buf + i)), len);
            memcpy((void *)((char *)(ascii_out_buf + inuse_cap + len)), "++", 2);
            inuse_cap += len + 2;
        }
        if (len > 0)
            i += len - 1;

        if (inuse_cap >= MAX_EXTRACTED_BUFF)
            break;
    }
    ascii_out_buf[inuse_cap] = '\0';
    //return out_buf;
}

#define MAX_MEM_SIZE 10000
char recv_buf[MAX_MEM_SIZE + 1];
char send_buf[MAX_MEM_SIZE + 1];

/*
typedef struct _AFD_WSABUF {
    unsigned int  len;
    char          *buf;
} AFD_WSABUF, *PAFD_WSABUF;

typedef struct  _AFD_RECV_INFO {
    PAFD_WSABUF	        BufferArray;
    uint32_t			BufferCount;
    uint32_t			AfdFlags;
    uint32_t			TdiFlags;
} AFD_RECV_INFO , *PAFD_RECV_INFO ;
*/

/* <MN FAROS> */
static char * get_afd_recv_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_RECV_INFO
    uint32_t wptr = 0; // Pointer to AFD_WSABUF
    char *buffer = 0;
    
    // Read/Get AFD_RECV_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_RECV_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t BufferCount = 0;
    uint32_t AfdFlags = 0;
    uint32_t TdiFlags = 0;
    panda_virtual_memory_rw(env, ptr+4,
                            (uint8_t *) &BufferCount, 4, false);
    panda_virtual_memory_rw(env, ptr+8,
                            (uint8_t *) &AfdFlags, 4, false);
    panda_virtual_memory_rw(env, ptr+12,
                            (uint8_t *) &TdiFlags, 4, false);    
    
    //recv_buf[recv_buf_len] = '\0';
    //std::string str(recv_buf);
    //char * new_str = extract_asscii_str(recv_buf, recv_buf_len);

    // Read/Get AFD_WSABUF's pointer
    panda_virtual_memory_rw(env, ptr,
                                (uint8_t *) &wptr, 4, false);

    uint32_t buf_len = 0;
    uint32_t recv_buf_len = 0;
    // Calculate how much memory we need to allocate
     for (uint32_t i = 0; i < BufferCount; i++){        
        recv_buf_len = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &recv_buf_len, 4, false);
        buf_len += recv_buf_len;
    }
    buffer = (char *)malloc(MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF);
    if(!buffer){
    	faros_syscall << "\nget_afd_recv_data: malloc failed! size: " << MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF;
        faros_syscall.flush();
        return NULL;
    }
    sprintf(buffer,"IOCTL_AFD_RECV<<BufferCount:%d@AfdFlags:%d@TdiFlags:%d", BufferCount, AfdFlags, TdiFlags);
    for (uint32_t i = 0; i < BufferCount; i++){
        
        recv_buf_len = 0;
        uint32_t buf_p = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &recv_buf_len, 4, false);
        // Read/Get buf's pointer
        panda_virtual_memory_rw(env, wptr + 8*i + 4,
                                (uint8_t *) &buf_p, 4, false);
        uint32_t alloc_recv_buf_len = 0;
        if (recv_buf_len > MAX_MEM_SIZE)
            alloc_recv_buf_len = MAX_MEM_SIZE;
        else
            alloc_recv_buf_len = recv_buf_len;
        //char *recv_buf = (char *)malloc(alloc_recv_buf_len);

        // Read/Get buf's content
        panda_virtual_memory_rw(env, buf_p,
                            (uint8_t *) recv_buf, alloc_recv_buf_len, false);

        //char * ascii_buf = extract_asscii_str(recv_buf, recv_buf_len);
        extract_asscii_str(recv_buf, alloc_recv_buf_len);
        //std::string hex_buf = to_hex_str_buff(recv_buf, recv_buf_len);
        //free(recv_buf);
        if (i == BufferCount - 1)
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}>>", recv_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf/*hex_buf.c_str()*/);
        else
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}", recv_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf/*hex_buf.c_str()*/);
        
        //free(ascii_buf);
    }
    
    //std::string str(new_str);
    //faros_syscall << "\n RECV =>"  <<"BufferCount: " << BufferCount << ", AfdFlags: " << AfdFlags << ", TdiFlags: " << TdiFlags;
    // faros_syscall.flush();
    
    *buffer_addr = wptr;
    *buffer_size = 8;
    
    return buffer;
#endif
    return NULL;
}


/*
typedef struct  _AFD_SEND_INFO {
    PAFD_WSABUF			BufferArray;
    ULONG				BufferCount;
    ULONG				AfdFlags;
    ULONG				TdiFlags;
} AFD_SEND_INFO , *PAFD_SEND_INFO ;
size:16
*/
/* <MN FAROS> */
static char * get_afd_send_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_SEND_INFO
    uint32_t wptr = 0; // Pointer to AFD_WSABUF
    char *buffer = 0;
    
    // Read/Get AFD_SEND_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_SEND_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t BufferCount = 0;
    uint32_t AfdFlags = 0;
    uint32_t TdiFlags = 0;
    panda_virtual_memory_rw(env, ptr+4,
                            (uint8_t *) &BufferCount, 4, false);
    panda_virtual_memory_rw(env, ptr+8,
                            (uint8_t *) &AfdFlags, 4, false);
    panda_virtual_memory_rw(env, ptr+12,
                            (uint8_t *) &TdiFlags, 4, false);
    
    // Read/Get AFD_WSABUF's pointer
    panda_virtual_memory_rw(env, ptr,
                                (uint8_t *) &wptr, 4, false);

    uint32_t buf_len = 0;
    uint32_t send_buf_len = 0;
    // Calculate how much memory we need to allocate
     for (uint32_t i = 0; i < BufferCount; i++){        
        send_buf_len = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &send_buf_len, 4, false);
        buf_len += send_buf_len;
    }
    buffer = (char *)malloc(MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF);
    if(!buffer){
      	faros_syscall << "\nget_afd_send_data: malloc failed! size: " << MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF;
        faros_syscall.flush();
        return NULL;
    }
    sprintf(buffer,"IOCTL_AFD_SEND<<BufferCount:%d@AfdFlags:%d@TdiFlags:%d", BufferCount, AfdFlags, TdiFlags);
    for (uint32_t i = 0; i < BufferCount; i++){
        
        send_buf_len = 0;
        uint32_t buf_p = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &send_buf_len, 4, false);
        // Read/Get buf's pointer
        panda_virtual_memory_rw(env, wptr + 8*i + 4,
                                (uint8_t *) &buf_p, 4, false);
        uint32_t alloc_send_buf_len = 0;
        if (send_buf_len > MAX_MEM_SIZE)
            alloc_send_buf_len = MAX_MEM_SIZE;
        else
            alloc_send_buf_len = send_buf_len;                        
        //char *send_buf = (char *)malloc(send_buf_len);
        // Read/Get buf's content
        panda_virtual_memory_rw(env, buf_p,
                            (uint8_t *) send_buf, alloc_send_buf_len, false);
        

        //char * ascii_buf = extract_asscii_str(send_buf, send_buf_len);
        extract_asscii_str(send_buf, alloc_send_buf_len);
        //std::string hex_buf = to_hex_str_buff(send_buf, send_buf_len);
        //free(send_buf);
        if (i == BufferCount - 1)
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}>>", send_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf/*hex_buf.c_str()*/);
        else
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}", send_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf/*hex_buf.c_str()*/);
        
       // free(ascii_buf);
        
    }
       
    *buffer_addr = wptr;
    *buffer_size = 8;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_DISCONNECT_INFO {
    ULONG				DisconnectType;
    LARGE_INTEGER			Timeout;
} AFD_DISCONNECT_INFO, *PAFD_DISCONNECT_INFO;
size:16
*/
/* <MN FAROS> */
static char * get_afd_disconnect_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_DISCONNECT_INFO
    char *buffer = 0;
    
    // Read/Get AFD_DISCONNECT_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_DISCONNECT_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t DisconnectType = 0;
    long long Timeout = 0;

    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &DisconnectType, 4, false);
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &Timeout, 12, false);
    
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_DISCONNECT<<DisconnectType:%d@Timeout:%lld>>", DisconnectType, Timeout);
                           
    //faros_syscall << "\n DISCONNECT =>" << "struct:" << struct_size << "DisconnectType: " << DisconnectType << ", Timeout: " << Timeout;                       
    //faros_syscall.flush();    
       
    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_LISTEN_DATA {
    BOOLEAN				UseSAN;
    ULONG				Backlog;
    BOOLEAN				UseDelayedAcceptance;
} AFD_LISTEN_DATA, *PAFD_LISTEN_DATA;
*/
/* <MN FAROS> */
static char * get_afd_listen_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_LISTEN_DATA
    char *buffer = 0;
    
    // Read/Get AFD_LISTEN_DATA's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_LISTEN_DATA's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t UseSAN = 0;
    uint32_t Backlog = 0;
    uint32_t UseDelayedAcceptance = 0;
    
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &UseSAN, 4, false);
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &Backlog, 4, false);
    panda_virtual_memory_rw(env, ptr + 8,
                            (uint8_t *) &UseDelayedAcceptance, 4, false);
    
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_LISTEN<<UseSAN:%d@Backlog:%d@UseDelayedAcceptance:%d>>", UseSAN, Backlog, UseDelayedAcceptance);
                         
    //faros_syscall << "\n LISTEN =>" << "struct:" << struct_size << "UseSAN: " << UseSAN << ", Backlog: " << Backlog << ", UseDelayedAcceptance: " << UseDelayedAcceptance;                       
    //faros_syscall.flush();    
       
    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_EVENT_SELECT_INFO {
    HANDLE				EventObject;
    ULONG				Events;
} AFD_EVENT_SELECT_INFO, *PAFD_EVENT_SELECT_INFO;
size:8
*/
/* <MN FAROS> */
static char * get_afd_event_select_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_EVENT_SELECT_INFO
    char *buffer = 0;
    
    // Read/Get AFD_EVENT_SELECT_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_EVENT_SELECT_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t EventObject = 0;
    uint32_t Events = 0;
    
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &EventObject, 4, false);
    panda_virtual_memory_rw(env, ptr+4,
                            (uint8_t *) &Events, 4, false);
    
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_EVENT_SELECT<<EventObject:%d@Events:%d>>", EventObject, Events);
               
    //faros_syscall << "\n EVENT SELECT =>" << "struct:" << struct_size << "EventObject: " << EventObject << ", Events: " << Events;                       
    //faros_syscall.flush();    
       
    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_ENUM_NETWORK_EVENTS_INFO {
    HANDLE Event;
    ULONG PollEvents;
    NTSTATUS EventStatus[AFD_MAX_EVENTS];
} AFD_ENUM_NETWORK_EVENTS_INFO, *PAFD_ENUM_NETWORK_EVENTS_INFO;
*/
static char * get_afd_network_events_data (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){
#if defined(TARGET_I386)

    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_ENUM_NETWORK_EVENTS_INFO

    char *buffer = 0;
    
    // Read/Get AFD_ENUM_NETWORK_EVENTS_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_ENUM_NETWORK_EVENTS_INFO's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t Event = 0;
    uint32_t PollEvents = 0;
    
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &Event, 4, false);
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &PollEvents, 4, false);
    
    buffer = (char *)malloc(MAX_INFO_BUFF);
    sprintf(buffer,"IOCTL_AFD_ENUM_NETWORK_EVENTS_INFO<<Event:%d@PollEvents:%d>>", Event, PollEvents);    
    
    //faros_syscall << "\n NETWORK_EVENTS =>" << "struct:" << struct_size << "Event: " << Event << ", PollEvents: " << PollEvents;                       
    //faros_syscall.flush();    
       
    *buffer_addr = 0;
    *buffer_size = 0;
    
    return buffer;
#endif
    return NULL;
}

/*
typedef struct _AFD_RECV_INFO_UDP {
    PAFD_WSABUF			BufferArray;
    ULONG				BufferCount;
    ULONG				AfdFlags;
    ULONG				TdiFlags;
    PVOID				Address;
    PINT				AddressLength;
} AFD_RECV_INFO_UDP, *PAFD_RECV_INFO_UDP;
*/

static char * get_afd_recv_datagram(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){

#if defined(TARGET_I386)
   
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_RECV_INFO_UDP
    uint32_t wptr = 0; // Pointer to AFD_WSABUF
    char *buffer = 0;
    
    // Read/Get AFD_RECV_INFO_UDP's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_RECV_INFO_UDP's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t BufferCount = 0;
    uint32_t AfdFlags = 0;
    uint32_t TdiFlags = 0;
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &BufferCount, 4, false);
    panda_virtual_memory_rw(env, ptr + 8,
                            (uint8_t *) &AfdFlags, 4, false);
    panda_virtual_memory_rw(env, ptr + 12,
                            (uint8_t *) &TdiFlags, 4, false);
                            
    /* This API is asynch and info.Address is an
     * outparam, so its possible that none of this data is written yet
     */
    /*
    uint32_t AddressLength = 0, AddressLength_p = 0;
    uint32_t Address_p = 0;
    panda_virtual_memory_rw(env, ptr + 20,
                            (uint8_t *) &AddressLength_p, 4, false);
    panda_virtual_memory_rw(env, AddressLength_p,
                            (uint8_t *) &AddressLength, 4, false);
    char *Address = (char *)malloc(AddressLength);
    panda_virtual_memory_rw(env, ptr + 16,
                            (uint8_t *) &Address_p, 4, false);
    panda_virtual_memory_rw(env, Address_p,
                            (uint8_t *) Address, AddressLength, false);*/

    // Read/Get AFD_WSABUF's pointer
    panda_virtual_memory_rw(env, ptr,
                                (uint8_t *) &wptr, 4, false);

    uint32_t buf_len = 0;
    uint32_t recv_buf_len = 0;
    // Calculate how much memory we need to allocate
    for (uint32_t i = 0; i < BufferCount; i++){        
        recv_buf_len = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &recv_buf_len, 4, false);
        buf_len += recv_buf_len;
    }
    buffer = (char *)malloc(MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF);
    if(!buffer){
      	faros_syscall << "\nget_afd_recv_datagram: malloc failed! size: " << MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF;
        faros_syscall.flush();
        return NULL;
    }      
    sprintf(buffer,"IOCTL_AFD_RECV_DATAGRAM<<BufferCount:%d@AfdFlags:%d@TdiFlags:%d", BufferCount, AfdFlags, TdiFlags);
    for (uint32_t i = 0; i < BufferCount; i++){
        
        recv_buf_len = 0;
        uint32_t buf_p = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &recv_buf_len, 4, false);
        // Read/Get buf's pointer
        panda_virtual_memory_rw(env, wptr + 8*i + 4,
                                (uint8_t *) &buf_p, 4, false);
        uint32_t alloc_recv_buf_len = 0;
        if (recv_buf_len > MAX_MEM_SIZE)
            alloc_recv_buf_len = MAX_MEM_SIZE;
        else
            alloc_recv_buf_len = recv_buf_len;
        //char *recv_buf = (char *)malloc(recv_buf_len);
        // Read/Get buf's content
        panda_virtual_memory_rw(env, buf_p,
                            (uint8_t *) recv_buf, alloc_recv_buf_len, false);
        if(recv_buf_len < 1000){
            std::string hex_buf = to_hex_str_buff(recv_buf, recv_buf_len);
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d hexContent:{%s}", recv_buf_len, recv_buf_len, i+1, hex_buf.c_str());
        }
        else{
            extract_asscii_str(recv_buf, alloc_recv_buf_len);
            //char * ascii_buf = extract_asscii_str(recv_buf, recv_buf_len);

            //std::string hex_buf = to_hex_str_buff(recv_buf, recv_buf_len);
            //free(recv_buf);
            if (i == BufferCount - 1)
                sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}>>", recv_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf);
            else
                sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}", recv_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf);
        }
        //free(ascii_buf);
    }
    
    //std::string str(new_str);
    //faros_syscall << "\n RECV =>"  <<"BufferCount: " << BufferCount << ", AfdFlags: " << AfdFlags << ", TdiFlags: " << TdiFlags;
    // faros_syscall.flush();
    
    *buffer_addr = wptr;
    *buffer_size = 8;
    
    return buffer;
#endif
    return NULL;
    

}

/*
typedef struct _AFD_SEND_INFO_UDP {
    PAFD_WSABUF			BufferArray;
    ULONG				BufferCount;
    ULONG				AfdFlags;
#if 1 // timurrrr: based on XP+win7 observation: i#418 
    ULONG				UnknownGap[9];
    ULONG				SizeOfRemoteAddress;
    PVOID				RemoteAddress;
#else
    TDI_REQUEST_SEND_DATAGRAM		TdiRequest;
    TDI_CONNECTION_INFORMATION		TdiConnection;
#endif
} AFD_SEND_INFO_UDP, *PAFD_SEND_INFO_UDP;

RemoteAddress:
struct sockaddr_in{
   short sin_family;
   unsigned short sin_port;
   struct in_addr sin_addr;
   char sin_zero[8];
};


*/

static char * get_afd_send_datagram(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size){

#if defined(TARGET_I386)
   
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_SEND_INFO_UDP
    uint32_t wptr = 0; // Pointer to AFD_WSABUF
    char *buffer = 0;
    
    // Read/Get AFD_SEND_INFO_UDP's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_SEND_INFO_UDP's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
     
    uint32_t BufferCount = 0;
    uint32_t AfdFlags = 0;
    panda_virtual_memory_rw(env, ptr + 4,
                            (uint8_t *) &BufferCount, 4, false);
    panda_virtual_memory_rw(env, ptr + 8,
                            (uint8_t *) &AfdFlags, 4, false);

    // Read/Get AFD_WSABUF's pointer
    panda_virtual_memory_rw(env, ptr,
                                (uint8_t *) &wptr, 4, false);
    uint32_t SizeOfRemoteAddress = 0;
    uint32_t RemoteAddress_p = 0;
   
    panda_virtual_memory_rw(env, ptr + 48,
                                (uint8_t *) &SizeOfRemoteAddress, 4, false);
    panda_virtual_memory_rw(env, ptr + 52,
                                    (uint8_t *) &RemoteAddress_p, 4, false);

    unsigned short family = 0, port = 0;
    panda_virtual_memory_rw(env, RemoteAddress_p,
                                (uint8_t *) &family, 2, false);
    panda_virtual_memory_rw(env, RemoteAddress_p + 2,
                                (uint8_t *) &port, 2, false);
                                
                                
    // Read/Get sa_data
    struct in_addr addr;
    panda_virtual_memory_rw(env, RemoteAddress_p + 4,
                            (uint8_t *) &addr, 4, false);  
    char *ip_adress = inet_ntoa(addr);
    std::string ip((char *)ip_adress);
    
    //faros_syscall << "\n SEND_UDP =>" << ", family: " <<  family << ", port: " << port << ", ip: " << ip;
    //faros_syscall.flush();                                                                     
    
    
    uint32_t buf_len = 0;
    uint32_t send_buf_len = 0;
    // Calculate how much memory we need to allocate
    for (uint32_t i = 0; i < BufferCount; i++){        
        send_buf_len = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &send_buf_len, 4, false);
        buf_len += send_buf_len;
    }
    buffer = (char *)malloc(MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF);
    if(!buffer){
      	faros_syscall << "\nget_afd_send_datagram: malloc failed! size: " << MAX_EXTRACTED_BUFF*BufferCount*2 + MAX_INFO_BUFF;
        faros_syscall.flush();
        return NULL;
    }  
    if (family == AF_INET)
        sprintf(buffer,"IOCTL_AFD_SEND_DATAGRAM<<family:AF_INET@port:%d@ipAddress:%s@BufferCount:%d@AfdFlags:%d", port, ip_adress, BufferCount, AfdFlags);
    else
        sprintf(buffer,"IOCTL_AFD_SEND_DATAGRAM<<family:%d@port:%d@ipAddress:%s@BufferCount:%d@AfdFlags:%d", family, port, ip_adress, BufferCount, AfdFlags);       

    for (uint32_t i = 0; i < BufferCount; i++){
        
        send_buf_len = 0;
        uint32_t buf_p = 0;
        // Read/Get buf's len
        panda_virtual_memory_rw(env, wptr + 8*i,
                                (uint8_t *) &send_buf_len, 4, false);
        // Read/Get buf's pointer
        panda_virtual_memory_rw(env, wptr + 8*i + 4,
                                (uint8_t *) &buf_p, 4, false);
        uint32_t alloc_send_buf_len = 0;
        if (send_buf_len > MAX_MEM_SIZE)
            alloc_send_buf_len = MAX_MEM_SIZE;
        else
            alloc_send_buf_len = send_buf_len;  
        //char *send_buf = (char *)malloc(send_buf_len);
        // Read/Get buf's content
        panda_virtual_memory_rw(env, buf_p,
                            (uint8_t *) send_buf, alloc_send_buf_len, false);
       
        //char * ascii_buf = extract_asscii_str(send_buf, send_buf_len);
        if(send_buf_len < 1000){
            std::string hex_buf = to_hex_str_buff(send_buf, send_buf_len);
            sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d hexContent:{%s}", send_buf_len, send_buf_len, i+1, hex_buf.c_str());
        }
        else{
            extract_asscii_str(send_buf, alloc_send_buf_len);
            //std::string hex_buf = to_hex_str_buff(send_buf, send_buf_len);
            //free(send_buf);
            if (i == BufferCount - 1)
                sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}>>", send_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf);
            else
                sprintf(buffer + strlen(buffer) ,"@OrgBufLen:%d@AsciiBufLen:%d@AsciiBuf #%d Content:{%s}", send_buf_len, (uint32_t)strlen(ascii_out_buf), i+1, ascii_out_buf);
        }
        //free(ascii_buf);
    }
    
    //std::string str(new_str);
    //faros_syscall << "\n SEND =>"  <<"BufferCount: " << BufferCount << ", AfdFlags: " << AfdFlags << ", TdiFlags: " << TdiFlags;
    //faros_syscall.flush();
    
    *buffer_addr = wptr;
    *buffer_size = 8;
    
    return buffer;
#endif
    return NULL;

}

/*
typedef struct _MEDIA_SERIAL_NUMBER_DATA {
  ULONG SerialNumberLength;
  ULONG Result;
  ULONG Reserved[2];
  UCHAR SerialNumberData[];
} MEDIA_SERIAL_NUMBER_DATA, *PMEDIA_SERIAL_NUMBER_DATA;
*/

/*static char * get_media_serial_number(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, uint32_t struct_size, uint32_t *buffer_addr, unsigned short *buffer_size){

#if defined(TARGET_I386)
   
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to MEDIA_SERIAL_NUMBER_DATA
    char *buffer = 0;
    
    // Read/Get MEDIA_SERIAL_NUMBER_DATA's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if (ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get MEDIA_SERIAL_NUMBER_DATA's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
    uint32_t SerialNumberLength = 0;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &SerialNumberLength, 4, false);
    uint32_t sptr = 0;
    panda_virtual_memory_rw(env, ptr + 12,
                            (uint8_t *) &sptr, 4, false);

    if (!sptr || !(buffer = (char *)malloc(SerialNumberLength)))
        return 0;
    
    panda_virtual_memory_rw(env, sptr,
                            (uint8_t *) buffer, SerialNumberLength, false);
    
    *buffer_size = SerialNumberLength;
    *buffer_addr = sptr;
    faros_syscall << "\n get_media_serial_number";
    faros_syscall.flush();
    
    return buffer;
#endif
    return NULL;
}*/

/*
IOCTL_STORAGE_GET_DEVICE_NUMBER 0x2d1080
typedef struct _STORAGE_DEVICE_NUMBER {
  DEVICE_TYPE DeviceType;
  ULONG       DeviceNumber;
  ULONG       PartitionNumber;
} STORAGE_DEVICE_NUMBER, *PSTORAGE_DEVICE_NUMBER;
*/

/*static int get_storage_device_number(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, uint32_t struct_size){

#if defined(TARGET_I386)
   
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to STORAGE_DEVICE_NUMBER
    
    // Read/Get STORAGE_DEVICE_NUMBER's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if (ptr == 0)
        return 0;
    *struct_addr = ptr;
    // Read/Get STORAGE_DEVICE_NUMBER's structure content
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return 0;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
    
    uint32_t device_number = 0;
    panda_virtual_memory_rw(env, ptr+4,
                            (uint8_t *) &device_number, 4, false);
    faros_syscall << "\n get_storage_device_number: " << device_number << "-> size: " <<struct_size;
    faros_syscall.flush();                                                                     
    
    return 1;
#endif
    return 0;
}*/



/*
typedef struct _STORAGE_DESCRIPTOR_HEADER {
  DWORD Version;
  DWORD Size;
} STORAGE_DESCRIPTOR_HEADER, *PSTORAGE_DESCRIPTOR_HEADER;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
  DWORD            Version;
  DWORD            Size;
  BYTE             DeviceType;
  BYTE             DeviceTypeModifier;
  BOOLEAN          RemovableMedia;
  BOOLEAN          CommandQueueing;
  DWORD            VendorIdOffset;
  DWORD            ProductIdOffset;
  DWORD            ProductRevisionOffset;
  DWORD            SerialNumberOffset;
  STORAGE_BUS_TYPE BusType;
  DWORD            RawPropertiesLength;
  BYTE             RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;
The data retrieved by IOCTL_STORAGE_QUERY_PROPERTY is reported in the buffer immediately following this structure.
*/

// Copies in to out, but removes leading and trailing whitespace.
void trim(char *out, const char *in)
{
    int i, first, last;
     
    // Find the first non-space character (maybe none).
    first = -1;
    for (i = 0; in[i]; i++)
        if (!isspace((int)in[i])) {
            first = i;
            break;
        }
     
    if (first == -1) {
        // There are no non-space characters.
        out[0] = '\0';
        return;
    }
 
    // Find the last non-space character.
    for (i = strlen(in)-1; i >= first && isspace((int)in[i]); i--);
    last = i;
 
    strncpy(out, in+first, last-first+1);
    out[last-first+1] = '\0';
}
 
// Convenience function for formatting strings from ata_identify_device
void formatdriveidstring(char *out, const char *in, int n)
{
    n = n > 64 ? 64 : n;
    trim(out, in);
}

std::queue<uint32_t> inAddrQueue;
std::queue<uint32_t> outAddrQueue;
#define HARD_DRIVE_ID_SIZE 42

enum types {HARD_DRIVE_SERIAL_NUMBER=1, HARD_DRIVE_VERSION};
            
static void get_storage_query_property(CPUState* env, uint32_t *addr, uint32_t *size, uint32_t *type){

#if defined(TARGET_I386)

    if (inAddrQueue.empty() || outAddrQueue.empty())
        return NULL;
    uint32_t inAddr = inAddrQueue.front();
    uint32_t outAddr = outAddrQueue.front();
    inAddrQueue.pop();
    outAddrQueue.pop();
    
    char *buffer = 0;
    // Read/Get MEDIA_SERIAL_NUMBER_DATA's pointer
    if (inAddr == 0 || outAddr == 0)
        return NULL;
    //faros_syscall << ">> outAddr2: " << ptrOut << "\n";
    uint8_t PropertyId = 0, QueryType = 0;
    panda_virtual_memory_rw(env, inAddr,
                            (uint8_t *) &PropertyId, 1, false);
    panda_virtual_memory_rw(env, inAddr + 1,
                            (uint8_t *) &QueryType, 1, false);
    //faros_syscall << "\n get_storage_query_property: PropertyId: " << (int)PropertyId << "-> QueryType: " << (int)QueryType;
    //faros_syscall.flush();

    // Read/Get STORAGE_DEVICE_DESCRIPTOR's structure content
    if (PropertyId == 0){
       char serialNumber[HARD_DRIVE_ID_SIZE], out[HARD_DRIVE_ID_SIZE];
       uint32_t SerialNumberOffset = 0, size = 0;
       panda_virtual_memory_rw(env, outAddr + 4, (uint8_t *) &size, 4, false);
       panda_virtual_memory_rw(env, outAddr + 0x18, (uint8_t *) &SerialNumberOffset, 4, false);
       if (SerialNumberOffset){
           panda_virtual_memory_rw(env, outAddr + SerialNumberOffset, (uint8_t *) serialNumber, HARD_DRIVE_ID_SIZE, false);
           serialNumber[HARD_DRIVE_ID_SIZE-1] = '\0';
           formatdriveidstring(out, serialNumber, HARD_DRIVE_ID_SIZE);
           faros_syscall << "\n get_storage_query_property: serialNumber: " << out << ": offset: " << SerialNumberOffset << " size: " << size << "\n";
           faros_syscall.flush();
       }
    }                    
    *addr = outAddr + SerialNumberOffset;
    *size = HARD_DRIVE_ID_SIZE;
    *type = HARD_DRIVE_SERIAL_NUMBER;
#endif

}


void get_DeviceIoControlFile_out_buffer (CPUState* env, uint32_t *addr, uint32_t *size, uint32_t *type, uint32_t ioControlCode) {
#if defined(TARGET_I386)

    switch(ioControlCode){ 
        //case 73755: //0x1201b 0x1b200100 : GET_MAC_ADDRESS
        /*case 2952208: // 0x2d0c10 : IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER
            faros_syscall << "\n IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER";
            faros_syscall.flush(); 
            return get_media_serial_number(env, argnum, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 2953344: // 0x2d1080 : IOCTL_STORAGE_GET_DEVICE_NUMBER
            faros_syscall << "\n IOCTL_STORAGE_GET_DEVICE_NUMBER";
            faros_syscall.flush(); 
            get_storage_device_number(env, argnum, struct_content, struct_addr, struct_size);
            break;
        case 458820: // 0x70044 : IOCTL_DISK_CONTROLLER_NUMBER
            faros_syscall << "\n IOCTL_DISK_CONTROLLER_NUMBER";
            faros_syscall.flush();
            break;    
        case 458992: // 0x700f0 :  IOCTL_DISK_GET_DISK_ATTRIBUTES
            faros_syscall << "\n  IOCTL_DISK_GET_DISK_ATTRIBUTES";
            faros_syscall.flush();
            break;*/
        case 2954240: // 0x2d1400 :  IOCTL_STORAGE_QUERY_PROPERTY
            faros_syscall << "\n  IOCTL_STORAGE_QUERY_PROPERTY";
            faros_syscall.flush();
            get_storage_query_property(env, addr, size, type);
        default:
            faros_syscall << "\n  Unknown: " << ioControlCode;
            faros_syscall.flush();
    }

#endif

}

#define NO_IOCTL_CODES 764
std::string ioctl_table[NO_IOCTL_CODES][2];
int loaded = 0;

int load_ioctl_table(){
    
    if(loaded)
        return 0;
    std::ifstream theFile ("ioctl_table.csv");
    int i = 0 ;
    std::string line;
    while(std::getline(theFile, line))
    {
        std::string ioctl_name,ioctl_code;
        std::stringstream ss(line);

        std::getline(ss, ioctl_name, ',');
        ioctl_table[i][0] = ioctl_name;

        std::getline(ss, ioctl_code, ',');
        ioctl_code.erase (0,2); // remove 0x
        ioctl_table[i][1] = ioctl_code;
        faros_syscall << "\nname: " <<  ioctl_table[i][0];
        faros_syscall << "  code: " << ioctl_table[i][1];faros_syscall.flush();
        i++;
    }
    loaded = 1;

    return 1;
}

std::string get_ioctl_name(uint32_t ioctl_code){
    std::string str = std::string();//empty string
    load_ioctl_table();
    //    return str;
    for(int i = 0; i < NO_IOCTL_CODES; i++){
        uint32_t ioctl_code_decimal = (uint32_t)strtol(ioctl_table[i][1].c_str(), NULL, 16); 

        //sscanf(ioctl_table[i][1].c_str(), "%x", &ioctl_code_decimal);
        faros_syscall << "\n get_ioctl_name: " << ioctl_code_decimal;faros_syscall.flush(); 
        if(ioctl_code_decimal == ioctl_code)
            return ioctl_table[i][0];
    }
    return str;
}



/* <MN FAROS> */
static char * get_win_syscall_arg_struct_afd_info (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size, uint32_t io_control_code){//, char *buffer) {
#if defined(TARGET_I386)
    char *buffer = NULL;
    switch(io_control_code){
        case 2954240:{ // 0x2d1400 : IOCTL_STORAGE_QUERY_PROPERTY
            uint32_t inAddr = 0, outAddr = 0;
            panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*8),
                            (uint8_t *) &outAddr, 4, false);
            panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*6),
                            (uint8_t *) &inAddr, 4, false);
            inAddrQueue.push(inAddr);
            outAddrQueue.push(outAddr);
            break;
        }
        default:
            faros_syscall << "\n unknown ioctl: " << io_control_code;
            return NULL;
            
        /*case 73731: // 0x12003 : IOCTL_AFD_BIND 
            return get_afd_bind_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73739: // 0x1200b : IOCTL_AFD_START_LISTEN 
            return get_afd_listen_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);           
        case 73735: // 0x12007 : IOCTL_AFD_CONNECT 
            return get_afd_connect_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73744: // 0x12010 : IOCTL_AFD_ACCEPT 
            return get_afd_accept_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73751: // 0x12017 : IOCTL_AFD_RECV 
            return get_afd_recv_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73759: // 0x1201f : IOCTL_AFD_SEND 
            return get_afd_send_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);            
        case 73863: // 0x12087 : IOCTL_AFD_EVENT_SELECT 
            return get_afd_event_select_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);            
        case 73771: // 0x1202b : IOCTL_AFD_DISCONNECT 
            return get_afd_disconnect_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73867: // 0x1208b : IOCTL_AFD_ENUM_NETWORK_EVENTS_INFO 
            return get_afd_network_events_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
       //TO DO:
        case 73755: // 0x1201b : IOCTL_AFD_RECV_DATAGRAM
            //sprintf(buffer,"%s","IOCTL_AFD_RECV_DATAGRAM<<>>");
            //break;           
            return get_afd_recv_datagram(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73763: // 0x12023 : IOCTL_AFD_SEND_DATAGRAM
            //sprintf(buffer,"%s","IOCTL_AFD_SEND_DATAGRAM<<>>");
            //break;
            return get_afd_send_datagram(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73764: // 0x12024 : IOCTL_AFD_SELECT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_SELECT<<>>");
            break;
            //return get_afd_select_data(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 73851: // 0x1207b : IOCTL_AFD_GET_INFO
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_GET_INFO<<>>");
            break;
            //return get_afd_get_info(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73787: // 0x1203b : IOCTL_AFD_SET_INFO
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_SET_INFO<<>>");
            break;
            //return get_afd_set_info(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73799: // 0x12047 : IOCTL_AFD_SET_CONTEXT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_SET_CONTEXT<<>>");
            break;
            //return get_afd_set_context(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73919: // 0x120bf : IOCTL_AFD_DEFER_ACCEPT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_DEFER_ACCEPT<<>>");
            break;
            //return get_afd_defer_accept(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 73775: // 0x1202f : IOCTL_AFD_GET_SOCK_NAME
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_GET_SOCK_NAME<<>>");
            break; 
            //return get_afd_get_sock_name(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 315400: // 0x4d008 : IOCTL_SCSI_MINIPORT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_SCSI_MINIPORT<<>>");
            break;
            //return get_scsi_miniport(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 315412: // 0x4d014 : IOCTL_SCSI_PASS_THROUGH_DIRECT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_SCSI_PASS_THROUGH_DIRECT<<>>");
            break; 
            //return get_cssi_pass_through_direct(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 458752: // 0x70000 : IOCTL_DISK_GET_DRIVE_GEOMETRY
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_DISK_GET_DRIVE_GEOMETRY<<>>");
            break;
            //return get_disk_get_drive_geometry(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 458912: // 0x700a0 : IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_DISK_GET_DRIVE_GEOMETRY_EX<<>>");
            break;
            //return get_disk_get_drive_geometry_ex(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 475228: // 0x7405c : IOCTL_DISK_GET_LENGTH_INFO
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_DISK_GET_LENGTH_INFO<<>>");
            break;
            //return get_disk_get_length_info(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 589848: // 0x90018 : FSCTL_LOCK_VOLUME
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","FSCTL_LOCK_VOLUME<<>>");
            break;
            //return get_lock_volume(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 589852: // 0x9001c : FSCTL_UNLOCK_VOLUME
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","FSCTL_UNLOCK_VOLUME<<>>");
            break;
            //return get_fsctl_unlock_volume(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 589992: // 0x900a8 : FSCTL_GET_REPARSE_POINT
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","FSCTL_GET_REPARSE_POINT<<>>");
            break;
            //return get_fsctl_get_reparse_point(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 2952208: // 0x2d0c10 : IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER<<>>");
            break;
            //return get_storage_get_media_serial_number(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 2953344: // 0x2d1080 : IOCTL_STORAGE_GET_DEVICE_NUMBER
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_STORAGE_GET_DEVICE_NUMBER<<>>");
            break;
            //return get_storage_get_device_number(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);

            //return get_storage_query_property(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
         case 3768320: // 0x398000 : IOCTL_KSEC_REGISTER_LSA_PROCESS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_REGISTER_LSA_PROCESS<<>>");
            break;
            //return get_ksec_register_lsa_process(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735556: // 0x390004 : IOCTL_KSEC_1
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_1<<>>");
            break;
            //return get_ksec_1(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735560: // 0x390008 : IOCTL_KSEC_RANDOM_FILL_BUFFER
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_AFD_GET_SOCK_NAME<<>>");
            break;
            //return get_ksec_random_fill_buffer(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 3735566: // 0x39000e : IOCTL_KSEC_ENCRYPT_PROCESS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_ENCRYPT_PROCESS<<>>");
            break;
            //return get_ksec_encrypt_process(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735570: // 0x390012 : IOCTL_KSEC_DECRYPT_PROCESS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_DECRYPT_PROCESS<<>>");
            break;
            //return get_ksec_decrypt_process(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735574: // 0x390016 : IOCTL_KSEC_ENCRYPT_CROSS_PROCESS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_ENCRYPT_CROSS_PROCESS<<>>");
            break;
            //return get_ksec_encrypt_cross_process(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735578: // 0x39001a : IOCTL_KSEC_DECRYPT_CROSS_PROCESS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_DECRYPT_CROSS_PROCESS<<>>");
            break;
            //return get_ksec_decrypt_cross_process(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 3735582: // 0x39001e : IOCTL_KSEC_ENCRYPT_SAME_LOGON
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_ENCRYPT_SAME_LOGON<<>>");
            break;
            //return get_ksec_encrypt_same_logon(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 3735586: // 0x390022 : IOCTL_KSEC_DECRYPT_SAME_LOGON
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_DECRYPT_SAME_LOGON<<>>");
            break;
            //return get_ksec_decrypt_same_logon(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);        
        case 3735608: // 0x390038 : IOCTL_KSEC_REGISTER_EXTENSION
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_KSEC_REGISTER_EXTENSION<<>>");
            break;
            //return get_ksec_register_extension(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 5046280: // 0x4d0008 : IOCTL_MOUNTDEV_QUERY_DEVICE_NAME
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_MOUNTDEV_QUERY_DEVICE_NAME<<>>");
            break;
            //return get_mountdev_query_device_name(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 5636096: // 0x560000 : IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS<<>>");
            break;
            //return get_volume_get_volume_disk_extents(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 7143432: // 0x6d0008 : IOCTL_MOUNTMGR_QUERY_POINTS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_MOUNTMGR_QUERY_POINTS<<>>");
            break;
            //return get_mountmgr_query_points(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);
        case 7143472: // 0x6d0030 : IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH<<>>");
            break;
            //return get_mountmgr_query_dos_volume_path(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size);   
        case 7143476: // 0x6d0034 : IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS
            buffer = (char *)malloc(50);
            sprintf(buffer,"%s","IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS<<>>");
            break;*/
            //return get_mountmgr_query_dos_volume_paths(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size); 

    }
    uint32_t ptr = 0;
    // Read/Get AFD_SEND_INFO_UDP's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    *struct_content = malloc(struct_size);
    if(*struct_content == NULL)
        return NULL;
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) *struct_content, struct_size, false);
                            
    *buffer_addr = 0;
    *buffer_size = 0;
    return buffer;
    /*
    // At sysenter on Windows7, args start at EDX+8
    uint32_t ptr = 0;  // Pointer to AFD_INFO
    uint32_t sptr = 0; // Pointer to AFD_WSABUF
    
    //char afd_wsabuf[8];
    uint32_t afd_wsabuf_len = 0;
    uint32_t afd_wsabuf_address = 0;
    char *buffer = 0;
    
    // Read/Get AFD_INFO's pointer
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &ptr, 4, false);
    if( ptr == 0)
        return NULL;
    *struct_addr = ptr;
    // Read/Get AFD_INFO's structure content
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) struct_content, struct_size, false);
    // Read/Get AFD_WSABUF's pointer
    panda_virtual_memory_rw(env, ptr,
                            (uint8_t *) &sptr, 4, false);
    if( sptr == 0)
        return NULL;
    // Read/Get AFD_WSABUF's buffer's len
    panda_virtual_memory_rw(env, sptr,
                            (uint8_t *) &afd_wsabuf_len, 4, false);
    
    faros_syscall << "\n afd_len: " << afd_wsabuf_len;
    faros_syscall.flush();    


    if (afd_wsabuf_len == 0)
        return NULL;
    // Read/Get AFD_WSABUF's buffer's address
    panda_virtual_memory_rw(env, sptr + 4,
                            (uint8_t *) &afd_wsabuf_address, 4, false);

    if (!afd_wsabuf_address)
        return NULL;
    //gchar *buffer = (gchar *)g_malloc0(afd_wsabuf_len);
    buffer = (char *)malloc(afd_wsabuf_len+1);
   // if (!buffer)
   //     return NULL;
    // Read/Get AFD_WSABUF's buffer's content
    panda_virtual_memory_rw(env, afd_wsabuf_address,
                            (uint8_t *) buffer, afd_wsabuf_len, false);
    //((char *)buffer + afd_wsabuf_len) = '\0'; 
    buffer[afd_wsabuf_len] = '\0';
    
    std::string str((char *)buffer);    
    faros_syscall << "\n afd_info: " << str;
    faros_syscall.flush();    

    *buffer_addr = afd_wsabuf_address;
    *buffer_size = afd_wsabuf_len;
    
    return buffer;*/
#endif
    return NULL;
}



/* <MN FAROS> */
static char * get_win_syscall_arg_struct_unicode_str (CPUState* env, int nr, void **struct_content,/*struct OBJ_ATTRIBUTES *attr){*/uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t uptr = 0; // Pointer to _UNICODE_STRING
    char *obj_name;
    
    // Read/Get _UNICODE_STRING's pointer content
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &uptr, 4, false);
    
    if (uptr == 0) // Return if the structure is empty
        return NULL;
    
    // Read/Get _UNICODE_STRING's wstring size
    panda_virtual_memory_rw(env, uptr,
                            (uint8_t *) ustr_size, 2, false);
    
    if(*ustr_size == 0)
        return NULL;
    
    *struct_size = 8;
    *struct_content = malloc(*struct_size);
    if(*struct_content == NULL)
        return NULL;
    
    // Read/Get _UNICODE_STRING's content
    panda_virtual_memory_rw(env, uptr,
                            (uint8_t *) *struct_content, *struct_size, false);
   
    // Get the unicode string and convert it to char *
    obj_name = get_unicode_str(env, uptr);
    
    /*std::string str((char *)obj_name);
    
    faros_syscall << "\n str: " << str;
    faros_syscall.flush();*/
    
    *struct_addr = env->regs[R_EDX] + 8 + (4*nr);
    *ustr_addr = uptr;
    
    return obj_name;
#endif
    return NULL;
}

/* <MN FAROS> */
char * get_wstr(CPUState *env, PTR ustr_ptr, uint32_t ustr_size) {
    
    gchar *in_str = (gchar *)g_malloc0(ustr_size);
    if (-1 == panda_virtual_memory_rw(env, ustr_ptr, (uint8_t *)in_str, ustr_size, false)) {
        g_free(in_str);
        return NULL;//make_pagedstr(); 
    }

    GError *error = NULL;
    
    gsize bytes_written = 0;
     if(in_str == NULL || ustr_size == 0){
           // faros_syscall << "\n wstr error: str is NULL!" ;
           // faros_syscall.flush();
            return NULL;
    }
    gchar *out_str = g_convert(in_str, ustr_size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, &error);

    if(error){
        std::string str(error->message);
        faros_syscall << "\n wstr error: " << str ;
        faros_syscall.flush();
        return NULL;
    }
    
    if(out_str == NULL){
        faros_syscall << "\n wstr error: out_str == NULL";
        faros_syscall.flush();
        return NULL;
    }
    // An abundance of caution: we copy it over to something allocated
    // with our own malloc. In the future we need to provide a way for
    // someone else to free the memory allocated in here...
    char *ret = (char *)malloc(bytes_written+1);
    memcpy(ret, out_str, bytes_written+1);
    g_free(in_str);
    g_free(out_str);
    return ret;
}   

/* <MN FAROS> */
static char * get_win_syscall_arg_wstr(CPUState* env, uint32_t arg_no, uint32_t *pointer_value, uint32_t *pointer_addr, uint32_t ustr_size){
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    char *ustr; // WSTR
    
    // Read/Get PWSTR's pointer content
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*arg_no),
                            (uint8_t *) pointer_value, 4, false);
    
    if (*pointer_value == 0) // Return if the string is empty
        return NULL;
     
    ustr = get_wstr(env, *pointer_value, ustr_size);
    
    *pointer_addr = env->regs[R_EDX] + 8 + (4*arg_no);
    //*ustr_addr = uptr;
    
    return ustr;
#endif
    return NULL;

}

uint32_t get_32_linux_x86 (CPUState *env, uint32_t argnum) {
    assert (argnum < 6);
    return (uint32_t) get_linux_x86_argnum(env, argnum);
}
uint32_t get_32_linux_arm (CPUState *env, uint32_t argnum) {
    assert (argnum < 7);
    return (uint32_t) env->regs[argnum];
}

/* <MN FAROS> */
uint32_t get_32_windows_x86_pointer (CPUState *env, uint32_t argnum, void **buffer, uint32_t len, uint32_t *pointer_addr) {
    return get_win_syscall_arg_pointer(env, argnum, buffer, len, pointer_addr);
}

/* <MN FAROS> */
char * get_32_windows_x86_struct_obj_attr (CPUState* env, int argnum, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
    return get_win_syscall_arg_struct_obj_attr(env, argnum, struct_content, struct_addr, struct_size, ustr_addr, ustr_size);
}

/* <MN FAROS> */
char * get_32_windows_x86_struct_afd_info (CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size,uint32_t io_control_code) {
    return get_win_syscall_arg_struct_afd_info (env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size, io_control_code);
}

/* <MN FAROS> */
char * get_32_windows_x86_struct_unicode_str (CPUState* env, int argnum, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
    return get_win_syscall_arg_struct_unicode_str(env, argnum, struct_content, struct_addr, struct_size, ustr_addr, ustr_size);
}

/* <MN FAROS> */
char * get_32_windows_x86_wstr (CPUState* env, uint32_t arg_no, uint32_t *pointer_value, uint32_t *pointer_addr, uint32_t ustr_size) {
    return get_win_syscall_arg_wstr(env, arg_no, pointer_value, pointer_addr, ustr_size);
}

/* <MN FAROS> */
void get_32_windows_x86_DeviceIoControlFile_out_buffer (CPUState* env, uint32_t *addr, uint32_t *size, uint32_t *type, uint32_t ioControlCode) {
    return get_DeviceIoControlFile_out_buffer(env, addr, size, type, ioControlCode);
}

uint32_t get_32_windows_x86 (CPUState *env, uint32_t argnum) {
    return (uint32_t) get_win_syscall_arg(env, argnum);
}

uint64_t get_64_linux_x86(CPUState *env, uint32_t argnum) {
    assert (argnum < 6);
    return (((uint64_t) get_linux_x86_argnum(env, argnum)) << 32) | (get_linux_x86_argnum(env, argnum));
}

uint64_t get_64_linux_arm(CPUState *env, uint32_t argnum) {
    assert (argnum < 7);
    return (((uint64_t) env->regs[argnum]) << 32) | (env->regs[argnum+1]);
}

uint64_t get_64_windows_x86(CPUState *env, uint32_t argnum) {
    assert (false && "64-bit arguments not supported on Windows 7 x86");
    return 0;
}

// Argument getting (at syscall return)
static uint32_t get_win_syscall_return_arg(CPUState* env, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t arg = 0;
    panda_virtual_memory_rw(env, ESP + 4 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#else
    return 0;
#endif
}

uint32_t get_return_32_windows_x86 (CPUState *env, uint32_t argnum) {
    return get_win_syscall_return_arg(env, argnum);
}

uint64_t get_return_64_windows_x86(CPUState *env, uint32_t argnum) {
    assert (false && "64-bit arguments not supported on Windows 7 x86");
}

enum ProfileType {
    PROFILE_LINUX_X86,
    PROFILE_LINUX_ARM,
    PROFILE_WINDOWSXP_SP2_X86,
    PROFILE_WINDOWSXP_SP3_X86,
    PROFILE_WINDOWS7_X86,
    PROFILE_LAST
};

struct Profile {
    void         (*enter_switch)(CPUState *, target_ulong);
    void         (*return_switch)(CPUState *, target_ulong, target_ulong, ReturnPoint &);
    target_long  (*get_return_val )(CPUState *);
    target_ulong (*calc_retaddr )(CPUState *, target_ulong);
    uint32_t     (*get_32 )(CPUState *, uint32_t);
    int32_t      (*get_s32)(CPUState *, uint32_t);
    uint64_t     (*get_64)(CPUState *, uint32_t);
    int64_t      (*get_s64)(CPUState *, uint32_t);
    target_ulong (*get_pointer)(CPUState *, uint32_t);
    uint32_t	 (*get_pointer_buffer)(CPUState *, uint32_t, void **, uint32_t, uint32_t *);/* <MN FAROS> */
    char *       (*get_struct_obj_attr)(CPUState*, int, void **, uint32_t *, unsigned long *, uint32_t *, unsigned short *);/* <MN FAROS> */
    char *       (*get_struct_unicode_str)(CPUState*, int, void **, uint32_t *, unsigned long *, uint32_t *, unsigned short *);/* <MN FAROS> */
    char *       (*get_wstr)(CPUState*, uint32_t, uint32_t *, uint32_t *, uint32_t);/* <MN FAROS> */
    char *       (*get_struct_afd_info)(CPUState*, int, void **, uint32_t *, unsigned long, uint32_t *, uint32_t *, uint32_t io_control_code);/* <MN FAROS> */
    void         (*get_DeviceIoControlFile_out_buffer)(CPUState*, uint32_t *, uint32_t *, uint32_t *, uint32_t);/* <MN FAROS> */
    uint32_t     (*get_return_32 )(CPUState *, uint32_t);
    int32_t      (*get_return_s32)(CPUState *, uint32_t);
    uint64_t     (*get_return_64)(CPUState *, uint32_t);
    int64_t      (*get_return_s64)(CPUState *, uint32_t);
    target_ulong (*get_return_pointer)(CPUState *, uint32_t);
};

Profile profiles[PROFILE_LAST] = {
    {
        .enter_switch = syscall_enter_switch_linux_x86,
        .return_switch = syscall_return_switch_linux_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_linux_x86,
        .get_32 = get_32_linux_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_x86,
        .get_s64 = get_s64_generic,
        .get_pointer = get_pointer_32bit,
	    .get_pointer_buffer = NULL, /* <MN FAROS> */
	    .get_struct_obj_attr = NULL, /* <MN FAROS> */
	    .get_struct_unicode_str = NULL, /* <MN FAROS> */
	    .get_wstr = NULL, /* <MN FAROS> */
	    .get_struct_afd_info = NULL, /* <MN FAROS> */
	    .get_DeviceIoControlFile_out_buffer = NULL,/* <MN FAROS> */
        .get_return_32 = get_32_linux_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_x86,
        .get_return_s64 = get_return_s64_generic,
        .get_return_pointer = get_pointer_32bit
    },
    {
        .enter_switch = syscall_enter_switch_linux_arm,
        .return_switch = syscall_return_switch_linux_arm,
        .get_return_val = get_return_val_arm,
        .calc_retaddr = calc_retaddr_linux_arm,
        .get_32 = get_32_linux_arm,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_arm,
        .get_s64 = get_s64_generic,
        .get_pointer = get_pointer_32bit,
        .get_pointer_buffer = NULL, /* <MN FAROS> */
        .get_struct_obj_attr = NULL, /* <MN FAROS> */
        .get_struct_unicode_str = NULL, /* <MN FAROS> */
        .get_wstr = NULL, /* <MN FAROS> */
        .get_struct_afd_info = NULL, /* <MN FAROS> */
        .get_DeviceIoControlFile_out_buffer = NULL,/* <MN FAROS> */
        .get_return_32 = get_32_linux_arm,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_arm,
        .get_return_s64 = get_return_s64_generic,
        .get_return_pointer = get_pointer_32bit
    },
    {
        .enter_switch = syscall_enter_switch_windowsxp_sp2_x86,
        .return_switch = syscall_return_switch_windowsxp_sp2_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_pointer = get_pointer_32bit,
        .get_pointer_buffer = NULL, /* <MN FAROS> */
        .get_struct_obj_attr = NULL, /* <MN FAROS> */
        .get_struct_unicode_str = NULL, /* <MN FAROS> */
        .get_wstr = NULL, /* <MN FAROS> */
        .get_struct_afd_info = NULL, /* <MN FAROS> */
        .get_DeviceIoControlFile_out_buffer = NULL,/* <MN FAROS> */
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
        .get_return_pointer = get_return_pointer_32bit
    },
    {
        .enter_switch = syscall_enter_switch_windowsxp_sp3_x86,
        .return_switch = syscall_return_switch_windowsxp_sp3_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_pointer = get_pointer_32bit,
        .get_pointer_buffer = NULL, /* <MN FAROS> */
        .get_struct_obj_attr = NULL, /* <MN FAROS> */
        .get_struct_unicode_str = NULL, /* <MN FAROS> */
        .get_wstr = NULL, /* <MN FAROS> */
        .get_struct_afd_info = NULL, /* <MN FAROS> */
        .get_DeviceIoControlFile_out_buffer = NULL,/* <MN FAROS> */
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
        .get_return_pointer = get_return_pointer_32bit
    },
    {
        .enter_switch = syscall_enter_switch_windows7_x86,
        .return_switch = syscall_return_switch_windows7_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_pointer = get_pointer_32bit,
        .get_pointer_buffer = get_32_windows_x86_pointer, /* <MN FAROS> */
        .get_struct_obj_attr = get_32_windows_x86_struct_obj_attr, /* <MN FAROS> */
        .get_struct_unicode_str = get_32_windows_x86_struct_unicode_str, /* <MN FAROS> */
        .get_wstr = get_32_windows_x86_wstr, /* <MN FAROS> */
        .get_struct_afd_info = get_32_windows_x86_struct_afd_info, /* <MN FAROS> */
        .get_DeviceIoControlFile_out_buffer = get_32_windows_x86_DeviceIoControlFile_out_buffer,/* <MN FAROS> */
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
        .get_return_pointer = get_return_pointer_32bit
    }
};

Profile *syscalls_profile;

// Wrappers
target_long  get_return_val (CPUState *env) {
    return syscalls_profile->get_return_val(env);
}
target_ulong calc_retaddr (CPUState *env, target_ulong pc) {
    return syscalls_profile->calc_retaddr(env, pc);
}
uint32_t get_32(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_32(env, argnum);
}
int32_t get_s32(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_s32(env, argnum);
}
uint64_t get_64(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_64(env, argnum);
}
int64_t get_s64(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_s64(env, argnum);
}
target_ulong get_pointer(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_pointer(env, argnum);
}

/* <MN FAROS> */
uint32_t get_pointer_buffer_32(CPUState *env, uint32_t argnum, void **buffer, uint32_t len, uint32_t *pointer_addr) {
    return syscalls_profile->get_pointer_buffer(env, argnum, buffer, len, pointer_addr);
}

/* <MN FAROS> */
char * get_struct_obj_attr_32(CPUState* env, int argnum, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
    return syscalls_profile->get_struct_obj_attr(env, argnum, struct_content, struct_addr, struct_size, ustr_addr, ustr_size);
}

/* <MN FAROS> */
char * get_struct_unicode_str_32(CPUState* env, int argnum, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size) {
    return syscalls_profile->get_struct_unicode_str(env, argnum, struct_content, struct_addr, struct_size, ustr_addr, ustr_size);
}

/* <MN FAROS> */
char * get_wstr_32(CPUState* env, uint32_t arg_no, uint32_t *pointer_value, uint32_t *pointer_addr, uint32_t ustr_size) {
    return syscalls_profile->get_wstr(env, arg_no, pointer_value, pointer_addr, ustr_size);
}

/* <MN FAROS> */
char * get_struct_afd_info_32(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size, uint32_t io_control_code) {
    return syscalls_profile->get_struct_afd_info(env, nr, struct_content, struct_addr, struct_size, buffer_addr, buffer_size, io_control_code);
}


/* <MN FAROS> */
void get_DeviceIoControlFile_out_buffer_32 (CPUState* env, uint32_t *addr, uint32_t *size, uint32_t *type, uint32_t ioControlCode) {
    return syscalls_profile->get_DeviceIoControlFile_out_buffer(env, addr, size, type, ioControlCode);
}

uint32_t get_return_32 (CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_return_32(env, argnum);
}
int32_t get_return_s32(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_return_s32(env, argnum);
}
uint64_t get_return_64(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_return_64(env, argnum);
}
int64_t get_return_s64(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_return_s64(env, argnum);
}
target_ulong get_return_pointer(CPUState *env, uint32_t argnum) {
    return syscalls_profile->get_return_pointer(env, argnum);
}

target_ulong get_pointer_32bit(CPUState *env, uint32_t argnum) {
    return (target_ulong) get_32(env, argnum);
}

target_ulong get_pointer_64bit(CPUState *env, uint32_t argnum) {
    return (target_ulong) get_64(env, argnum);
}

target_ulong get_return_pointer_32bit(CPUState *env, uint32_t argnum) {
    return (target_ulong) get_return_32(env, argnum);
}

target_ulong get_return_pointer_64bit(CPUState *env, uint32_t argnum) {
    return (target_ulong) get_return_64(env, argnum);
}

int32_t get_s32_generic(CPUState *env, uint32_t argnum) {
    return (int32_t) get_32(env, argnum);
}

int64_t get_s64_generic(CPUState *env, uint32_t argnum) {
    return (int64_t) get_64(env, argnum);
}

int32_t get_return_s32_generic(CPUState *env, uint32_t argnum) {
    return (int32_t) get_return_32(env, argnum);
}

int64_t get_return_s64_generic(CPUState *env, uint32_t argnum) {
    return (int64_t) get_return_64(env, argnum);
}

std::vector<void (*)(CPUState*, target_ulong)> preExecCallbacks;

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong)){
    preExecCallbacks.push_back(callback);
}

// always return to same process
static std::map < std::pair < target_ulong, target_ulong >, ReturnPoint > returns; 

void appendReturnPoint(ReturnPoint &rp){
    returns[std::make_pair(rp.retaddr,rp.proc_id)] = rp;
}


static int returned_check_callback(CPUState *env, TranslationBlock* tb){
    // check if any of the internally tracked syscalls has returned
    // only one should be at its return point for any given basic block
    std::pair < target_ulong, target_ulong > ret_key = std::make_pair(tb->pc, panda_current_asid(env));
    if (returns.count(ret_key) != 0) {
        ReturnPoint &retVal = returns[ret_key];
        syscalls_profile->return_switch(env, tb->pc, retVal.ordinal, retVal);
        // used by remove_if to delete from returns list those values
        // that have been processed
        //        retVal.retaddr = retVal.proc_id = 0;
        returns.erase(ret_key);
    }
    
    return false;
}


// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
    // run any code we need to update our state
    for(const auto callback : preExecCallbacks){
        callback(env, pc);
    }
    syscalls_profile->enter_switch(env, pc);
    return 0;
}

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
#if defined(TARGET_I386)
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        return true;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        return true;
    }
    else {
        return false;
    }
#elif defined(TARGET_ARM)
    unsigned char buf[4] = {};

    // Check for ARM mode syscall
    if(env->thumb == 0) {
        panda_virtual_memory_rw(env, pc, buf, 4, 0);
        // EABI
        if ( ((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ) {
            return true;
        }
#if defined(CAPTURE_ARM_OABI)
        else if (((buf[3] & 0x0F) == 0x0F)  && (buf[2] == 0x90)) {  // old ABI
            return true;
        }
#endif
    }
    else {
        panda_virtual_memory_rw(env, pc, buf, 2, 0);
        // check for Thumb mode syscall
        if (buf[1] == 0xDF && buf[0] == 0){
            return true;
        }
    }
    return false;
#endif
}


extern "C" {

panda_arg_list *args;

bool init_plugin(void *self) {

    printf("Initializing plugin syscalls2\n");

// <MN FAROS: start>
// We make this plugin to be loadable inside faros plugin
    /*args = panda_get_args("syscalls");

    const char *profile_name = panda_parse_string(args, "profile", "linux_x86");
    if (0 == strncmp(profile_name, "linux_x86", 8)) {
        syscalls_profile = &profiles[PROFILE_LINUX_X86];
    }
    else if (0 == strncmp(profile_name, "linux_arm", 8)) {
        syscalls_profile = &profiles[PROFILE_LINUX_ARM];
    }
    else if (0 == strncmp(profile_name, "windowsxp_sp2_x86", 13)) {
        syscalls_profile = &profiles[PROFILE_WINDOWSXP_SP2_X86];
    }
    else if (0 == strncmp(profile_name, "windowsxp_sp3_x86", 13)) {
        syscalls_profile = &profiles[PROFILE_WINDOWSXP_SP3_X86];
    }
    else if (0 == strncmp(profile_name, "windows7_x86", 8)) {
        syscalls_profile = &profiles[PROFILE_WINDOWS7_X86];
    }
    else {
        printf ("Unrecognized profile %s\n", profile_name);
        assert (1==0);
    }*/
    
    // Setting default profile
    syscalls_profile = &profiles[PROFILE_WINDOWS7_X86];

// <MN FAROS: end>   
    faros_syscall.open("syscall2.log", std::ios::out | std::ios::trunc);

// Don't bother if we're not on a supported target
#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    //    pcb.before_block_exec_invalidate_opt = returned_check_callback;
    //   panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.before_block_exec = returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#else
    fwrite(stderr,"The syscalls plugin is not currently supported on this platform.\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void *self) {
    faros_syscall.flush();
    faros_syscall.close();
}
    
}
