/*
 *NOTES:
 *    Physical Write Callbacks seems to fire on qemu_st instructions and not
 *    on the normal st instructions. Writes seem to fire on qemu_ld's not ld's.
 *
 *    Regular ld/st ops are reads/writes to memory/registers on the HOST
 *    while qemu_ld/qemu_st are reads/writes to the GUEST memory.
 *
 *
 *    Looks like PANDA doesn't provide a nice way of instrumenting based on
 *    the TCG code that will be run. Instead you have to choose to intrument
 *    based on the guest machine code to be run. This means we'll need to
 *    handle different ARCHs differently. Not ideal but if that's all we've got...
 *
 */
/*
 * TO-DO List:
 *
 * TODO Properly handle branches, both cond and uncond.
 * TODO Convert shadow memory to use more efficient data structure
 * TODO ifdef guard portions that are arch specific
 *
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdio>
#include <utility> // std:pair
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <vector>
#include <set>
#include <queue>
#include <list>
#include <deque>
#include <algorithm>
#include <cstdint>
#include <thread>         // std::thread
#include <pthread.h>
//PCAP
#include <stdio.h>
#include <stdlib.h>
//#include <pcap/pcap.h>
#include <time.h>
#include <list>
#include "pwnda_funcs.h"

#include "../taint2/taint2.h"
#include "../../rr_log_all.h"


#include "../common/prog_point.h" // for callstack_ins

extern "C" {
#include "tcg.h"
#include "config.h"
#include "monitor.h"
#include "qemu-common.h"
#include "panda_common.h"
#include "panda_plugin.h"

#include "../osi/osi_proc_events.h"
#include "../osi/os_intro.h"
#include "../syscalls2/syscalls2.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../taint2/taint2_ext.h"
#include "panda_plugin_plugin.h" 


#include "../syscalls2/syscalls_common.h"

//#include "net-pcap.h"
#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h" // for callstack_ins

#include <sys/time.h>

#ifndef CONFIG_SOFTMMU
#include "linux-user/syscall_defs.h"
#endif

}


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    int monitor_callback(Monitor *, const char *);
    int before_block_exec(CPUState *, TranslationBlock *);
    int faros_net_recv(CPUState *env, uint64_t dst_addr, uint32_t num_bytes);

}

//extern enum types {MAC_ADDR_LABEL=1, COMPUTER_NAME_LABEL, HOST_NAME_LABEL, 
//            VOLUME_SERIAL_NUMBER, HARD_DRIVE_SERIAL_NUMBER, 
//            HARD_DRIVE_MODEL_NAME, WINDOWS_VERSION, CPU_MODEL, SID_NUMBER};


typedef struct computer_name{
    target_ulong pname;
    target_ulong psize;
}computerName;

typedef struct host_name{
    target_ulong pname;
    uint32_t size;
}hostName;

typedef target_ulong proc_id;

bool taint_enabled = false;
bool log_funcs = false;

#define BASIC_TAINT 1
#define FULL_TAINT  2
#define MAX_PID_LIST_LEN 10
#define MAX_PNAMES_LIST_LEN 100
#define MAX_SYSCALL_NO 100000

typedef struct pid_list{
    uint32_t   pid[MAX_PID_LIST_LEN];
    uint32_t   count;
}pid_list;

typedef struct pname_list{
    std::string   pname[MAX_PNAMES_LIST_LEN];
    uint32_t      count;
}pname_list;

// FAROS plugin input arguments
pid_list pids;                // List of pids specified by user that we should filter the outputs for them
pname_list pnames;              // List of process names specified by user that we should filter the outputs for them
bool     faros_enabled;       // whether FAROS start working at srartup or not

//std::string targetProcess = "" ;//"WMIC.exe";baidubrowser.e

// Output files
std::ofstream faros_log;
std::ofstream taint_log;

ModuleLoader *mod_tag_loader;
uint32_t old_pid = 0;

char out[30000];

bool is_this_process_filtered(char *process_name, uint32_t pname_len){
    
    if (pnames.count == 0)
        return true;
    for (uint32_t i = 0; i < pnames.count; i++)
        if (0 == strncmp(pnames.pname[i].c_str(), process_name, pname_len))
            return true;
    return false;
}

std::string to_hex_str_buff(char *buf, uint32_t size) {
    uint32_t i,j;
    out[0] = '\0';

    if(size >= 10000){
        std::string str_null("");
        return str_null;
    }
    for (i = 0,j = 0; i < size; i++, j++)
        sprintf( out + j*2, "%02X", buf[i]);

    out[j*2] = '\0';

    std::string str(out);    

    return str;
}

int monitor_callback(Monitor *mon, const char *cmd) {
    std::string cmd_str(cmd);

    if (cmd_str == "faros_enable") {
        monitor_printf(mon, "Enabling Faros\n");
        faros_enabled = true;
        //panda_do_flush_tb();
        /*panda_disable_tb_chaining();
        panda_enable_memcb();*/
        //panda_enable_precise_pc();
    } else if (cmd_str == "faros_disable") {
        monitor_printf(mon, "Disabling Faros\n");
        faros_enabled = false;
        //panda_do_flush_tb();
        //panda_disable_precise_pc();
        /*panda_disable_memcb();
        panda_enable_tb_chaining();*/
    } else {
        monitor_printf(mon, "Bad command!\n");
    }
    return 0;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
#if defined(TARGET_I386)
    
    // Skip the kernel because it prints a lot of extra stuff
    if (panda_in_kernel(env)) {
        old_pid = 4;
        return 0;
    }

    // If we haven't seen this asid before load it's exports    
    if (!mod_tag_loader->asid_loaded(panda_current_asid(env))) {
        mod_tag_loader->process_module(env);
        
    }

#endif
    return 0;
}

// Return address calculations
target_ulong calc_retaddr_windows_x86(CPUState* env) {
#if defined(TARGET_I386)
    target_ulong retaddr = 0;
    panda_virtual_memory_rw(env, env->regs[R_EDX], (uint8_t *) &retaddr, 4, false);
    return retaddr;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

#define PTR uint32_t

char * get_wstr(CPUState *env, PTR ustr_ptr, uint32_t ustr_size) {
    
    gchar *in_str = (gchar *)g_malloc0(ustr_size);
    if (-1 == panda_virtual_memory_rw(env, ustr_ptr, (uint8_t *)in_str, ustr_size, false)) {
        g_free(in_str);
        faros_log << "error1\n";faros_log.flush();
        return NULL;
    }

    GError *error = NULL;
    
    gsize bytes_written = 0;
     if(in_str == NULL || ustr_size == 0){
            faros_log << "error2\n";faros_log.flush();
            return NULL;
    }
    gchar *out_str = g_convert(in_str, ustr_size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, &error);

    if(error){
        std::string str(error->message);
        faros_log << "error3: " << str << "\n";faros_log.flush();
        return NULL;
    }
    
    if(out_str == NULL){
        faros_log << "error4\n";faros_log.flush();
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



void on_func_call_print(CPUState *env, target_ulong func) {
    OsiProc *current = get_current_process(env);
//    faros_log << "process name: " << current->name << "\n";
    //baidubrowser.e
    if (!is_this_process_filtered(current->name, strlen(current->name)))
        return;

    if (panda_in_kernel(env))
        return;
    
    auto func_name = mod_tag_loader->get_block_name(func);
   
    // If we are at the starting BB of a known WinAPI call log the function name,
    // its argument's addresses, and the total number of arguments
    if (func_name != nullptr && func_name->length() > 0) {
        faros_log << "Executing known block: "
            << func_name->c_str()
            << "(";
            // Get a vector of function call argument addresses on the stack
            for (auto s : mod_tag_loader->get_func_args_addr(env, *func_name)) {
                uint32_t arg = 0;
                panda_virtual_memory_rw(env, s, (uint8_t *)&arg, 4, false);
                faros_log << arg << ", ";
                
            }
            // Get total number of function arguments
            faros_log << ") [" << mod_tag_loader->get_num_func_args(*func_name) << "]"
                << "\n";
            faros_log.flush();
    }
    free(current);
}


typedef target_ulong func_addr;
typedef target_ulong adapter_address_struct;
std::unordered_map<func_addr, computerName> compNameMap;
std::unordered_map<func_addr, adapter_address_struct> macAddrMap;
std::unordered_map<func_addr, hostName> hostNameMap;
std::unordered_map<func_addr, target_ulong> volSerialMap;
std::unordered_map<func_addr, target_ulong> hardDriveMap;
std::unordered_map<func_addr, target_ulong> ZwhardDriveMap;
std::unordered_map<func_addr, target_ulong> versionMap;
std::unordered_map<func_addr, target_ulong> cpuMap;
std::unordered_map<func_addr, target_ulong> sidMap;

void taint_phys_mem(CPUState *env, target_ulong va, target_ulong size, uint32_t label){
    for(target_ulong byte_indx = 0; byte_indx < size; byte_indx++){
         target_ulong pa = panda_virt_to_phys(env, va + byte_indx);
         taint2_label_ram(pa, label);
    }
}

//TODO: GetVolumeInformationByHandleW
void on_func_ret(CPUState *env, target_ulong func) {
    if (panda_in_kernel(env))
        return;

    auto func_name = mod_tag_loader->get_block_name(func);
    if(!func_name)
        return;
    OsiProc *current = get_current_process(env);
    if (!is_this_process_filtered(current->name, strlen(current->name))){
           //faros_log << ">>" << func_name->c_str() << "\n";faros_log.flush();
           return;
    }
    //func = calc_retaddr_windows_x86(env);
    if (0 == strncmp((*func_name).c_str(), "GetAdaptersInfo", 15)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (macAddrMap.count(func) && macAddrMap[func]){
             char arg[6];
             target_ulong mac_address_addr = macAddrMap[func] + 
                                        256/*MAX_ADAPTER_NAME_LENGTH*/ + 
                                        128 /*MAX_ADAPTER_DESCRIPTION_LENGTH*/ + 5*4;
             panda_virtual_memory_rw(env, mac_address_addr, (uint8_t *)arg, 6, false);

             if (taint_enabled)
                 taint_phys_mem(env, mac_address_addr, 6, MAC_ADDR_LABEL);

             faros_log << "MAC address:: " << to_hex_str_buff(arg,6) << "\n\n";faros_log.flush();
             macAddrMap.erase(func);
         }
    }    
    else if (0 == strncmp((*func_name).c_str(), "GetAdaptersAddresses", 20)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (macAddrMap.count(func) && macAddrMap[func]){
             char arg[6];
             target_ulong mac_address_addr =  macAddrMap[func] + 0x2c;
             panda_virtual_memory_rw(env, mac_address_addr, (uint8_t *)arg, 6, false);

             if (taint_enabled)
                 taint_phys_mem(env, mac_address_addr, 6, MAC_ADDR_LABEL);
             faros_log << "MAC address:: " << to_hex_str_buff(arg,6) << "\n\n";faros_log.flush();
             macAddrMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameExW", 18)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (compNameMap.count(func)){
             target_ulong size = 0;
             computerName c_name = compNameMap[func];     
             panda_virtual_memory_rw(env, c_name.psize, (uint8_t *)&size, 4, false);
             //faros_log << "size: " << size << "\n";faros_log.flush();
             if(size > 0 && size < 20 && c_name.psize && c_name.pname){                         
                 char *computername = get_wstr(env, c_name.pname, size*2); 
                 if (taint_enabled)
                     taint_phys_mem(env, c_name.pname, size, COMPUTER_NAME_LABEL);
                     
                 faros_log << "GetComputerNameExW name:: " << computername << ", size: " << strlen(computername) << "\n\n";   
                 faros_log.flush();                
              }
              compNameMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameW", 16)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (compNameMap.count(func)){
             target_ulong size = 0;
             computerName c_name = compNameMap[func];     
             panda_virtual_memory_rw(env, c_name.psize, (uint8_t *)&size, 4, false);
             //faros_log << "size: " << size << "\n";faros_log.flush();
             if(size > 0 && size < 20 && c_name.psize && c_name.pname){                         
                 char *computername = get_wstr(env, c_name.pname, size*2);                             
                 if (taint_enabled)
                     taint_phys_mem(env, c_name.pname, size, COMPUTER_NAME_LABEL);
                 faros_log << "GetComputerNameW name:: " << computername << ", size: " << strlen(computername) << "\n\n";   
                 faros_log.flush();                
              }
              compNameMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameA", 16)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (compNameMap.count(func)){
             target_ulong size = 0;
             computerName c_name = compNameMap[func];     
             panda_virtual_memory_rw(env, c_name.psize, (uint8_t *)&size, 4, false);
             //faros_log << "size: " << size << "\n";faros_log.flush();
             if(size > 0 && size < 20 && c_name.psize && c_name.pname){                         
                 char *computername = (char *)malloc(size+1);         
                 panda_virtual_memory_rw(env, c_name.pname, (uint8_t *)computername, size, false);
                 computername[size] = '\0';
                 if (taint_enabled)
                     taint_phys_mem(env, c_name.pname, size, COMPUTER_NAME_LABEL);
                 faros_log << "GetComputerNameWA name:: " << computername << ", size: " << strlen(computername) << "\n\n";   
                 faros_log.flush();                
              }
              compNameMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "gethostname", 11)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (hostNameMap.count(func)){
              hostName h_name = hostNameMap[func];
              if(h_name.size > 0 && h_name.pname){
                  char *hostname = (char *)malloc(h_name.size+1);                 
                  panda_virtual_memory_rw(env, h_name.pname, (uint8_t *)hostname, h_name.size, false);
                  hostname[h_name.size] = '\0';
                  if (taint_enabled)
                     taint_phys_mem(env, h_name.pname, h_name.size, HOST_NAME_LABEL);
                  faros_log << "gethostname name:: " << hostname << ", size: " << strlen(hostname) << "\n\n"; 
                  faros_log.flush();                             
              }
              hostNameMap.erase(func);
         }
    }
    else if ( (0 == strncmp((*func_name).c_str(), "GetVolumeInformation", 20)) ||
        (0 == strncmp((*func_name).c_str(), "GetVolumeInformationByHandle", 28)) ){ // A/W
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (volSerialMap.count(func) && volSerialMap[func]){
               uint32_t serialNo = 0;
               panda_virtual_memory_rw(env, volSerialMap[func], (uint8_t *)&serialNo, 4, false);
               if (taint_enabled)
                  taint_phys_mem(env, volSerialMap[func], 4, VOLUME_SERIAL_NUMBER);
               faros_log << "GetVolumeInformation name:: " << to_hex_str_buff((char *)&serialNo,4) << "\n\n"; 
               faros_log.flush();                             
          }
          volSerialMap.erase(func);
    }
    else if (0 == strncmp((*func_name).c_str(), "DeviceIoControl", 15)){
         faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (hardDriveMap.count(func)){
             target_ulong outBuffer = hardDriveMap[func];
             
             char serialNumber[42];
             uint32_t SerialNumberOffset = 0;
             if (outBuffer){
                 panda_virtual_memory_rw(env, outBuffer + 0x18, (uint8_t *) &SerialNumberOffset, 4, false);
                 if (SerialNumberOffset){
                     panda_virtual_memory_rw(env, outBuffer + SerialNumberOffset, (uint8_t *) serialNumber, 42, false);
                     serialNumber[41] = '\0';//to_hex_str_buff(serialNumber,20)
                     if (taint_enabled)
                          taint_phys_mem(env, outBuffer + SerialNumberOffset, 41, HARD_DRIVE_SERIAL_NUMBER);
                          
                     faros_log << "DeviceIoControl: serialNumber: " << serialNumber  << ", Hex: " << to_hex_str_buff(serialNumber,40) << ": addr: " << outBuffer + SerialNumberOffset << "\n\n";
                     
                      char modelName[42];
                      uint32_t ProductIdOffset = 0;
                      panda_virtual_memory_rw(env, outBuffer + 16, (uint8_t *) &ProductIdOffset, 4, false);
                      if (ProductIdOffset && ProductIdOffset < 1000){
                          panda_virtual_memory_rw(env, outBuffer + ProductIdOffset, (uint8_t *) modelName, 42, false);
                          modelName[41] = '\0';                           
                          faros_log << "\n DeviceIoControl: modelName: " << modelName << ": offset: " << ProductIdOffset << ", size: " << strlen(modelName) << "\n";
                          // add taint location
                          if (taint_enabled)
                              taint_phys_mem(env, outBuffer + ProductIdOffset, strlen(modelName), HARD_DRIVE_MODEL_NAME);
                      }
                      faros_log.flush();
                 }
             }
             hardDriveMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "ZwDeviceIoControlFile", 21)){
         faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (ZwhardDriveMap.count(func)){
             target_ulong outBuffer = ZwhardDriveMap[func];
             
             char serialNumber[42];
             uint32_t SerialNumberOffset = 0;
             if (outBuffer){
                 panda_virtual_memory_rw(env, outBuffer + 0x18, (uint8_t *) &SerialNumberOffset, 4, false);
                 if (SerialNumberOffset){
                     panda_virtual_memory_rw(env, outBuffer + SerialNumberOffset, (uint8_t *) serialNumber, 42, false);
                     serialNumber[41] = '\0';
                     if (taint_enabled)
                          taint_phys_mem(env, outBuffer + SerialNumberOffset, 41, HARD_DRIVE_SERIAL_NUMBER);
                          
                     faros_log << "ZwDeviceIoControlFile : serialNumber: " << serialNumber << ", Hex: " << to_hex_str_buff(serialNumber,40) << ": addr: " << outBuffer + SerialNumberOffset << "\n\n";
                     char modelName[42];
                     uint32_t ProductIdOffset = 0;
                     panda_virtual_memory_rw(env, outBuffer + 16, (uint8_t *) &ProductIdOffset, 4, false);
                     if (ProductIdOffset && ProductIdOffset < 1000){
                         panda_virtual_memory_rw(env, outBuffer + ProductIdOffset, (uint8_t *) modelName, 42, false);
                         modelName[41] = '\0';                           
                         faros_log << "\n ZwDeviceIoControlFile: modelName: " << modelName << ": offset: " << ProductIdOffset << ", size: " << strlen(modelName) << "\n";
                         // add taint location
                         if (taint_enabled)
                             taint_phys_mem(env, outBuffer + ProductIdOffset, strlen(modelName), HARD_DRIVE_MODEL_NAME);
                     }
                     faros_log.flush();
                 }
             }
             ZwhardDriveMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "GetVersionEx", 12)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (versionMap.count(func)){
             target_ulong outBuffer = versionMap[func];
             uint32_t major = 0, minor = 0, build = 0;
             panda_virtual_memory_rw(env, outBuffer + 4, (uint8_t *) &major, 4, false);
             panda_virtual_memory_rw(env, outBuffer + 8, (uint8_t *) &minor, 4, false);
             panda_virtual_memory_rw(env, outBuffer + 12, (uint8_t *) &build, 4, false);
             if (taint_enabled)
                 taint_phys_mem(env, outBuffer + 4, 12, WINDOWS_VERSION);
             faros_log << "GetVersionEx majorVersion: " << major  << ": minorVersion: " << minor << ": buildVersion: " << build << "\n\n";
             faros_log.flush();
             versionMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "GetSystemInfo", 13)){
         //faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (cpuMap.count(func)){
             target_ulong outBuffer = cpuMap[func];
             uint32_t processorType = 0;
             uint16_t processorLevel = 0, processorRevision = 0;
             panda_virtual_memory_rw(env, outBuffer + 24, (uint8_t *) &processorType, 4, false);
             panda_virtual_memory_rw(env, outBuffer + 32, (uint8_t *) &processorLevel, 2, false);
             panda_virtual_memory_rw(env, outBuffer + 34, (uint8_t *) &processorRevision, 2, false);
             if (taint_enabled){
                 taint_phys_mem(env, outBuffer, 4, CPU_MODEL);//20
                 taint_phys_mem(env, outBuffer + 20, 8, CPU_MODEL);//20
                 taint_phys_mem(env, outBuffer + 32, 4, CPU_MODEL);
             }
             faros_log << "GetSystemInfo processorType: " << processorType  << ": processorLevel: " << processorLevel << ": processorRevision: " << processorRevision << "\n\n";
             faros_log.flush();
             cpuMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "LookupAccountNameLocalW", 22)){ // W/A
         faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (sidMap.count(func)){
             target_ulong outBuffer = sidMap[func];
             char sid[40];
             panda_virtual_memory_rw(env, outBuffer, (uint8_t *) &sid, 40, false);
             sid[39] = '\0';
             if (taint_enabled){
                 taint_phys_mem(env, outBuffer, 32, SID_NUMBER);
             }
             //faros_log << "\n LookupAccountNameW sid: " << sid << "\n";
             faros_log.flush();
             sidMap.erase(func);
         }
    }
    else if (0 == strncmp((*func_name).c_str(), "LookupAccountNameW", 17)){ // W/A
         faros_log << "ret from " << (*func_name).c_str() << "\n";faros_log.flush();
         if (sidMap.count(func)){
             target_ulong outBuffer = sidMap[func];
             char sid[40];
             panda_virtual_memory_rw(env, outBuffer, (uint8_t *) &sid, 40, false);
             sid[39] = '\0';
             if (taint_enabled){
                 taint_phys_mem(env, outBuffer, 32, SID_NUMBER);
             }
             //faros_log << "\n LookupAccountNameW sid: " << sid << "\n";
             faros_log.flush();
             sidMap.erase(func);
         }
    }
    faros_log.flush();
}

void on_func_call(CPUState *env, target_ulong func) {
    if (panda_in_kernel(env)) 
        return;

    auto func_name = mod_tag_loader->get_block_name(func);
    if (func_name == nullptr || func_name->length() == 0)
        return;

    OsiProc *current = get_current_process(env);    
    // new-ComputerNa
    if (!is_this_process_filtered(current->name, strlen(current->name)))
           return;
   
    if (0 == strncmp((*func_name).c_str(), "GetAdaptersInfo", 15)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        uint32_t arg = 0;
        panda_virtual_memory_rw(env, args[0], (uint8_t *)&arg, 4, false);
        macAddrMap[func] = arg;
    }        
    else if (0 == strncmp((*func_name).c_str(), "GetAdaptersAddresses", 20)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        uint32_t arg = 0;
        panda_virtual_memory_rw(env, args[3], (uint8_t *)&arg, 4, false);
        macAddrMap[func] = arg;
    }
    /* BOOL WINAPI GetComputerName(
     *  _Out_   LPTSTR  lpBuffer,
     *   _Inout_ LPDWORD lpnSize);
     */
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameExW", 18)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        computerName c_name;
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        if (args.size() == 3 ){ //TODO first arg should be zero
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&c_name.pname, 4, false);
            if(!c_name.pname)
                faros_log << "pname is NULL\n";
            panda_virtual_memory_rw(env, args[2], (uint8_t *)&c_name.psize, 4, false);
            //faros_log << "pname: " << c_name.pname << ", psize: " << c_name.psize << "\n";
            //proc_id asid = func;//calc_retaddr_windows_x86(env);
            compNameMap[func] = c_name;
        }
        else
            faros_log << "Wrong number of args.\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameA", 16)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        computerName c_name;
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        if (args.size() == 2){
            panda_virtual_memory_rw(env, args[0], (uint8_t *)&c_name.pname, 4, false);
            if(!c_name.pname)
                faros_log << "pname is NULL\n";
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&c_name.psize, 4, false);
            //faros_log << "pname: " << c_name.pname << ", psize: " << c_name.psize << "\n";
            //proc_id asid = func;//calc_retaddr_windows_x86(env);//panda_current_asid(env);
            compNameMap[func] = c_name;
        }
        else
            faros_log << "Wrong number of args.\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "GetComputerNameW", 16)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        computerName c_name;
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        if (args.size() == 2){
            panda_virtual_memory_rw(env, args[0], (uint8_t *)&c_name.pname, 4, false);
            if(!c_name.pname)
                faros_log << "pname is NULL\n";
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&c_name.psize, 4, false);
            //faros_log << "pname: " << c_name.pname << ", psize: " << c_name.psize << "\n";
            //proc_id asid = func;//calc_retaddr_windows_x86(env);
            compNameMap[func] = c_name;
        }
        else
            faros_log << "Wrong number of args.\n";faros_log.flush();
    }
    /* int gethostname(
     * _Out_ char *name,
     * _In_  int  namelen);
     */
    else if (0 == strncmp((*func_name).c_str(), "gethostname", 11)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        hostName h_name;
        // Get a vector of function call argument addresses on the stack
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        panda_virtual_memory_rw(env, args[0], (uint8_t *)&h_name.pname, 4, false);
        panda_virtual_memory_rw(env, args[1], (uint8_t *)&h_name.size, 4, false);

        //proc_id asid = func;//calc_retaddr_windows_x86(env);
        hostNameMap[func] = h_name;
    }
    else if ( (0 == strncmp((*func_name).c_str(), "GetVolumeInformation", 20)) ||
        (0 == strncmp((*func_name).c_str(), "GetVolumeInformationByHandle", 28)) ){ // A/W
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        target_ulong pserial;
        // Get a vector of function call argument addresses on the stack
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        char buff[10];
        target_ulong addr;
        panda_virtual_memory_rw(env, args[0], (uint8_t *)&addr, 4, false);
        panda_virtual_memory_rw(env, addr, (uint8_t *)buff, 9, false);
        buff[9] = '\0';
        faros_log << "buff: " << buff << "\n";faros_log.flush();
        panda_virtual_memory_rw(env, args[3], (uint8_t *)&pserial, 4, false);
        if (pserial)
            volSerialMap[func] = pserial;
    }    
    else if (0 == strncmp((*func_name).c_str(), "DeviceIoControl", 15)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        uint32_t ioctlCode = 0;
        target_ulong outBuffer = 0;
        if (args.size() == 8){
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&ioctlCode, 4, false);
            // 0x2d1400 :  IOCTL_STORAGE_QUERY_PROPERTY
            if (ioctlCode == 2954240){
                faros_log << "DeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY captured!\n";faros_log.flush();
                panda_virtual_memory_rw(env, args[4], (uint8_t *)&outBuffer, 4, false);
                hardDriveMap[func] = outBuffer;
            }
            else
                faros_log << "unknown ioctl: " << ioctlCode << "\n";
        }
        else
            faros_log << "Wrong number of args.\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "ZwDeviceIoControlFile", 21)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        uint32_t ioctlCode = 0;
        target_ulong outBuffer = 0;
        if (args.size() == 10){
            panda_virtual_memory_rw(env, args[5], (uint8_t *)&ioctlCode, 4, false);
            // 0x2d1400 :  IOCTL_STORAGE_QUERY_PROPERTY
            if (ioctlCode == 2954240){
                panda_virtual_memory_rw(env, args[8], (uint8_t *)&outBuffer, 4, false);
                ZwhardDriveMap[func] = outBuffer;
                faros_log << "ZwDeviceIoControlFile: IOCTL_STORAGE_QUERY_PROPERTY captured!\n";faros_log.flush();
            }
            //else
                //faros_log << "unknown ioctl: " << ioctlCode << "\n";
        }
        else
            faros_log << "Wrong number of args: " << args.size() << "\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "GetVersionEx", 12)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        target_ulong outBuffer = 0;
        if (args.size() == 1){
            panda_virtual_memory_rw(env, args[0], (uint8_t *)&outBuffer, 4, false);
            versionMap[func] = outBuffer;
        }
        else
            faros_log << "Wrong number of args: " << args.size() << "\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "GetSystemInfo", 13)){
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        target_ulong outBuffer = 0;
        if (args.size() == 1){
            panda_virtual_memory_rw(env, args[0], (uint8_t *)&outBuffer, 4, false);
            cpuMap[func] = outBuffer;
        }
        else
            faros_log << "Wrong number of args: " << args.size() << "\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "LookupAccountNameLocalW", 22)){ // W/A
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        target_ulong outBuffer = 0, inBuffer = 0;
        if (args.size() == 6){
            uint32_t cbSid = 0, pcbSid = 0;
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&outBuffer, 4, false);
            sidMap[func] = outBuffer;
            panda_virtual_memory_rw(env, args[0], (uint8_t *)&inBuffer, 4, false);
            char *username = get_wstr(env, inBuffer, 20);                             
            panda_virtual_memory_rw(env, args[2], (uint8_t *)&pcbSid, 4, false);
            panda_virtual_memory_rw(env, pcbSid, (uint8_t *)&cbSid, 4, false);
            faros_log << ">> username: " << username << " ,cbSid: " << cbSid << "\n";
        }
        else
            faros_log << "Wrong number of args: " << args.size() << "\n";faros_log.flush();
    }
    else if (0 == strncmp((*func_name).c_str(), "LookupAccountNameW", 17)){ // W/A
        faros_log << "calling " << (*func_name).c_str() << ", process name: " << current->name <<"\n";faros_log.flush();
        // Get a vector of function call argument addresses on the stack            
        auto args = mod_tag_loader->get_func_args_addr(env, *func_name);
        target_ulong outBuffer = 0, inBuffer = 0;
        if (args.size() == 7){
            uint32_t cbSid = 0, pcbSid = 0;
            panda_virtual_memory_rw(env, args[2], (uint8_t *)&outBuffer, 4, false);
            sidMap[func] = outBuffer;
            panda_virtual_memory_rw(env, args[1], (uint8_t *)&inBuffer, 4, false);
            char *username = get_wstr(env, inBuffer, 20);                             
            panda_virtual_memory_rw(env, args[3], (uint8_t *)&pcbSid, 4, false);
            panda_virtual_memory_rw(env, pcbSid, (uint8_t *)&cbSid, 4, false);
            faros_log << ">> username: " << username << " ,cbSid: " << cbSid << "\n";
        }
        else
            faros_log << "Wrong number of args: " << args.size() << "\n";faros_log.flush();
    }

    
}


void print_labels(target_ulong addr, const std::set<uint32_t> *labelsList){
       taint_log << addr << " | ";
       for (auto it = labelsList->begin(); it!=labelsList->end(); ++it){
            switch(*it){
                case MAC_ADDR_LABEL:
                    taint_log << "MAC, ";
                    break;
                case COMPUTER_NAME_LABEL:
                    taint_log << "Computer Name, ";
                    break;
                case HOST_NAME_LABEL:
                    taint_log << "Host Name, ";
                    break;
                case VOLUME_SERIAL_NUMBER:
                    taint_log << "Volume Serial Number, ";
                    break;
                case HARD_DRIVE_SERIAL_NUMBER:
                    taint_log << "Hard Drive Serial Number, ";
                    break;
                case HARD_DRIVE_MODEL_NAME:
                    taint_log << "Hard Drive Model Name, ";
                    break;
                case WINDOWS_VERSION:
                    taint_log << "Windows Version and Build, ";
                    break;
                case CPU_MODEL:
                    taint_log << "CPU Model, ";
                    break;
                case SID_NUMBER:
                    taint_log << "Security Identifier Number, ";
                    break;
            }
       }
       taint_log << "\n";taint_log.flush();

}


void print_buffer(uint64_t pa, uint32_t num_bytes){
    
    char *buff = (char *)malloc(num_bytes);
    if (!buff){
        taint_log << "Couldn't allocate memory\n";
        return;
    }
    panda_physical_memory_rw(pa, (uint8_t *)buff, num_bytes, false);
    taint_log << "Hex Buffer: " << to_hex_str_buff(buff, num_bytes) << "\n"; taint_log.flush();
    taint_log << "String Buffer: " << buff << "\n"; taint_log.flush(); taint_log.flush();
    taint_log << "================================== \n"; taint_log.flush();
    free(buff);

}

/*
// this is for much of the network taint transfers.
// this gets called from rr_log.c, rr_replay_skipped_calls, RR_CALL_NET_TRANSFER
// case.
int cb_replay_net_transfer_taint(CPUState *env, uint32_t type, uint64_t src_addr,
        uint64_t dest_addr, uint32_t num_bytes){
    // Replay network transfer as taint transfer
    switch (type) {
        case NET_TRANSFER_RAM_TO_IOB:{
//#ifdef TAINTDEBUG
 //           printf("NET_TRANSFER_RAM_TO_IOB src: 0x%lx, dest 0x%lx, len %d\n",
  //              src_addr, dest_addr, num_bytes);
//#endif
            //bool print_flag = false;
            faros_log << "before query, src_addr: " << src_addr << ", size: " << num_bytes << "\n";faros_log.flush();
            for(uint32_t byte_indx = 0; byte_indx < num_bytes ; byte_indx++){
                const std::set<uint32_t> *labelsList = taint2_query_ram(src_addr + byte_indx);
                if(labelsList && !labelsList->empty()){
                    print_flag = true;
                    print_labels(src_addr + byte_indx, labelsList);
                    taint2_delete_ram(src_addr+byte_indx);
                }
            }
            //if (print_flag)
                print_buffer(src_addr, num_bytes);
            break;
        }
        case NET_TRANSFER_IOB_TO_RAM:
//#ifdef TAINTDEBUG
  //          printf("NET_TRANSFER_IOB_TO_RAM src: 0x%lx, dest 0x%lx, len %d\n",
  //              src_addr, dest_addr, num_bytes);
//#endif

            break;
        case NET_TRANSFER_IOB_TO_IOB:
//#ifdef TAINTDEBUG
  //          printf("NET_TRANSFER_IOB_TO_IOB src: 0x%lx, dest 0x%lx, len %d\n",
  //              src_addr, dest_addr, num_bytes);
//#endif

            break;
        default:
            assert(0);
    }

    return 0;
}*/


void NtDeviceIoControlFile_return(CPUState* env,target_ulong pc, taintLocation *taintLocations){

    OsiProc *current = get_current_process(env);
    if (!is_this_process_filtered(current->name, strlen(current->name)))
           return;

    if (taintLocations == NULL)
        return;
    faros_log << "NtDeviceIoControlFile_return\n";

    for (taintLocation *loc = taintLocations;loc;loc=loc->next){
        if (taint_enabled && loc->type)
            taint_phys_mem(env, loc->addr, loc->size, loc->type);
        faros_log << "NtDeviceIoControlFile_return -> pname:" << current->name << ", loc: " << loc->addr << ", " << loc->size << ", " << loc->type << "\n"; 
    }


}


std::vector<std::string> blackList = {"0.0.0.0", "239.255.255.250", "127.0.0.1"};

bool is_this_ip_blocked(char *IP){
    for (auto ip: blackList){
        if (0 == strncmp(IP, ip.c_str(), ip.size()))
           return true;
    }
    return false;
}

void NtDeviceIoControlFile_enter(CPUState* env,target_ulong pc, packetInfo *pi){

    OsiProc *current = get_current_process(env);
    if (!is_this_process_filtered(current->name, strlen(current->name)))
        return;
           
    if (!pi)
        return;
    
    bool ignoreTaint = false;
    if (pi->pt == UDP && pi->destIP && is_this_ip_blocked(pi->destIP))
        ignoreTaint = true;        
    
    if (taint_enabled){
        char *buffer = (char *)malloc(pi->buffSize);
        panda_virtual_memory_rw(env, pi->buffAddr,
                                (uint8_t *)buffer, pi->buffSize, false);
        if (pi->destIP)
            faros_log << "NtDeviceIoControlFile_enter -> IP: " << pi->destIP << ", port: " << 
                                  pi->destPort << ", type: " << pi->pt << ", buffSize: " << pi->buffSize << "\n buffer: " << buffer << "\n";
        else
            faros_log << "NtDeviceIoControlFile_enter -> type: " << pi->pt << ", buffSize: " << 
                                                          pi->buffSize << "\n buffer: " << buffer << "\n";
        // check outgoing bytes' taint labels        
        
        //bool print_flag = false;
        target_ulong src_addr = pi->buffAddr;
        uint32_t num_bytes = pi->buffSize;
        faros_log << "before query, src_addr: " << src_addr << "\n";faros_log.flush();
        for(uint32_t byte_indx = 0; byte_indx < num_bytes ; byte_indx++){        
            target_ulong pa = panda_virt_to_phys(env, src_addr + byte_indx);
            const std::set<uint32_t> *labelsList = taint2_query_ram(pa);
            if(labelsList && !labelsList->empty()){
                //print_flag = true;
                if (!ignoreTaint)
                    print_labels(pa, labelsList);
                taint2_delete_ram(pa);
            }
        }
        //if (print_flag)
        src_addr= panda_virt_to_phys(env, src_addr);
        print_buffer(src_addr, num_bytes);
    }
}

// TODO Handle arguments to the plugin on startup to allow faros enabled at start or other config
bool init_plugin(void *self) {

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    panda_require("win7x86intro");
    // init osi plugin
    assert(init_osi_api());

    panda_require("syscalls2");
    // We disable FAROS at startup by default
    faros_enabled = true;
    taint_enabled = false;
    log_funcs = false;
    
    // Parse input arguments, i.e. pid and taint_enable
    panda_arg_list *args = panda_get_args("PIITracker");
    
    //PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);
    // Load the csv of known API calls and init the loader class
    std::ifstream win_api_file("./msdn.csv");
    mod_tag_loader = new ModuleLoader(win_api_file);
    pnames.count = 0;
    PPP_REG_CB("syscalls2", on_NtDeviceIoControlFile_return, NtDeviceIoControlFile_return);
    PPP_REG_CB("syscalls2", on_NtDeviceIoControlFile_enter, NtDeviceIoControlFile_enter);
    
    if (args != NULL) {
        for (int i = 0; i < args->nargs; i++) {
            if (0 == strncmp(args->list[i].key, "taint_enabled", 13)) {
                if (0 == strncmp(args->list[i].value, "true", 4)){
                    taint_enabled = true;
                    fprintf(stdout, "\nEnabling Taint Engine");
                }
            }
            else if (0 == strncmp(args->list[i].key, "log_funcs", 9)) {
                if (0 == strncmp(args->list[i].value, "true", 4)){
                    log_funcs = true;
                    fprintf(stdout, "\nEnabling logging function calls");
                }
            }
            else if (0 == strncmp(args->list[i].key, "pname", 5)) {
                std::string pname_list(args->list[i].value);
                std::string delimiter = "-";
                size_t pos = 0;
                std::string pname;
                while ((pos = pname_list.find(delimiter)) != std::string::npos) {
                    pname = pname_list.substr(0, pos);
                    pnames.pname[pnames.count] = std::string(pname.c_str(), strlen(pname.c_str()));
                    pnames.count++;
                    pname_list.erase(0, pos + delimiter.length());
                }
                pnames.pname[pnames.count] = std::string(pname_list.c_str(), strlen(pname_list.c_str()));
                pnames.count++;
            }
            else{
                    fprintf(stderr, "\nPlugin 'PIITracker' needs arguments: -panda PIITracker:taint_enabled=true/false\n");
                    return false;
            }
        }
    }
    if (log_funcs){
        PPP_REG_CB("callstack_instr", on_call, on_func_call_print);
    }
    else{      
        PPP_REG_CB("callstack_instr", on_call, on_func_call);
        PPP_REG_CB("callstack_instr", on_ret, on_func_ret);
    }
    panda_cb pcb;
    if (taint_enabled){
        panda_require("taint2");
        assert(init_taint2_api());
        taint2_enable_taint();
        //pcb.replay_net_transfer = cb_replay_net_transfer_taint;
        //panda_register_callback(self, PANDA_CB_REPLAY_NET_TRANSFER, pcb); 

    }
    pcb.monitor = monitor_callback;    
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_disable_tb_chaining(); 
    panda_enable_memcb();
    panda_enable_precise_pc();
    
    // Open output files
    faros_log.open("PIITracker.log", std::ios::out | std::ios::trunc);
    taint_log.open("taint.log", std::ios::out | std::ios::trunc);
    taint_log << "Memory Address | Taint Labels\n";
    taint_log << "---------------------------------\n";
        
    faros_log << "PIITracker loading ...!\n";
    std::cout << "\nPIITracker Started. Nothing to see here. Move along!\n";

    return true;
}

void uninit_plugin(void *self) {
    panda_disable_precise_pc();
    panda_disable_memcb();
    panda_enable_tb_chaining(); 
    faros_log.close();
    taint_log.close();
}


