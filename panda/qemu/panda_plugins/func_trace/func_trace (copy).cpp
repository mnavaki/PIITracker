/*
 * ============================================================================
 *
 *       Filename:  func_trace.cpp
 *
 *    Description:  Simple function tracing plugin for panda
 *
 *        Version:  1.0
 *       Compiler:  g++
 *
 *         Author:  Geoff Alexander <alexandg (at) cs.unm.edu>
 *
 * ============================================================================
 */
//#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <queue>
#include <string>

#include "llvm/IR/Function.h"

extern "C" {
#include "panda_plugin.h"
#include "panda_common.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "../callstack_instr/callstack_instr.h"
//#include "../callstack_instr/callstack_instr_ext.h"
}

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    int before_block_exec(CPUState *, TranslationBlock *);
}

std::ofstream faros_log;

std::unordered_map<target_ulong, std::string> mod_names;
std::unordered_map<target_ulong, target_ulong> bases;
std::unordered_map<target_ulong, target_ulong> mod_bases;
std::unordered_map<target_ulong, std::string> global_funcs;
std::unordered_map<std::string, std::vector<std::string>> func_args;

typedef struct _arg_line {
    std::string name;
    std::vector<std::string> args;
} ArgLine;

std::pair<std::string, std::vector<std::string>> split_line(std::string str, char delim) {
    std::string name;
    std::vector<std::string> args;
    std::stringstream ss(str);
    std::string tok;

    bool is_name = true;
    while (std::getline(ss, tok, delim)) {
        if (is_name) {
            name = tok;
            is_name = false;
        } else {
            args.push_back(tok);
        }
    }

    return std::make_pair(name, args);
}
/*
std::string get_process_name(CPUState *env, uint32_t peb) {
    uint32_t proc_params = 0;
    uint16_t len = 0;
    uint8_t image_path[256];
    uint8_t proc_name[256];
    uint32_t image_ptr = 0;

    // Lookup process name
    // From PEB get ProcessParameters
    panda_virtual_memory_rw(env, peb + 0x10, (uint8_t *)&proc_params, 4, 0);

    // In ProcParams ImagePathName:0x38 is a UNICODE_STRING which has format:
    //   struct _UNICODE_STRING {
    //      ushort Length;
    //      ushort MaxLength;
    //      wchar_t *buffer;
    //   }
    //
    // So read length, then buffer
    panda_virtual_memory_rw(env, proc_params + 0x38, (uint8_t *)&len, 2, 0);

    len = len + 1 < 256 ? len + 1 : 255;
    image_path[len] = '\0';
    panda_virtual_memory_rw(env, proc_params + 0x3c, (uint8_t *)&image_ptr, 4, 0);
    panda_virtual_memory_rw(env, image_ptr, (uint8_t *)image_path, len, 0);

    // FIXME Gotta be a better way...
    memset(proc_name, 0, len);
    for (auto x = 0, y = 0; x < len - 1; x += 2, ++y) {
        proc_name[y] = image_path[x];
    }

    return std::string((char *) proc_name);
}
*/


uint32_t get_win_func_arg(CPUState* env, int nr) {
//#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t arg = 0; //R_EDX = 2
    panda_virtual_memory_rw(env, env->regs[2] + 8 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
//#endif
    return 0;
}


// TODO Safety checks for wrong/bad PE headers
int before_block_exec(CPUState *env, TranslationBlock *tb) {
#if defined(TARGET_I386) // && defined(CONFIG_LLVM)
    uint32_t pid, peb, ldr, ldr_start, ldr_cur;
    uint8_t name_buffer[256];

    if (panda_in_kernel(env)) {
        return 0;
    }
    // Get PID from the TIB
    auto fs = env->segs[R_FS].base;
    panda_virtual_memory_rw(env, fs + 0x20, (uint8_t *)&pid, 4, 0);
//    if (pid != 528) {
//        return 0;
//    }

    // Get PEB from the TIB
    panda_virtual_memory_rw(env, fs + 0x30, (uint8_t *)&peb, 4, 0);

    // If we've already seen this ASID no need to figure out the process's name
    if (!mod_names.count(panda_current_asid(env))) {
        mod_names[panda_current_asid(env)] = get_process_name(env, peb);
    }

    // If we've already seen this ASID just check if in a known function and
    // don't walk the modules list
    if (bases.count(panda_current_asid(env))) {
        if (global_funcs.count(env->eip)) {
            fprintf(stderr, "[0x%08x] [%u] [%s] BB Call %s (", env->eip, pid,
                    mod_names[panda_current_asid(env)].c_str(),
                    global_funcs[env->eip].c_str());
            if (func_args.count(global_funcs[env->eip])) {
                for (std::string s : func_args[global_funcs[env->eip]]) {
                    fprintf(stderr, "%s, ", s.c_str());
                }
            }
            fprintf(stderr, ")\n");
        }
        return 0;
    }
    bases[panda_current_asid(env)] = panda_current_asid(env);

    panda_virtual_memory_rw(env, peb + 0xc, (uint8_t *)&ldr, 4, 0);
    panda_virtual_memory_rw(env, ldr + 0xc, (uint8_t *)&ldr_cur, 4, 0);
    panda_virtual_memory_rw(env, ldr + 0x10, (uint8_t *)&ldr_start, 4, 0);

    auto mods = 0;
    while(mods < 1000 && ldr_cur != ldr_start) {
        uint32_t func_addr = 0, name_addr, e_lfanew, dll_base = 0;
        uint32_t funcs_arr, names_arr, ord_arr, export_table, num_ex_func;
        uint16_t ordinal = 0;

        panda_virtual_memory_rw(env, ldr_cur + 0x18, (uint8_t *)&dll_base, 4, 0);
        if (!mod_bases.count(dll_base)) {
            mod_bases[dll_base] = dll_base;

            // Get ptr to nt_hdr
            panda_virtual_memory_rw(env, dll_base + 0x3c,
                                    (uint8_t *)&e_lfanew, 4, 0);

            // Find the export table and number of exported functions
            panda_virtual_memory_rw(env, dll_base + e_lfanew + 0x78,
                                    (uint8_t *)&export_table, 4, 0);
            panda_virtual_memory_rw(env, dll_base + export_table + 0x14,
                                    (uint8_t *)&num_ex_func, 4, 0);

            // Get Function, Name, and Ordinal array addresses
            panda_virtual_memory_rw(env, dll_base + export_table + 0x1c,
                                    (uint8_t *)&funcs_arr, 4, 0);
            panda_virtual_memory_rw(env, dll_base + export_table + 0x20,
                                    (uint8_t *)&names_arr, 4, 0);
            panda_virtual_memory_rw(env, dll_base + export_table + 0x24,
                                    (uint8_t *)&ord_arr, 4, 0);

            // Add location of each exported function
            for (uint32_t idx = 0; idx < num_ex_func; ++idx) {
                panda_virtual_memory_rw(env, dll_base + ord_arr + (2 * idx),
                                        (uint8_t *)&ordinal, 2, 0);

                if (ordinal) {
                    memset(name_buffer, 0, 256);
                    panda_virtual_memory_rw(env, dll_base + funcs_arr + (4 * ordinal),
                                            (uint8_t *)&func_addr, 4, 0);
                    panda_virtual_memory_rw(env, dll_base + names_arr + (4 * ordinal),
                                            (uint8_t *)&name_addr, 4, 0);
                    panda_virtual_memory_rw(env, dll_base + name_addr,
                                            (uint8_t *)name_buffer, 256, 0);
                    name_buffer[255] = '\0';
                    if (strlen((char *) name_buffer)) {
                        global_funcs[func_addr + dll_base] = std::string((char *) name_buffer);
                        /*if (0 == strncmp(global_funcs[func_addr + dll_base].c_str(), "GetAdaptersAddresses", 20)){
                             uint32_t arg = get_win_func_arg(env, 0);
                             faros_log << "\n === arg 0: " << arg;
                        }*/
                    }
                }
            }
        }
        panda_virtual_memory_rw(env, ldr_cur, (uint8_t *)&ldr_cur, 4, 0);
        mods++;
    }

#endif
    return 0;
}
#define PTR uint32_t
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
           faros_log << "\n wstr error: str is NULL!" ;
           faros_log.flush();
            return NULL;
    }
    gchar *out_str = g_convert(in_str, ustr_size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, &error);

    if(error){
        std::string str(error->message);
        faros_log << "\n wstr error: " << str ;
        faros_log.flush();
        return NULL;
    }
    
    if(out_str == NULL){
        faros_log << "\n wstr error: out_str == NULL";
        faros_log.flush();
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

void on_func_call(CPUState *env, target_ulong func) {
    if (!panda_in_kernel(env)) {
        fprintf(stderr, "Function call to %s\n", global_funcs[func].c_str());
        if (0 == strncmp(global_funcs[func].c_str(), "GetAdaptersAddresses", 20)){
             //uint32_t arg = get_win_func_arg(env, 1);
             uint32_t arg = 0; //R_EDX = 2, R_EBP = 5
             panda_virtual_memory_rw(env, env->regs[5] + 8,
                            (uint8_t *) &arg, 4, false);
             faros_log << "\n === arg 1: " << arg;faros_log.flush();
             panda_virtual_memory_rw(env, env->regs[5] + 12,
                            (uint8_t *) &arg, 4, false);
             faros_log << "\n === arg 2: " << arg;faros_log.flush();
             panda_virtual_memory_rw(env, env->regs[5] + 16,
                            (uint8_t *) &arg, 4, false);
             faros_log << "\n === arg 3: " << arg;faros_log.flush();
             panda_virtual_memory_rw(env, env->regs[5] + 20,
                            (uint8_t *) &arg, 4, false);
             faros_log << "\n === arg 4: " << arg;faros_log.flush();
             //panda_virtual_memory_rw(env, env->regs[5] + 24,
             //(uint8_t *) &arg, 4, false);
             //faros_log << "\n === arg 5: " << arg;faros_log.flush();
             uint32_t arg1 = 0;
             panda_virtual_memory_rw(env, arg + 12 + 8*4 + 8 + 4, (uint8_t *) &arg1, 4, false);
             faros_log << "\n === arg 6: " << arg1;faros_log.flush();
            /* char *str = get_wstr(env, arg1, 10);
             if(!str){
                str[5] = '\0';
                std::string str1(str);
                faros_log << "\n === string: " << str1;
             }*/
             //uint32_t arg2 = 0;
             //panda_virtual_memory_rw(env, arg1, (uint8_t *) &arg2, 1, false);
             //faros_log << "\n === arg 7: " << arg2;faros_log.flush();
        }
    }
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)
    panda_cb pcb;

    panda_require("callstack_instr");
    PPP_REG_CB("callstack_instr", on_ret, on_func_call);
    //if (!init_callstack_instr_api()) return false;
    /*if (!init_callstack_instr_api()) {
       return false;
    }*/
    faros_log.open("faros.log", std::ios::out | std::ios::trunc);
    
    // Read in csv file
    std::ifstream in_file("msdn.csv");
    std::string line_buffer;

    while (in_file && std::getline(in_file, line_buffer)) {
        if (!line_buffer.length()) {
            continue;
        }

        auto line = split_line(line_buffer, ',');
        func_args[line.first] = line.second;
    }

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_disable_tb_chaining();
    panda_enable_memcb();
    panda_enable_precise_pc();
    //panda_enable_llvm();

    std::cout << "Function Trace Enabled" << std::endl;
#endif
    return true;
}

void uninit_plugin(void *self) {
    //panda_disable_llvm();
    panda_disable_precise_pc();
    panda_disable_memcb();
    panda_enable_tb_chaining();
    faros_log.close();
}

