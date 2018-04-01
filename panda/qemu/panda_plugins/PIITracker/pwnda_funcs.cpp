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
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

//#include "llvm/IR/Function.h"
#include "pwnda_funcs.h"

/* 
 * On windows 64 bit the TIB is in the GS register instead of the FS register.
 *
 * Most other fields are at different offsets because of the larger size
 * of pointers on 64 comapred to 32-bit systems.
 *
 */

int read_n_bytes(CPUState *env, target_ulong addr, uint8_t *buf, target_ulong n) {
    return panda_virtual_memory_rw(env, addr, buf, n, 0);
}

int read_u16(CPUState *env, target_ulong addr, uint16_t *value) {
    return panda_virtual_memory_rw(env, addr, (uint8_t *)value, 2, 0);
}

int read_u32(CPUState *env, target_ulong addr, uint32_t *value) {
    return panda_virtual_memory_rw(env, addr, (uint8_t *)value, 4, 0);
}

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

// Look up the fullname of the process corresponding the a given PEB
std::string get_process_name(CPUState *env, uint32_t peb) {
    uint32_t proc_params = 0;
    uint16_t len = 0;
    uint8_t image_path[256];
    uint8_t proc_name[256];
    uint32_t image_ptr = 0;

    // Lookup process name
    // From PEB get ProcessParameters
    read_u32(env, peb + 0x10, &proc_params);

    // In ProcParams ImagePathName:0x38 is a UNICODE_STRING which has format:
    //   struct _UNICODE_STRING {
    //      ushort Length;
    //      ushort MaxLength;
    //      wchar_t *buffer;
    //   }
    //
    // So read length, then buffer
    read_u16(env, proc_params + 0x38, &len);

    len = len + 1 < 256 ? len + 1 : 255;
    image_path[len] = '\0';
    read_u32(env, proc_params + 0x3c, &image_ptr);
    read_n_bytes(env, image_ptr, (uint8_t *)image_path, len);

    // FIXME Gotta be a better way...
    memset(proc_name, 0, len);
    for (auto x = 0, y = 0; x < len - 1; x += 2, ++y) {
        proc_name[y] = image_path[x];
    }

    return std::string((char *) proc_name);
}

bool ModuleLoader::module_loaded(target_ulong addr) {
    return mod_bases.count(addr) != 0;
}

bool ModuleLoader::asid_loaded(target_ulong asid) {
    return bases.count(asid) != 0;
}



// Walk the list of loaded modules and add any modules and exports we haven't seen yet
void ModuleLoader::load_modules(CPUState *env, uint32_t start, uint32_t end) {
    uint8 name_buffer[256];

    auto mods = 0;
    uint32_t ldr_cur = start;
    if (!ldr_cur)
        return;
    pwnda_log << "\nloading modules...";pwnda_log.flush();
    int counter =0;
    do{
        uint32_t func_addr = 0, name_addr, e_lfanew, dll_base = 0;
        uint32_t funcs_arr, names_arr, ord_arr, export_table, num_ex_func, ordinal_base;
        uint16_t ordinal = 0;

        read_u32(env, ldr_cur + 0x18, &dll_base);
        if (dll_base /*&& !mod_bases.count(dll_base)*/) {
            mod_bases[dll_base] = dll_base;

            // Get ptr to nt_hdr
            read_u32(env, dll_base + 0x3c, &e_lfanew);

            // Find the export table and number of exported functions
            read_u32(env, dll_base + e_lfanew + 0x78, &export_table);
            
            read_u32(env, dll_base + export_table + 0x10, &ordinal_base);
            read_u32(env, dll_base + export_table + 0x14, &num_ex_func);

            // Get Function, Name, and Ordinal array addresses
            read_u32(env, dll_base + export_table + 0x1c, &funcs_arr);
            read_u32(env, dll_base + export_table + 0x20, &names_arr);
            read_u32(env, dll_base + export_table + 0x24, &ord_arr);

            //pwnda_log << "\nnum_ex_func: " << num_ex_func;pwnda_log.flush();
            // Add location of each exported function
            for (uint32_t idx = 0; num_ex_func < 100000 && idx < num_ex_func; idx++) {
                read_u16(env, dll_base + ord_arr + (2 * idx), &ordinal);

                //if (ordinal) {
                    memset(name_buffer, 0, 256);
                    read_u32(env, dll_base + funcs_arr + (4 * ordinal), &func_addr);
                    read_u32(env, dll_base + names_arr + (4 * idx), &name_addr);
                    read_n_bytes(env, dll_base + name_addr, (uint8_t *)name_buffer, 256);
                    name_buffer[255] = '\0';
                    //pwnda_log << "\naddr: " << func_addr + dll_base;
                    if (strlen((char *) name_buffer)) {
                        //pwnda_log << "\nfname: " << (char *)name_buffer;
                        if (0 == strncmp((char *)name_buffer, "UuidCreateSequential", 20))
                            pwnda_log << "\nfname: " << (char *)name_buffer << ", addr: " << func_addr + dll_base;
                        else if (0 == strncmp((char *)name_buffer, "GetAdaptersAddresses", 20))
                            pwnda_log << "\nfname: " << (char *)name_buffer << ", addr: " << func_addr + dll_base;
                        else if (0 == strncmp((char *)name_buffer, "GetAdaptersInfo", 15))
                            pwnda_log << "\nfname: " << (char *)name_buffer <<  ", addr: " << func_addr + dll_base;
                        else if (0 == strncmp((char *)name_buffer, "GetComputerName", 15))
                            pwnda_log << "\nfname: " << (char *)name_buffer <<  ", addr: " << func_addr + dll_base;
                        global_funcs[func_addr + dll_base] = std::make_shared<std::string>(std::string((char *) name_buffer));
                   }
                   else
                        counter++;
                //}
            }
            pwnda_log.flush();
        }
        else
            break;
        read_u32(env, ldr_cur, &ldr_cur);
        mods++;
    }while(ldr_cur != end);
    
    pwnda_log << "\nmods: " << mods;
}


/*
// Walk the list of loaded modules and add any modules and exports we haven't seen yet
void ModuleLoader::load_modules(CPUState *env, uint32_t start, uint32_t end) {
    uint8 name_buffer[256];

    auto mods = 0;
    uint32_t ldr_cur = start;
    pwnda_log << "\nloading modules...";pwnda_log.flush();
    do{
    //while(mods < 256 && ldr_cur != end) {
        uint32_t func_addr = 0, name_addr, e_lfanew, dll_base = 0;
        uint32_t funcs_arr, names_arr, ord_arr, export_table, num_ex_func;
        uint16_t ordinal = 0;

        read_u32(env, ldr_cur + 0x18, &dll_base);
        if (dll_base && !mod_bases.count(dll_base)) {
            mod_bases[dll_base] = dll_base;

            // Get ptr to nt_hdr
            read_u32(env, dll_base + 0x3c, &e_lfanew);

            // Find the export table and number of exported functions
            read_u32(env, dll_base + e_lfanew + 0x78, &export_table);
            read_u32(env, dll_base + export_table + 0x14, &num_ex_func);// 0x14

            // Get Function, Name, and Ordinal array addresses
            read_u32(env, dll_base + export_table + 0x1c, &funcs_arr); //0x1c
            read_u32(env, dll_base + export_table + 0x20, &names_arr); //0x20
            read_u32(env, dll_base + export_table + 0x24, &ord_arr); //0x24

            pwnda_log << "\nnum_ex_func: " << num_ex_func;pwnda_log.flush();
            // Add location of each exported function
            for (uint32_t idx = 0; idx < num_ex_func; ++idx) {
                read_u16(env, dll_base + ord_arr + (2 * idx), &ordinal);

                if (ordinal) {
                    memset(name_buffer, 0, 256);
                    //for (int k=0; k < 256; k++)
                    //    name_buffer[k] = 0;
                    read_u32(env, dll_base + funcs_arr + (4 * ordinal), &func_addr);
                    read_u32(env, dll_base + names_arr + (4 * ordinal), &name_addr);
                    read_n_bytes(env, dll_base + name_addr, (uint8_t *)name_buffer, 256);
                    //panda_virtual_memory_rw(env, dll_base + name_addr, (uint8_t *)name_buffer, 256, false);
                    name_buffer[255] = '\0';
                    if (strlen((char *) name_buffer)) {
                        if (0 == strncmp((char *)name_buffer, "GetAdaptersAddresses", 20))
                            pwnda_log << "\nfname: " << (char *)name_buffer << ", dll_base: " << dll_base << ", func_addr: " << func_addr;
                        if (0 == strncmp((char *)name_buffer, "GetAdaptersInfo", 15))
                            pwnda_log << "\nfname: " << (char *)name_buffer<< ", dll_base: " << dll_base << ", func_addr: " << func_addr;
                        global_funcs[func_addr + dll_base] = std::make_shared<std::string>(std::string((char *) name_buffer));
                    }
                }
            }
        } else {
            break;
        }
        read_u32(env, ldr_cur, &ldr_cur);
        mods++;
    }while(ldr_cur != end && !ldr_cur);
}*/

// TODO Safety checks for wrong/bad PE headers
int ModuleLoader::process_module(CPUState *env) {
#if defined(TARGET_I386)
    uint32_t pid, peb, ldr, ldr_start, ldr_end;
   //uint8_t name_buffer[256];
    // Don't process the kernel
    if (panda_in_kernel(env)) {
        return 0;
    }
    auto asid = panda_current_asid(env);
    if (bases.count(asid)) {
        return 0;
    }

    auto fs = env->segs[R_FS].base;

    // Get PID and PEB from the TIB
    read_u32(env, fs + 0x20, &pid);
    read_u32(env, fs + 0x30, &peb);


    bases[panda_current_asid(env)] = asid;

    // Get linked list of modules
    read_u32(env, peb + 0xc, &ldr);
    // ldr + 0x14 : head of the linked list
    read_u32(env, ldr + 0xc, &ldr_start);//0xc
    read_u32(env, ldr + 0x10, &ldr_end);//0x10
    
    //read_u32(env, ldr + 0x14, &ldr_start);//0xc
    //read_u32(env, ldr + 0x18, &ldr_end);//0x10

    load_modules(env, ldr_start, ldr_end);
#endif
    return 0;
}

// Return the type of the arguments for a given WinAPI function
std::vector<std::string>& ModuleLoader::get_func_args(std::string& func) {
    return func_args[func];
}

// Return a list of the addresses, on the STACK, used to store function
// arguments for Win32 API Calls
std::vector<target_ulong> ModuleLoader::get_func_args_addr(CPUState *env, std::string& func) {
    std::vector<target_ulong> result;
#if defined(TARGET_I386)
    auto args = func_args[func];

    auto esp = env->regs[R_ESP]+4;
    for (target_ulong idx = 0; idx < args.size(); ++idx) {
        result.push_back(esp + (idx * 4));
    }
#endif
    return result;
}

int ModuleLoader::get_num_func_args(std::string& func_name) {
    if (func_args.count(func_name)) {
        return func_args.at(func_name).size();
    }

    return 0;
}

void ModuleLoader::load_api_funcs(std::ifstream &in_file) {
    std::string line_buffer;
    while (in_file && std::getline(in_file, line_buffer)) {
        if (line_buffer.length()) {
            auto line = split_line(line_buffer, ',');
            func_args[line.first] = line.second;
        }
    }
}

ModuleLoader::ModuleLoader(std::ifstream& in_file) {
    load_api_funcs(in_file);
    pwnda_log.open("pwnda.log", std::ios::out | std::ios::trunc);
}

std::shared_ptr<std::string> ModuleLoader::get_block_name(target_ulong pc) {
    if (global_funcs.count(pc)) {
        return global_funcs.at(pc);
    }

    return std::make_shared<std::string>();
}

