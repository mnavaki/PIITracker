/*
 * =====================================================================================
 *
 *       Filename:  func_trace.cpp
 *
 *    Description:  Simple funciton tracing plugin for panda
 *
 *        Version:  1.0
 *        Created:  05/03/2016 10:58:49 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *        Company:
 *
 * =====================================================================================
 */
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>

extern "C" {
#include "qemu-common.h"
#include "panda_common.h"
#include "panda_plugin.h"
}

#include "pwnda_funcs.h"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    int before_block_exec(CPUState *, TranslationBlock *);
}

ModuleLoader *mod_tag_loader;
uint32_t old_pid = 0;

// TODO Safety checks for wrong/bad PE headers
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

    auto tag_pc = env->eip;
    auto func_name = mod_tag_loader->get_block_name(tag_pc);
   
    // If we are at the starting BB of a know WinAPI call log the function name,
    // it's argument's addresses, and the total number of arguments
    if (func_name != nullptr && func_name->length() > 0) {
        std::cerr << "Executing known block: "
            << func_name->c_str()
            << "(";

        // Get a vector of function call argument addresses on the stack
        for (auto s : mod_tag_loader->get_func_args_addr(env, *func_name)) {
            std::cerr << s << ", ";
        }

        // Get total number of function arguments
        std::cerr << ") [" << mod_tag_loader->get_num_func_args(*func_name) << "]"
            << "\n";
    }
#endif
    return 0;
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)
    panda_cb pcb;
    
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // Load the csv of known API calls and init the loader class
    std::ifstream win_api_file("/home/geoff/tmp/WinHelp/msdn.csv");
    mod_tag_loader = new ModuleLoader(win_api_file);

    panda_disable_tb_chaining(); 
    panda_enable_memcb();
    panda_enable_precise_pc();
    std::cout << "Function Trace Enabled" << std::endl;
#endif
    return true;
}

void uninit_plugin(void *self) {
    panda_disable_precise_pc();
    panda_disable_memcb();
    panda_enable_tb_chaining(); 
}
