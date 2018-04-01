#include <unordered_map>
#include <vector>
#include <string>
#include <fstream>
#include <memory>

extern "C" {
#include "panda_plugin.h"
#include "panda_common.h"
#include "rr_log.h"
}

typedef struct _arg_line {
    std::string name;
    std::vector<std::string> args;
} ArgLine;

class ModuleLoader {
    private:
        std::unordered_map<target_ulong, std::string> mod_names;
        std::unordered_map<target_ulong, target_ulong> bases;
        std::unordered_map<target_ulong, target_ulong> mod_bases;
        std::unordered_map<target_ulong, std::shared_ptr<std::string>> global_funcs;
        std::unordered_map<std::string, std::vector<std::string>> func_args;

        void load_api_funcs(std::ifstream& in_file);
        void load_modules(CPUState *env, uint32_t start, uint32_t end);
        std::ofstream pwnda_log;
    public:
        ModuleLoader(std::ifstream& in_file);
        int process_module(CPUState *env);
        bool module_loaded(target_ulong addr);
        bool asid_loaded(target_ulong asid);
        std::shared_ptr<std::string> get_block_name(target_ulong pc);
        int get_num_func_args(std::string& func_name);
        std::vector<std::string>& get_func_args(std::string& func);
        std::vector<target_ulong> get_func_args_addr(CPUState *env, std::string& func);
};

