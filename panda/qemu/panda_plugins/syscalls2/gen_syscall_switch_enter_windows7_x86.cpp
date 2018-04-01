// I have searched from 0-16, adding cases: (cases do not have headers or comments for pointers)
//
//        4, 6, 7, 9, 10, 16
//
// I have searched through 0-99, adding directions to the headers for cases:
//
//        1, 1, 2, 11, 12, 13, 14, 15, 19, 44, 45, 48, 49, 50, 51, 55, 57
//        58, 59, 60, 61, 62, 64, 65, 66, 67, 70, 71, 73, 74, 75, 76, 77
//        79, 81, 84, 85, 86, 87, 89, 90, 96, 98, 99
//
// New syscall added:
//
//        4105, 4106, 4122, 4130, 4137, 4138, 4139, 4143, 4226, 4228, 4234
//        4249, 4255, 4257, 4260, 4264, 4269, 4271, 4275, 4278, 4282, 4294
//        4305, 4309, 4312, 4322, 4326, 4338, 4339, 4350
//
// New syscall added:
//
//        4105, 4106, 4122, 4130, 4137, 4138, 4139, 4143, 4226, 4228, 4234
//        4249, 4255, 4257, 4260, 4264, 4269, 4271, 4275, 4278, 4282, 4294
//        4305, 4309, 4312, 4322, 4326, 4338, 4339, 4350, 4358, 4360, 4377
//        4399, 4403, 4410, 4414, 4426, 4445, 4450, 4452, 4457, 4460, 4462
//        4463, 4464, 4466, 4467, 4469, 4479, 4482, 4483, 4486, 4491, 4492
//        4499, 4502, 4503, 4513, 4521, 4522, 4523, 4525, 4528, 4534, 4542
//        4548, 4549, 4565, 4574, 4575, 4583, 4591, 4604, 4609, 4616, 4619
//        4623, 4631, 4635, 4637, 4639, 4641, 4643, 4644, 4647, 4656, 4673
//        
//
// All cases over 4000 have been checked for pointers and commented for variables with pointers
//
// currently adding directions to headers between 0-400



extern "C" {
#include "panda_plugin.h"
}

#include <string.h>
#include "syscalls2.h" 
#include "panda_common.h"
#include "panda_plugin_plugin.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_enter.h"

}
/* <MN FAROS: begin> */

#include <fstream>
extern std::ofstream faros_syscall;

#define ULONG_SIZE 4
#define GENERIC_MAPPING_SIZE 16
#define POINTER_SIZE 4
#define PRIVILEGE_SET_SIZE 8
#define SECURITY_DESCRIPTOR_SIZE 22
#define OBJECT_TYPE_LIST_SIZE 12
#define ACCESS_MASK_SIZE 4
#define LARGE_INTEGER_SIZE 8

#define IN_DIR 1
#define OUT_DIR 2
#define IN_opt_DIR 3
#define OUT_opt_DIR 4
#define UNKNOWN_DIR 5
#define MEM_SIZE_THRESHOLD 1000


/* This keeps the whole syscall info. that 
 *  should be passed to FAROS plugin
 */
ReturnPoint rp;

/* Initialize SyscallArgs structure */
void init_args(){
    rp.SyscallArgs.arg_number = 0;
}

int get_DeviceIoControlFile_info(CPUState *env, packetInfo **pi, uint32_t io_control_code) {

    get_DeviceIoControlFile_in_buffer_32 (env, pi, io_control_code);
    return 1;
}

/* <MN FAROS: end> */


void syscall_enter_switch_windows7_x86 ( CPUState *env, target_ulong pc ) {  // osarch
#ifdef TARGET_I386  // GUARD

  //  OsiProc *current = get_current_process(env);
  //  if(!strcmp(current->name,"SnippingTool.e")){

    rp.ordinal = EAX;                        // CALLNO
    rp.proc_id = panda_current_asid(env);
    rp.retaddr = calc_retaddr(env, pc);

    init_args();


    switch( EAX ) {                          // CALLNO
// 0 NTSTATUS NtAcceptConnectPort ['_Out_ PHANDLE PortHandle', '_In_ PVOID PortContext', '_In_ PPORT_MESSAGE ConnectionRequest', '_In_ BOOLEAN AcceptConnection', '_In_ PPORT_VIEW ServerView', '_Out_ PREMOTE_PORT_VIEW ClientView']
/*case 0: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtAcceptConnectPort_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 1 NTSTATUS NtAccessCheck ['_In_ PSECURITY_DESCRIPTOR SecurityDescriptor', '_In_ HANDLE ClientToken', '_In_ ACCESS_MASK DesiredAccess', '_In_ PGENERIC_MAPPING GenericMapping', '_Out_ PPRIVILEGE_SET PrivilegeSet', '_In_ PULONG ReturnLength', '_Out_ PACCESS_MASK GrantedAccess', '_Out_ PNTSTATUS AccessStatus']
case 1: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3 , GENERIC_MAPPING_SIZE) == -1)
   AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
PPP_RUN_CB(on_NtAccessCheck_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 2 NTSTATUS NtAccessCheckAndAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PVOID HandleId', '_In_ PUNICODE_STRING ObjectTypeName', '_In_ PUNICODE_STRING ObjectName', '_In_ PSECURITY_DESCRIPTOR SecurityDescriptor', '_In_ ACCESS_MASK DesiredAccess', '_In_ PGENERIC_MAPPING GenericMapping', '_In_ BOOLEAN ObjectCreation', '_Out_ PACCESS_MASK GrantedAccess', '_Out_ PNTSTATUS AccessStatus', '_Out_ PBOOLEAN GenerateOnClose']
case 2: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t)); 
if(AddArgument_pointer(env, 4, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(AddArgument_pointer(env, 9, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtAccessCheckAndAuditAlarm_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 3 NTSTATUS NtAccessCheckByType ['PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeLength', ' PGENERIC_MAPPING GenericMapping', ' PPRIVILEGE_SET PrivilegeSet', ' ULONG PrivilegeSetLength', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus']
case 3: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, POINTER_SIZE))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, OBJECT_TYPE_LIST_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(AddArgument_pointer(env, 9, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
if(AddArgument_pointer(env, 10, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtAccessCheckByType_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;

//<FAROS MG>
// 4 NTSTATUS NtAccessCheckByTypeAndAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
case 4: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);
uint32_t arg15 = get_32(env, 15);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
if(AddArgument_pointer(env, 11, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
if(AddArgument_pointer(env, 14, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
}; break;

// 5 NTSTATUS NtAccessCheckByTypeResultList ['PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' HANDLE ClientToken', ' ACCESS_MASK DesiredAccess', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeLength', ' PGENERIC_MAPPING GenericMapping', ' PPRIVILEGE_SET PrivilegeSet', ' ULONG PrivilegeSetLength', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus']
case 5: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(AddArgument_pointer(env, 9, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
if(AddArgument_pointer(env, 10, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtAccessCheckByTypeResultList_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10); 
}; break;

//<FAROS MG>
// 6 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
case 6: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);
uint32_t arg15 = get_32(env, 15);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
if(AddArgument_pointer(env, 11, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
if(AddArgument_pointer(env, 14, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 7 NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle ['PUNICODE_STRING SubsystemName', ' PVOID HandleId', ' HANDLE ClientToken', ' PUNICODE_STRING ObjectTypeName', ' PUNICODE_STRING ObjectName', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' PSID PrincipalSelfSid', ' ACCESS_MASK DesiredAccess', ' AUDIT_EVENT_TYPE AuditType', ' ULONG Flags', ' POBJECT_TYPE_LIST ObjectTypeList', ' ULONG ObjectTypeListLength', ' PGENERIC_MAPPING GenericMapping', ' BOOLEAN ObjectCreation', ' PACCESS_MASK GrantedAccess', ' PNTSTATUS AccessStatus', ' PBOOLEAN GenerateOnClose']
case 7: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);
uint32_t arg15 = get_32(env, 15);
uint32_t arg16 = get_32(env, 16);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
if(AddArgument_pointer(env, 12, GENERIC_MAPPING_SIZE) == -1)
    AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
AddArgument(env, (void *)&arg16, 16, sizeof(uint32_t));
}; break;

// 8 NTSTATUS NtAddAtom ['_In_ PWSTR AtomName', ' ULONG AtomNameLength', ' PRTL_ATOM Atom']
case 8: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_pwstr(env, 0, arg1))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtAddAtom_enter, env,pc,arg0,arg1,arg2) ; 
}; break;

//<FAROS MG>
// 9 NTSTATUS NtAddBootEntry ['PBOOT_ENTRY BootEntry', ' PULONG Id']
case 9: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 10 NTSTATUS NtAddDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry', ' PULONG Id']
case 10: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 11 NTSTATUS NtAdjustGroupsToken ['_In_ HANDLE TokenHandle', '_In_ BOOLEAN ResetToDefault', '_In_ PTOKEN_GROUPS NewState', '_In_ ULONG BufferLength', '_Out_ PTOKEN_GROUPS PreviousState', '_Out_ PULONG ReturnLength']
case 11: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtAdjustGroupsToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;

// 12 NTSTATUS NtAdjustPrivilegesToken ['_In_ HANDLE TokenHandle', '_In_ BOOLEAN DisableAllPrivileges', '_In_ PTOKEN_PRIVILEGES NewState', '_In_ ULONG BufferLength', '_Out_ PTOKEN_PRIVILEGES PreviousState', '_Out_ PULONG ReturnLength']
case 12: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtAdjustPrivilegesToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;

// 13 NTSTATUS NtAlertResumeThread ['_In_ HANDLE ThreadHandle', '_Out_ PULONG SuspendCount']
case 13: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtAlertResumeThread_enter, env,pc,arg0,arg1) ; 
}; break;

// 14 NTSTATUS NtAlertThread ['_In_ HANDLE ThreadHandle']
case 14: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtAlertThread_enter, env,pc,arg0) ; 
}; break;

// 15 NTSTATUS NtAllocateLocallyUniqueId ['_Out_ LUID *LocallyUniqueId']
case 15: {
target_ulong arg0 = get_pointer(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtAllocateLocallyUniqueId_enter, env,pc,arg0) ; 
}; break;

//<FAROS MG>
// 16 NTSTATUS NtAllocateReserveObject ['PHANDLE MemoryReserveHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' MEMORY_RESERVE_TYPE Type']
case 16: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 17 NTSTATUS NtAllocateUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG NumberOfPages', ' PULONG UserPfnArray']
case 17: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtAllocateUserPhysicalPages_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 18 NTSTATUS NtAllocateUuids ['_Out_ PULARGE_INTEGER Time', '_Out_ PULONG Range', '_Out_ PULONG Sequence', ' PUCHAR Seed']
case 18: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtAllocateUuids_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 19 NTSTATUS NtAllocateVirtualMemory ['_In_ HANDLE ProcessHandle', '_In_ PVOID *BaseAddress', '_In_ ULONG ZeroBits', '_In_ PSIZE_T RegionSize', '_In_ ULONG AllocationType', '_In_ ULONG Protect']
case 19: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtAllocateVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;

// 20 NTSTATUS NtAlpcAcceptConnectPort ['PHANDLE PortHandle', ' HANDLE ConnectionPortHandle', ' ULONG Flags', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes', ' PVOID PortContext', ' PPORT_MESSAGE ConnectionRequest', ' PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes', ' BOOLEAN AcceptConnection']
case 20: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
}; break;

// 21 NTSTATUS NtAlpcCancelMessage ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_CONTEXT_ATTR MessageContext']
case 21: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCancelMessage_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 22 NTSTATUS NtAlpcConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes', ' ULONG Flags', ' PSID RequiredServerSid', ' PPORT_MESSAGE ConnectionMessage', ' PULONG BufferLength', ' PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes', ' PALPC_MESSAGE_ATTRIBUTES InMessageAttributes', ' PLARGE_INTEGER Timeout']
case 22: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
if(AddArgument_pointer(env, 10, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcConnectPort_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 23 NTSTATUS NtAlpcCreatePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PALPC_PORT_ATTRIBUTES PortAttributes']
case 23: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCreatePort_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 24 NTSTATUS NtAlpcCreatePortSection ['HANDLE PortHandle', ' ULONG Flags', ' HANDLE SectionHandle', ' SIZE_T SectionSize', ' PALPC_HANDLE AlpcSectionHandle', ' PSIZE_T ActualSectionSize']
case 24: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCreatePortSection_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 25 NTSTATUS NtAlpcCreateResourceReserve ['HANDLE PortHandle', ' ULONG Flags', ' SIZE_T MessageSize', ' PALPC_HANDLE ResourceId']
case 25: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCreateResourceReserve_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 26 NTSTATUS NtAlpcCreateSectionView ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_DATA_VIEW_ATTR ViewAttributes']
case 26: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCreateSectionView_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 27 NTSTATUS NtAlpcCreateSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' PALPC_SECURITY_ATTR SecurityAttribute']
case 27: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcCreateSecurityContext_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 28 NTSTATUS NtAlpcDeletePortSection ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE SectionHandle']
case 28: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcDeletePortSection_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 29 NTSTATUS NtAlpcDeleteResourceReserve ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ResourceId']
case 29: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcDeleteResourceReserve_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 30 NTSTATUS NtAlpcDeleteSectionView ['HANDLE PortHandle', ' ULONG Flags', ' PVOID ViewBase']
case 30: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcDeleteSectionView_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 31 NTSTATUS NtAlpcDeleteSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ContextHandle']
case 31: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcDeleteSecurityContext_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 32 NTSTATUS NtAlpcDisconnectPort ['HANDLE PortHandle', ' ULONG Flags']
case 32: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcDisconnectPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 33 NTSTATUS NtAlpcImpersonateClientOfPort ['HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' PVOID Reserved']
case 33: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcImpersonateClientOfPort_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 34 NTSTATUS NtAlpcOpenSenderProcess ['PHANDLE ProcessHandle', ' HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ULONG Flags', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 34: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 5))
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcOpenSenderProcess_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 35 NTSTATUS NtAlpcOpenSenderThread ['PHANDLE ThreadHandle', ' HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ULONG Flags', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 35: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env,5))
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcOpenSenderThread_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 36 NTSTATUS NtAlpcQueryInformation ['HANDLE PortHandle', ' ALPC_PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length', ' PULONG ReturnLength']
case 36: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcQueryInformation_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 37 NTSTATUS NtAlpcQueryInformationMessage ['HANDLE PortHandle', ' PPORT_MESSAGE PortMessage', ' ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass', ' PVOID MessageInformation', ' ULONG Length', ' PULONG ReturnLength']
case 37: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcQueryInformationMessage_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 38 NTSTATUS NtAlpcRevokeSecurityContext ['HANDLE PortHandle', ' ULONG Flags', ' ALPC_HANDLE ContextHandle']
case 38: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcRevokeSecurityContext_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 39 NTSTATUS NTAPI NtAlpcSendWaitReceivePort [ HANDLE PortHandle,DWORD SendFlags,PLPC_MESSAGE SendMessage OPTIONAL,PVOID InMessageBuffer OPTIONAL, PLPC_MESSAGE ReceiveBuffer OPTIONAL,PULONGReceiveBufferSize OPTIONAL,PVOID OutMessageBuffer OPTIONAL,PLARGE_INTEGER Timeout OPTIONAL]
case 39: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
	AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
}; break;

// 40 NTSTATUS NtAlpcSetInformation ['HANDLE PortHandle', ' ALPC_PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG Length']
case 40: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtAlpcSetInformation_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 41 NTSTATUS NtApphelpCacheControl ['APPHELPCOMMAND type', ' PVOID buf']
case 41: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtApphelpCacheControl_enter, env,pc,arg0,arg1) ; 
}; break;

// 42 NTSTATUS NtAreMappedFilesTheSame ['PVOID File1MappedAsAnImage', ' PVOID File2MappedAsFile']
case 42: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtAreMappedFilesTheSame_enter, env,pc,arg0,arg1) ; 
}; break;
// 43 NTSTATUS NtAssignProcessToJobObject ['HANDLE JobHandle', ' HANDLE ProcessHandle']
case 43: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtAssignProcessToJobObject_enter, env,pc,arg0,arg1) ; 
}; break;
// 44 NTSTATUS NtCallbackReturn ['_In_ PVOID Result', '_In_ ULONG ResultLength', '_In_ NTSTATUS Status']
case 44: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, arg1) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCallbackReturn_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 45 NTSTATUS NtCancelIoFile ['_In_ HANDLE FileHandle', '_Out_ PIO_STATUS_BLOCK IoStatusBlock']
case 45: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtCancelIoFile_enter, env,pc,arg0,arg1) ; 
}; break;
// 46 NTSTATUS NtCancelIoFileEx ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoRequestToCancel', ' PIO_STATUS_BLOCK IoStatusBlock']
case 46: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCancelIoFileEx_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 47 NTSTATUS NtCancelSynchronousIoFile ['HANDLE ThreadHandle', ' PIO_STATUS_BLOCK IoRequestToCancel', ' PIO_STATUS_BLOCK IoStatusBlock']
case 47: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCancelSynchronousIoFile_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 48 NTSTATUS NtCancelTimer ['_In_ HANDLE TimerHandle', '_Out_ PBOOLEAN CurrentState']
case 48: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtCancelTimer_enter, env,pc,arg0,arg1) ; 
}; break;
// 49 NTSTATUS NtClearEvent ['_In_ HANDLE EventHandle']
case 49: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtClearEvent_enter, env,pc,arg0) ; 
}; break;
// 50 NTSTATUS NtClose ['_In_ HANDLE Handle']
case 50: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtClose_enter, env,pc,arg0) ; 
}; break;
// 51 NTSTATUS NtCloseObjectAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PVOID HandleId', '_In_ BOOLEAN GenerateOnClose']
case 51: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCloseObjectAuditAlarm_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 52 NTSTATUS NtCommitComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 52: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCommitComplete_enter, env,pc,arg0,arg1) ; 
}; break;
// 53 NTSTATUS NtCommitEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 53: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCommitEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 54 NTSTATUS NtCommitTransaction ['HANDLE TransactionHandle', ' BOOLEAN Wait']
case 54: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCommitTransaction_enter, env,pc,arg0,arg1) ; 
}; break;
// 55 NTSTATUS NtCompactKeys ['_In_ ULONG Count', '_In_ PHANDLE KeyArray']
case 55: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtCompactKeys_enter, env,pc,arg0,arg1) ; 
}; break;
// 56 NTSTATUS NtCompareTokens ['HANDLE FirstTokenHandle', ' HANDLE SecondTokenHandle', ' PBOOLEAN Equal']
case 56: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCompareTokens_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 57 NTSTATUS NtCompleteConnectPort ['_In_ HANDLE PortHandle']
case 57: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtCompleteConnectPort_enter, env,pc,arg0) ; 
}; break;
// 58 NTSTATUS NtCompressKey ['_In_ HANDLE Key']
case 58: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtCompressKey_enter, env,pc,arg0) ; 
}; break;
// 59 NTSTATUS NtConnectPort ['_Out_ PHANDLE PortHandle', '_In_ PUNICODE_STRING PortName', '_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos', '_IN_opt_ PPORT_VIEW ClientView', '_Out_ PREMOTE_PORT_VIEW ServerView', '_Out_ PULONG MaxMessageLength', '_In_ PVOID ConnectionInformation', '_In_ PULONG ConnectionInformationLength']
case 59: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
PPP_RUN_CB(on_NtConnectPort_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 60 NTSTATUS NtContinue ['_In_ PCONTEXT Context', '_In_ BOOLEAN TestAlert']
case 60: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtContinue_enter, env,pc,arg0,arg1) ; 
}; break;
// 61 NTSTATUS NtCreateDebugObject ['_Out_ PHANDLE DebugHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ BOOLEAN KillProcessOnExit']
case 61: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));

AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateDebugObject_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 62 NTSTATUS NtCreateDirectoryObject ['_Out_ PHANDLE DirectoryHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 62: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
    
PPP_RUN_CB(on_NtCreateDirectoryObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 63 NTSTATUS NtCreateEnlistment ['PHANDLE EnlistmentHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE ResourceManagerHandle', ' HANDLE TransactionHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG CreateOptions', ' NOTIFICATION_MASK NotificationMask', ' PVOID EnlistmentKey']
case 63: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateEnlistment_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 64 NTSTATUS NtCreateEvent ['_Out_ PHANDLE EventHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ EVENT_TYPE EventType', '_In_ BOOLEAN InitialState']
case 64: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateEvent_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 65 NTSTATUS NtCreateEventPair ['_Out_ PHANDLE EventPairHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 65: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateEventPair_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 66 NTSTATUS NtCreateFile ['_Out_ PHANDLE FileHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ PLARGE_INTEGER AllocationSize', '_In_ ULONG FileAttributes', '_In_ ULONG ShareAccess', '_In_ ULONG CreateDisposition', '_In_ ULONG CreateOptions', '_In_ PVOID EaBuffer', '_In_ ULONG EaLength']
case 66: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(AddArgument_pointer(env, 9, arg10) == -1)
	AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 67 NTSTATUS NtCreateIoCompletion ['_Out_ PHANDLE IoCompletionHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ ULONG NumberOfConcurrentThreads']
case 67: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateIoCompletion_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 68 NTSTATUS NtCreateJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 68: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateJobObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 69 NTSTATUS NtCreateJobSet ['ULONG NumJob', ' PJOB_SET_ARRAY UserJobSet', ' ULONG Flags']
case 69: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateJobSet_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 70 NTSTATUS NtCreateKey ['_Out_PHANDLE KeyHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ ULONG TitleIndex', '_In_ PUNICODE_STRING Class', '_In_ ULONG CreateOptions', '_Out_ PULONG Disposition']
case 70: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 71 NTSTATUS NtCreateKeyedEvent ['_Out_ PHANDLE KeyedEventHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ ULONG Flags']
case 71: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateKeyedEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 72 NTSTATUS NtCreateKeyTransacted ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG TitleIndex', ' PUNICODE_STRING Class', ' ULONG CreateOptions', ' HANDLE TransactionHandle', ' PULONG Disposition']
case 72: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateKeyTransacted_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 73 NTSTATUS NtCreateMailslotFile ['_Out_ PHANDLE MailSlotFileHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG FileAttributes', '_In_ ULONG ShareAccess', '_In_ ULONG MaxMessageSize', '_In_ PLARGE_INTEGER TimeOut']
case 73: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateMailslotFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 74 NTSTATUS NtCreateMutant ['_Out_PHANDLE MutantHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ BOOLEAN InitialOwner']
case 74: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateMutant_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 75 NTSTATUS NtCreateNamedPipeFile ['_Out_ PHANDLE NamedPipeFileHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG ShareAccess', '_In_ ULONG CreateDisposition', '_In_ ULONG CreateOptions', '_In_ ULONG WriteModeMessage', '_In_ ULONG ReadModeMessage', '_In_ ULONG NonBlocking', '_In_ ULONG MaxInstances', '_In_ ULONG InBufferSize', '_In_ ULONG OutBufferSize', '_In_ PLARGE_INTEGER DefaultTimeOut']
case 75: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
if(AddArgument_pointer(env, 13, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateNamedPipeFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13) ; 
}; break;
// 76 NTSTATUS NtCreatePagingFile ['_In_ PUNICODE_STRING FileName', '_In_ PLARGE_INTEGER InitialSize', '_In_ PLARGE_INTEGER MaxiumSize', '_Out_ ULONG Reserved']
case 76: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreatePagingFile_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 77 NTSTATUS NtCreatePort ['_Out_ PHANDLE PortHandle', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ ULONG MaxConnectionInfoLength', '_In_ ULONG MaxMessageLength', '_In_opt_ ULONG MaxPoolUsage']
case 77: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreatePort_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 78 NTSTATUS NtCreatePrivateNamespace ['PHANDLE NamespaceHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PVOID BoundaryDescriptor']
case 78: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreatePrivateNamespace_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 79 NTSTATUS c ['_Out_ PHANDLE ProcessHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ HANDLE ParentProcess', '_In_ BOOLEAN InheritObjectTable', '_In_ HANDLE SectionHandle', '_In_ HANDLE DebugPort', '_In_ HANDLE ExceptionPort']
case 79: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateProcess_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 80 NTSTATUS NtCreateProcessEx ['PHANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ParentProcess', ' ULONG Flags', ' HANDLE SectionHandle', ' HANDLE DebugPort', ' HANDLE ExceptionPort', ' BOOLEAN InJob']
case 80: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateProcessEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 81 NTSTATUS NtCreateProfile ['_Out_ PHANDLE ProfileHandle', '_In_ HANDLE ProcessHandle', '_In_ PVOID ImageBase', '_In_ ULONG ImageSize', '_In_ ULONG Granularity', '_In_ PVOID Buffer', '_In_ ULONG ProfilingSize', '_In_ KPROFILE_SOURCE Source', '_In_ KAFFINITY ProcessorMask']
case 81: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateProfile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 82 NTSTATUS NtCreateProfileEx ['PHANDLE ProfileHandle', ' HANDLE Process', ' PVOID ProfileBase', ' SIZE_T ProfileSize', ' ULONG BucketSize', ' PULONG Buffer', ' ULONG BufferSize', ' KPROFILE_SOURCE ProfileSource', ' ULONG GroupAffinityCount', ' PGROUP_AFFINITY GroupAffinity']
case 82: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateProfileEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 83 NTSTATUS NtCreateResourceManager ['PHANDLE ResourceManagerHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE TmHandle', ' LPGUID RmGuid', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG CreateOptions', ' PUNICODE_STRING Description']
case 83: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 6))
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateResourceManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 84 NTSTATUS NtCreateSection ['_Out_ PHANDLE SectionHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ PLARGE_INTEGER MaximumSize', '_In_ ULONG SectionPageProtection', '_In_ ULONG AllocationAttributes', '_In_ HANDLE FileHandle']
case 84: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateSection_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 85 NTSTATUS NtCreateSemaphore ['_Out_ PHANDLE SemaphoreHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ LONG InitialCount', '_In_ LONG MaximumCount']
case 85: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
int32_t arg3 = get_s32(env, 3);
int32_t arg4 = get_s32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(int32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(int32_t));
PPP_RUN_CB(on_NtCreateSemaphore_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 86 NTSTATUS NtCreateSymbolicLinkObject ['_Out_ PHANDLE SymbolicLinkHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ PUNICODE_STRING Name']
case 86: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateSymbolicLinkObject_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 87 NTSTATUS NtCreateThread ['_Out_ PHANDLE ThreadHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ HANDLE ProcessHandle', '_Out_ PCLIENT_ID ClientId', '_In_ PCONTEXT ThreadContext', '_In_ PINITIAL_TEB UserStack', '_In_ BOOLEAN CreateSuspended']
case 87: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateThread_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 88 NTSTATUS NtCreateThreadEx ['PHANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE ProcessHandle', ' PVOID StartRoutine', ' PVOID Argument', ' ULONG CreateFlags', ' ULONG_PTR ZeroBits', ' SIZE_T StackSize', ' SIZE_T MaximumStackSize', ' PPS_ATTRIBUTE_LIST AttributeList']
case 88: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateThreadEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 89 NTSTATUS NtCreateTimer ['_Out_ PHANDLE TimerHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ TIMER_TYPE TimerType']
case 89: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateTimer_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 90 NTSTATUS NtCreateToken ['_Out_ PHANDLE TokenHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ TOKEN_TYPE TokenType', '_In_ PLUID AuthenticationId', '_In_ PLARGE_INTEGER ExpirationTime', '_In_ PTOKEN_USER TokenUser', '_In_ PTOKEN_GROUPS TokenGroups', '_In_ PTOKEN_PRIVILEGES TokenPrivileges', '_In_ PTOKEN_OWNER TokenOwner', '_In_ PTOKEN_PRIMARY_GROUP TokenPrimaryGroup', '_In_ PTOKEN_DEFAULT_DACL TokenDefaultDacl', '_In_ PTOKEN_SOURCE TokenSource']
case 90: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12) ; 
}; break;
// 91 NTSTATUS NtCreateTransaction ['PHANDLE TransactionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LPGUID Uow', ' HANDLE TmHandle', ' ULONG CreateOptions', ' ULONG IsolationLevel', ' ULONG IsolationFlags', ' PLARGE_INTEGER Timeout', ' PUNICODE_STRING Description']
case 91: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 9))
    AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateTransaction_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 92 NTSTATUS NtCreateTransactionManager ['PHANDLE TmHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LogFileName', ' ULONG CreateOptions', ' ULONG CommitStrength']
case 92: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateTransactionManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 93 NTSTATUS NtCreateUserProcess ['PHANDLE ProcessHandle', ' PHANDLE ThreadHandle', ' ACCESS_MASK ProcessDesiredAccess', ' ACCESS_MASK ThreadDesiredAccess', ' POBJECT_ATTRIBUTES ProcessObjectAttributes', ' POBJECT_ATTRIBUTES ThreadObjectAttributes', ' ULONG ProcessFlags', ' ULONG ThreadFlags', ' PRTL_USER_PROCESS_PARAMETERS ProcessParameters', ' PPROCESS_CREATE_INFO CreateInfo', ' PPROCESS_ATTRIBUTE_LIST AttributeList']
case 93: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 5))
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateUserProcess_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 94 NTSTATUS NtCreateWaitablePort ['PHANDLE PortHandle', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG MaxConnectInfoLength', ' ULONG MaxDataLength', ' ULONG NPMessageQueueSize']
case 94: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtCreateWaitablePort_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 95 NTSTATUS NtCreateWorkerFactory ['PHANDLE WorkerFactoryHandleReturn', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE CompletionPortHandle', ' HANDLE WorkerProcessHandle', ' PVOID StartRoutine', ' PVOID StartParameter', ' ULONG MaxThreadCount', ' SIZE_T StackReserve', ' SIZE_T StackCommit']
case 95: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
//PPP_RUN_CB(on_NtCreateWorkerFactory_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 96 NTSTATUS NtDebugActiveProcess ['_In_ HANDLE Process', '_In_ HANDLE DebugObject']
case 96: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtDebugActiveProcess_enter, env,pc,arg0,arg1) ; 
}; break;
// 97 NTSTATUS NtDebugContinue ['HANDLE DebugObject', ' PCLIENT_ID AppClientId', ' NTSTATUS ContinueStatus']
case 97: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtDebugContinue_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 98 NTSTATUS NtDelayExecution ['_In_ BOOLEAN Alertable', '_In_ LARGE_INTEGER *Interval']
case 98: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
PPP_RUN_CB(on_NtDelayExecution_enter, env,pc,arg0,arg1) ; 
}; break;
// 99 NTSTATUS NtDeleteAtom ['_In_ RTL_ATOM Atom']
case 99: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtDeleteAtom_enter, env,pc,arg0) ; 
}; break;
// 100 NTSTATUS NtDeleteBootEntry ['ULONG Id']
case 100: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtDeleteBootEntry_enter, env,pc,arg0) ; 
}; break;
// 101 NTSTATUS NtDeleteDriverEntry ['ULONG Id']
case 101: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtDeleteDriverEntry_enter, env,pc,arg0) ; 
}; break;
// 102 NTSTATUS NtDeleteFile ['_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 102: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtDeleteFile_enter, env,pc,arg0) ; 
}; break;
// 103 NTSTATUS NtDeleteKey ['_In_ HANDLE KeyHandle']
case 103: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtDeleteKey_enter, env,pc,arg0) ; 
}; break;
// 104 NTSTATUS NtDeleteObjectAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PVOID HandleId', '_In_ BOOLEAN GenerateOnClose']
case 104: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtDeleteObjectAuditAlarm_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 105 NTSTATUS NtDeletePrivateNamespace ['HANDLE NamespaceHandle']
case 105: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtDeletePrivateNamespace_enter, env,pc,arg0) ; 
}; break;
// 106 NTSTATUS NtDeleteValueKey ['_In_ HANDLE KeyHandle', '_In_ PUNICODE_STRING ValueName']
case 106: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtDeleteValueKey_enter, env,pc,arg0,arg1) ; 
}; break;*/
// 107 NTSTATUS NtDeviceIoControlFile ['_In_ HANDLE DeviceHandle', '_In_ HANDLE Event', '_In_ PIO_APC_ROUTINE UserApcRoutine', '_In_ PVOID UserApcContext', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG IoControlCode', '_In_ PVOID InputBuffer', '_In_ ULONG InputBufferSize', '_Out_ PVOID OutputBuffer', '_In_ ULONG OutputBufferSize']
case 107: {
/*uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);*/
uint32_t arg5 = get_32(env, 5);
/*uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);*/

packetInfo *pi = NULL;
get_DeviceIoControlFile_info(env, &pi, arg5);

PPP_RUN_CB(on_NtDeviceIoControlFile_enter, env, pc, pi); 

}; break;
/*
// 108 NTSTATUS NtDisableLastKnownGood ['']
case 108: {
//PPP_RUN_CB(on_NtDisableLastKnownGood_enter, env,pc) ; 
}; break;
// 109 NTSTATUS NtDisplayString ['_In_ PUNICODE_STRING DisplayString']
case 109: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtDisplayString_enter, env,pc,arg0) ; 
}; break;
// 110 NTSTATUS NtDrawText ['PUNICODE_STRING Text']
case 110: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtDrawText_enter, env,pc,arg0) ; 
}; break;
// 111 NTSTATUS NtDuplicateObject ['_In_ HANDLE SourceProcessHandle', '_In_ HANDLE SourceHandle', '_In_ HANDLE TargetProcessHandle', '_Out_ PHANDLE TargetHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ ULONG HandleAttributes', '_In_ ULONG Options']
case 111: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtDuplicateObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 112 NTSTATUS NtDuplicateToken ['_In_ HANDLE ExistingTokenHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ BOOLEAN EffectiveOnly', '_In_ TOKEN_TYPE TokenType', '_Out_ PHANDLE NewTokenHandle']
case 112: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtDuplicateToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 113 NTSTATUS NtEnableLastKnownGood ['']
case 113: {
//PPP_RUN_CB(on_NtEnableLastKnownGood_enter, env,pc) ; 
}; break;
// 114 NTSTATUS NtEnumerateBootEntries ['PVOID Buffer', ' PULONG BufferLength']
case 114: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
//if(AddArgument_pointer(env, 0, arg1) == -1)
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtEnumerateBootEntries_enter, env,pc,arg0,arg1) ; 
}; break;
// 115 NTSTATUS NtEnumerateDriverEntries ['PVOID Buffer', ' PULONG BufferLength']
case 115: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtEnumerateDriverEntries_enter, env,pc,arg0,arg1) ; 
}; break;
// 116 NTSTATUS NtEnumerateKey ['_In_ HANDLE KeyHandle', '_In_ ULONG Index', '_In_ KEY_INFORMATION_CLASS KeyInformationClass', '_Out_ PVOID KeyInformation', '_In_ ULONG Length', '_Out_ PULONG ResultLength']
case 116: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtEnumerateKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 117 NTSTATUS NtEnumerateSystemEnvironmentValuesEx ['ULONG InformationClass', ' PVOID Buffer', ' ULONG BufferLength']
case 117: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, arg2) == -1)
        AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtEnumerateSystemEnvironmentValuesEx_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 118 NTSTATUS NtEnumerateTransactionObject ['HANDLE RootObjectHandle', ' KTMOBJECT_TYPE QueryType', ' PKTMOBJECT_CURSOR ObjectCursor', ' ULONG ObjectCursorLength', ' PULONG ReturnLength']
case 118: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtEnumerateTransactionObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 119 NTSTATUS NtEnumerateValueKey ['_In_ HANDLE KeyHandle', '_In_ ULONG Index', '_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', '_Out_ PVOID KeyValueInformation', '_In_ ULONG Length', '_Out_ PULONG ResultLength']
case 119: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtEnumerateValueKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 120 NTSTATUS NtExtendSection ['_In_ HANDLE SectionHandle', '_In_ PLARGE_INTEGER NewMaximumSize']
case 120: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtExtendSection_enter, env,pc,arg0,arg1) ; 
}; break;
// 121 NTSTATUS NtFilterToken ['HANDLE ExistingTokenHandle', ' ULONG Flags', ' PTOKEN_GROUPS SidsToDisable', ' PTOKEN_PRIVILEGES PrivilegesToDelete', ' PTOKEN_GROUPS RestrictedSids', ' PHANDLE NewTokenHandle']
case 121: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtFilterToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 122 NTSTATUS NtFindAtom [' PWSTR AtomName', '  ULONG AtomNameLength', ' PRTL_ATOM Atom']
case 122: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_pwstr(env, 0, arg1))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtFindAtom_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 123 NTSTATUS NtFlushBuffersFile ['_In_ HANDLE FileHandle', '_Out_ PIO_STATUS_BLOCK IoStatusBlock']
case 123: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtFlushBuffersFile_enter, env,pc,arg0,arg1) ; 
}; break;
// 124 NTSTATUS NtFlushInstallUILanguage ['LANGID InstallUILanguage', ' ULONG SetComittedFlag']
case 124: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtFlushInstallUILanguage_enter, env,pc,arg0,arg1) ; 
}; break;
// 125 NTSTATUS NtFlushInstructionCache ['_In_ HANDLE ProcessHandle', '_In_ PVOID BaseAddress', '_In_ ULONG NumberOfBytesToFlush']
case 125: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtFlushInstructionCache_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 126 NTSTATUS NtFlushKey ['_In_ HANDLE KeyHandle']
case 126: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtFlushKey_enter, env,pc,arg0) ; 
}; break;
// 127 VOID NtFlushProcessWriteBuffers ['']
case 127: {
//PPP_RUN_CB(on_NtFlushProcessWriteBuffers_enter, env,pc) ; 
}; break;
// 128 NTSTATUS NtFlushVirtualMemory ['_In_ HANDLE ProcessHandle', '_In_opt_ PVOID *BaseAddress', '_In_opt_ PSIZE_T RegionSize', '_Out_ PIO_STATUS_BLOCK IoStatus']
case 128: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtFlushVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 129 NTSTATUS NtFlushWriteBuffer ['VOID']
case 129: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtFlushWriteBuffer_enter, env,pc,arg0) ; 
}; break;
// 130 NTSTATUS NtFreeUserPhysicalPages ['HANDLE ProcessHandle', ' PULONG NumberOfPages', ' PULONG UserPfnArray']
case 130: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtFreeUserPhysicalPages_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 131 NTSTATUS NtFreeVirtualMemory ['_In_ HANDLE ProcessHandle', '_In_ PVOID *BaseAddress', '_In_opt_ PSIZE_T RegionSize', '_In_ ULONG FreeType']
case 131: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtFreeVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 132 NTSTATUS NtFreezeRegistry ['ULONG TimeOutInSeconds']
case 132: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtFreezeRegistry_enter, env,pc,arg0) ; 
}; break;
// 133 NTSTATUS NtFreezeTransactions ['PLARGE_INTEGER FreezeTimeout', ' PLARGE_INTEGER ThawTimeout']
case 133: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtFreezeTransactions_enter, env,pc,arg0,arg1) ; 
}; break;
// 134 NTSTATUS NtFsControlFile ['_In_ HANDLE DeviceHandle', '_In_ HANDLE Event', '_In_ PIO_APC_ROUTINE ApcRoutine', '_In_ PVOID ApcContext', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG IoControlCode', '_In_ PVOID InputBuffer', '_In_ ULONG InputBufferSize', '_Out_ PVOID OutputBuffer', '_In_ ULONG OutputBufferSize']
case 134: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, arg7) == -1)
        AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, arg9) == -1)
        AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
PPP_RUN_CB(on_NtFsControlFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 135 NTSTATUS NtGetContextThread ['_In_ HANDLE ThreadHandle', '_Out_ PCONTEXT Context']
case 135: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtGetContextThread_enter, env,pc,arg0,arg1) ; 
}; break;
// 136 ULONG NtGetCurrentProcessorNumber ['']
case 136: {
//PPP_RUN_CB(on_NtGetCurrentProcessorNumber_enter, env,pc) ; 
}; break;
// 137 NTSTATUS NtGetDevicePowerState ['HANDLE Device', ' DEVICE_POWER_STATE *State']
case 137: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetDevicePowerState_enter, env,pc,arg0,arg1) ; 
}; break;
// 138 NTSTATUS NtGetMUIRegistryInfo ['ULONG Flags', ' PULONG DataSize', ' PVOID Data']
case 138: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetMUIRegistryInfo_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 139 NTSTATUS NtGetNextProcess ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Flags', ' PHANDLE NewProcessHandle']
case 139: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetNextProcess_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 140 NTSTATUS NtGetNextThread ['HANDLE ProcessHandle', ' HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' ULONG Flags', ' PHANDLE NewThreadHandle']
case 140: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetNextThread_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 141 NTSTATUS NtGetNlsSectionPtr ['ULONG SectionType', ' ULONG SectionData', ' PVOID ContextData', ' PVOID *SectionPointer', ' PULONG SectionSize']
case 141: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetNlsSectionPtr_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 142 NTSTATUS NtGetNotificationResourceManager ['HANDLE ResourceManagerHandle', ' PTRANSACTION_NOTIFICATION TransactionNotification', ' ULONG NotificationLength', ' PLARGE_INTEGER Timeout', ' PULONG ReturnLength', ' ULONG Asynchronous', ' ULONG_PTR AsynchronousContext']
case 142: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
//PPP_RUN_CB(on_NtGetNotificationResourceManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 143 NTSTATUS NtGetPlugPlayEvent ['ULONG Reserved1', ' ULONG Reserved2', ' PPLUGPLAY_EVENT_BLOCK Buffer', ' ULONG BufferSize']
case 143: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtGetPlugPlayEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 144 NTSTATUS NtGetWriteWatch ['HANDLE ProcessHandle', ' ULONG Flags', ' PVOID BaseAddress', ' ULONG RegionSize', ' PVOID *UserAddressArray', ' PULONG EntriesInUserAddressArray', ' PULONG Granularity']
case 144: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(target_ulong));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtGetWriteWatch_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 145 NTSTATUS NtImpersonateAnonymousToken ['HANDLE Thread']
case 145: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtImpersonateAnonymousToken_enter, env,pc,arg0) ; 
}; break;
// 146 NTSTATUS NtImpersonateClientOfPort ['_In_ HANDLE PortHandle', '_In_ PPORT_MESSAGE ClientMessage']
case 146: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtImpersonateClientOfPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 147 NTSTATUS NtImpersonateThread ['_In_ HANDLE ThreadHandle', '_In_ HANDLE ThreadToImpersonate', '_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService']
case 147: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtImpersonateThread_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 148 NTSTATUS NtInitializeNlsFiles ['PVOID *BaseAddress', ' PLCID DefaultLocaleId', ' PLARGE_INTEGER DefaultCasingTableSize']
case 148: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtInitializeNlsFiles_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 149 NTSTATUS NtInitializeRegistry ['USHORT Flag']
case 149: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtInitializeRegistry_enter, env,pc,arg0) ; 
}; break;
// 150 NTSTATUS NtInitiatePowerAction ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags', ' BOOLEAN Asynchronous']
case 150: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtInitiatePowerAction_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 151 NTSTATUS NtIsProcessInJob ['HANDLE ProcessHandle', ' HANDLE JobHandle']
case 151: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtIsProcessInJob_enter, env,pc,arg0,arg1) ; 
}; break;
// 152 BOOLEAN NtIsSystemResumeAutomatic ['']
case 152: {
//PPP_RUN_CB(on_NtIsSystemResumeAutomatic_enter, env,pc) ; 
}; break;
// 153 NTSTATUS NtIsUILanguageComitted ['']
case 153: {
//PPP_RUN_CB(on_NtIsUILanguageComitted_enter, env,pc) ; 
}; break;
// 154 NTSTATUS NtListenPort ['_In_ HANDLE PortHandle', '_Out_ PPORT_MESSAGE ConnectionRequest']
case 154: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtListenPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 155 NTSTATUS NtLoadDriver ['_In_ PUNICODE_STRING DriverServiceName']
case 155: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtLoadDriver_enter, env,pc,arg0) ; 
}; break;
// 156 NTSTATUS NtLoadKey ['POBJECT_ATTRIBUTES KeyObjectAttributes', ' POBJECT_ATTRIBUTES FileObjectAttributes']
case 156: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtLoadKey_enter, env,pc,arg0,arg1) ; 
}; break;
// 157 NTSTATUS NtLoadKey2 ['_In_ POBJECT_ATTRIBUTES KeyObjectAttributes', '_In_ POBJECT_ATTRIBUTES FileObjectAttributes', '_In_ ULONG Flags']
case 157: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtLoadKey2_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 158 NTSTATUS NtLoadKeyEx ['POBJECT_ATTRIBUTES TargetKey', ' POBJECT_ATTRIBUTES SourceFile', ' ULONG Flags', ' HANDLE TrustClassKey ']
case 158: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtLoadKeyEx_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 159 NTSTATUS NtLockFile ['_In_ HANDLE FileHandle', '_In_ HANDLE Event', '_In_ PIO_APC_ROUTINE ApcRoutine', '_In_ PVOID ApcContext', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ PLARGE_INTEGER ByteOffset', '_In_ PLARGE_INTEGER Length', '_In_ ULONG Key', '_In_ BOOLEAN FailImmediatedly', '_In_ BOOLEAN ExclusiveLock']
case 159: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
PPP_RUN_CB(on_NtLockFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 160 NTSTATUS NtLockProductActivationKeys ['PULONG pPrivateVer', ' PULONG pSafeMode']
case 160: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtLockProductActivationKeys_enter, env,pc,arg0,arg1) ; 
}; break;
// 161 NTSTATUS NtLockRegistryKey ['HANDLE KeyHandle']
case 161: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtLockRegistryKey_enter, env,pc,arg0) ; 
}; break;
// 162 NTSTATUS NtLockVirtualMemory ['_In_ HANDLE ProcessHandle', '_In_ PVOID BaseAddress', '_In_opt_ ULONG NumberOfBytesToLock', '_In_ PULONG NumberOfBytesLocked']
case 162: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtLockVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 163 NTSTATUS NtMakePermanentObject ['HANDLE Object']
case 163: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtMakePermanentObject_enter, env,pc,arg0) ; 
}; break;
// 164 NTSTATUS NtMakeTemporaryObject ['_In_ HANDLE Handle']
case 164: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtMakeTemporaryObject_enter, env,pc,arg0) ; 
}; break;
// 165 NTSTATUS NtMapCMFModule ['ULONG What', ' ULONG Index', ' PULONG CacheIndexOut', ' PULONG CacheFlagsOut', ' PULONG ViewSizeOut', ' PVOID *BaseAddress']
case 165: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtMapCMFModule_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 166 NTSTATUS NtMapUserPhysicalPages ['PVOID *VirtualAddresses', ' ULONG NumberOfPages', ' PULONG UserPfnArray']
case 166: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(target_ulong));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtMapUserPhysicalPages_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 167 NTSTATUS NtMapUserPhysicalPagesScatter ['PVOID *VirtualAddresses', ' ULONG NumberOfPages', ' PULONG UserPfnArray']
case 167: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(target_ulong));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtMapUserPhysicalPagesScatter_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 168 NTSTATUS NtMapViewOfSection ['_In_ HANDLE SectionHandle', '_In_ HANDLE ProcessHandle', '_In_opt_ PVOID *BaseAddress', '_In_ ULONG ZeroBits', '_In_ ULONG CommitSize', '_In_opt_ PLARGE_INTEGER SectionOffset', '_In_opt_ PSIZE_T ViewSize', '_In_ SECTION_INHERIT InheritDisposition', '_In_ ULONG AllocationType', '_In_ ULONG AccessProtection']
case 168: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(target_ulong));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
PPP_RUN_CB(on_NtMapViewOfSection_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 169 NTSTATUS NtModifyBootEntry ['PBOOT_ENTRY BootEntry']
case 169: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtModifyBootEntry_enter, env,pc,arg0) ; 
}; break;
// 170 NTSTATUS NtModifyDriverEntry ['PEFI_DRIVER_ENTRY DriverEntry']
case 170: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtModifyDriverEntry_enter, env,pc,arg0) ; 
}; break;
// 171 NTSTATUS NtNotifyChangeDirectoryFile ['_In_ HANDLE FileHandle', '_In_ HANDLE Event', '_In_ PIO_APC_ROUTINE ApcRoutine', '_In_ PVOID ApcContext', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_Out_ PVOID Buffer', '_In_ ULONG BufferSize', '_In_ ULONG CompletionFilter', '_In_ BOOLEAN WatchTree']
case 171: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, arg6) == -1)
        AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtNotifyChangeDirectoryFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 172 NTSTATUS NtNotifyChangeKey ['_In_ HANDLE KeyHandle', '_In_ HANDLE Event', '_In_ PIO_APC_ROUTINE ApcRoutine', '_In_ PVOID ApcContext', '_In_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG CompletionFilter', '_In_ BOOLEAN Asynchroneous', '_Out_ PVOID ChangeBuffer', '_In_ ULONG Length', '_In_ BOOLEAN WatchSubtree']
case 172: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, arg8) == -1)
        AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
PPP_RUN_CB(on_NtNotifyChangeKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) ; 
}; break;
// 173 NTSTATUS NtNotifyChangeMultipleKeys ['HANDLE MasterKeyHandle', ' ULONG Count', ' POBJECT_ATTRIBUTES SlaveObjects', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' ULONG CompletionFilter', ' BOOLEAN WatchTree', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN Asynchronous']
case 173: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(AddArgument_pointer(env, 9, arg10) == -1)
        AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
PPP_RUN_CB(on_NtNotifyChangeMultipleKeys_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11) ; 
}; break;
// 174 NTSTATUS NtNotifyChangeSession ['HANDLE Session', ' ULONG IoStateSequence', ' PVOID Reserved', ' ULONG Action', ' IO_SESSION_STATE IoState', ' IO_SESSION_STATE IoState2', ' PVOID Buffer', ' ULONG BufferSize']
case 174: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
//PPP_RUN_CB(on_NtNotifyChangeSession_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7) ; 
}; break;
// 175 NTSTATUS NtOpenDirectoryObject ['_Out_ PHANDLE FileHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 175: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenDirectoryObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 176 NTSTATUS NtOpenEnlistment ['PHANDLE EnlistmentHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE ResourceManagerHandle', ' LPGUID EnlistmentGuid', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 176: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenEnlistment_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 177 NTSTATUS NtOpenEvent ['_Out_ PHANDLE EventHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 177: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenEvent_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 178 NTSTATUS NtOpenEventPair ['_Out_ PHANDLE EventPairHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 178: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenEventPair_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 179 NTSTATUS NtOpenFile ['_Out_ PHANDLE FileHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_Out_ PIO_STATUS_BLOCK IoStatusBlock', '_In_ ULONG ShareAccess', '_In_ ULONG OpenOptions']
case 179: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 180 NTSTATUS NtOpenIoCompletion ['_Out_ PHANDLE CompetionPort', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 180: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenIoCompletion_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 181 NTSTATUS NtOpenJobObject ['PHANDLE JobHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 181: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenJobObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 182 NTSTATUS NtOpenKey ['_Out_ PHANDLE KeyHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 182: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenKey_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 183 NTSTATUS NtOpenKeyEx ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG OpenOptions']
case 183: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenKeyEx_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 184 NTSTATUS NtOpenKeyedEvent ['_Out_ PHANDLE EventHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 184: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenKeyedEvent_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 185 NTSTATUS NtOpenKeyTransacted ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE TransactionHandle']
case 185: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenKeyTransacted_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 186 NTSTATUS NtOpenKeyTransactedEx ['PHANDLE KeyHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' ULONG OpenOptions', ' HANDLE TransactionHandle']
case 186: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenKeyTransactedEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 187 NTSTATUS NtOpenMutant ['_Out_ PHANDLE MutantHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 187: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenMutant_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 188 NTSTATUS NtOpenObjectAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PVOID HandleId', '_In_ PUNICODE_STRING ObjectTypeName', '_In_ PUNICODE_STRING ObjectName', '_In_ PSECURITY_DESCRIPTOR SecurityDescriptor', '_In_ HANDLE ClientToken', '_In_ ULONG DesiredAccess', '_In_ ULONG GrantedAccess', '_In_ PPRIVILEGE_SET Privileges', '_In_ BOOLEAN ObjectCreation', '_In_ BOOLEAN AccessGranted', '_Out_ PBOOLEAN GenerateOnClose']
case 188: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenObjectAuditAlarm_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11) ; 
}; break;
// 189 NTSTATUS NtOpenPrivateNamespace ['PHANDLE NamespaceHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PVOID BoundaryDescriptor']
case 189: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenPrivateNamespace_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 190 NTSTATUS NtOpenProcess ['_Out_ PHANDLE ProcessHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ PCLIENT_ID ClientId']
case 190: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenProcess_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 191 NTSTATUS NtOpenProcessToken ['_In_ HANDLE ProcessHandle', '_In_ ACCESS_MASK DesiredAccess', '_Out_ PHANDLE TokenHandle']
case 191: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenProcessToken_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 192 NTSTATUS NtOpenProcessTokenEx ['HANDLE ProcessHandle', ' ACCESS_MASK DesiredAccess', ' ULONG HandleAttributes', ' PHANDLE TokenHandle']
case 192: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenProcessTokenEx_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 193 NTSTATUS NtOpenResourceManager ['PHANDLE ResourceManagerHandle', ' ACCESS_MASK DesiredAccess', ' HANDLE TmHandle', ' LPGUID ResourceManagerGuid', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 193: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 4))
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenResourceManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 194 NTSTATUS NtOpenSection ['_Out_ PHANDLE SectionHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 194: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenSection_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 195 NTSTATUS NtOpenSemaphore ['_Out_ PHANDLE SemaphoreHandle', '_In_ ACCESS_MASK DesiredAcces', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 195: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenSemaphore_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 196 NTSTATUS NtOpenSession ['PHANDLE SessionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes']
case 196: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenSession_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 197 NTSTATUS NtOpenSymbolicLinkObject ['_Out_ PHANDLE SymbolicLinkHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 197: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenSymbolicLinkObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 198 NTSTATUS NtOpenThread ['_Out_ PHANDLE ThreadHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_In_ PCLIENT_ID ClientId']
case 198: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenThread_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 199 NTSTATUS NtOpenThreadToken ['_In_ HANDLE ThreadHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ BOOLEAN OpenAsSelf', '_Out_ PHANDLE TokenHandle']
case 199: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenThreadToken_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 200 NTSTATUS NtOpenThreadTokenEx ['HANDLE ThreadHandle', ' ACCESS_MASK DesiredAccess', ' BOOLEAN OpenAsSelf', ' ULONG HandleAttributes', ' PHANDLE TokenHandle']
case 200: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenThreadTokenEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 201 NTSTATUS NtOpenTimer ['_Out_ PHANDLE TimerHandle', '_In_ ACCESS_MASK DesiredAccess', '_In_ POBJECT_ATTRIBUTES ObjectAttributes']
case 201: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtOpenTimer_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 202 NTSTATUS NtOpenTransaction ['PHANDLE TransactionHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' LPGUID Uow', ' HANDLE TmHandle']
case 202: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenTransaction_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 203 NTSTATUS NtOpenTransactionManager ['PHANDLE TmHandle', ' ACCESS_MASK DesiredAccess', ' POBJECT_ATTRIBUTES ObjectAttributes', ' PUNICODE_STRING LogFileName', ' LPGUID TmIdentity', ' ULONG OpenOptions']
case 203: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 3))
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtOpenTransactionManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 204 NTSTATUS NtPlugPlayControl ['PLUGPLAY_CONTROL_CLASS PlugPlayControlClass', ' PVOID Buffer', ' ULONG BufferSize']
case 204: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, arg2) == -1)
        AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtPlugPlayControl_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 205 NTSTATUS NtPowerInformation ['POWER_INFORMATION_LEVEL PowerInformationLevel', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength']
case 205: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, arg2) == -1)
        AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, arg4) == -1)
        AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtPowerInformation_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 206 NTSTATUS NtPrepareComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 206: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPrepareComplete_enter, env,pc,arg0,arg1) ; 
}; break;
// 207 NTSTATUS NtPrepareEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 207: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPrepareEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 208 NTSTATUS NtPrePrepareComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 208: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPrePrepareComplete_enter, env,pc,arg0,arg1) ; 
}; break;
// 209 NTSTATUS NtPrePrepareEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 209: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPrePrepareEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 210 NTSTATUS NtPrivilegeCheck ['_In_ HANDLE ClientToken', '_In_ PPRIVILEGE_SET RequiredPrivileges', '_In_ PBOOLEAN Result']
case 210: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtPrivilegeCheck_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 211 NTSTATUS NtPrivilegedServiceAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PUNICODE_STRING ServiceName', '_In_ HANDLE ClientToken', '_In_ PPRIVILEGE_SET Privileges', '_In_ BOOLEAN AccessGranted']
case 211: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtPrivilegedServiceAuditAlarm_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 212 NTSTATUS NtPrivilegeObjectAuditAlarm ['_In_ PUNICODE_STRING SubsystemName', '_In_ PVOID HandleId', '_In_ HANDLE ClientToken', '_In_ ULONG DesiredAccess', '_In_ PPRIVILEGE_SET Privileges', '_In_ BOOLEAN AccessGranted']
case 212: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, PRIVILEGE_SET_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtPrivilegeObjectAuditAlarm_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 213 NTSTATUS NtPropagationComplete ['HANDLE ResourceManagerHandle', ' ULONG RequestCookie', ' ULONG BufferLength', ' PVOID Buffer']
case 213: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPropagationComplete_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 214 NTSTATUS NtPropagationFailed ['HANDLE ResourceManagerHandle', ' ULONG RequestCookie', ' NTSTATUS PropStatus']
case 214: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtPropagationFailed_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 215 NTSTATUS NtProtectVirtualMemory ['_In_ HANDLE ProcessHandle', '_In_opt_ PVOID *BaseAddress', '_In_opt_ ULONG *NumberOfBytesToProtect', '_In_ ULONG NewAccessProtection', '_Out_ PULONG OldAccessProtection']
case 215: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(target_ulong));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtProtectVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 216 NTSTATUS NtPulseEvent ['_In_ HANDLE EventHandle', '_Out_ PLONG PulseCount']
case 216: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtPulseEvent_enter, env,pc,arg0,arg1) ; 
}; break;
// 217 NTSTATUS NtQueryAttributesFile ['_In_ POBJECT_ATTRIBUTES ObjectAttributes', '_Out_ PFILE_BASIC_INFORMATION FileInformation']
case 217: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryAttributesFile_enter, env,pc,arg0,arg1) ; 
}; break;
// 218 NTSTATUS NtQueryBootEntryOrder ['PULONG Ids', ' PULONG Count']
case 218: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryBootEntryOrder_enter, env,pc,arg0,arg1) ; 
}; break;
// 219 NTSTATUS NtQueryBootOptions ['PBOOT_OPTIONS BootOptions', ' PULONG BootOptionsLength']
case 219: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryBootOptions_enter, env,pc,arg0,arg1) ; 
}; break;
// 220 NTSTATUS NtQueryDebugFilterState ['ULONG ComponentId', ' ULONG Level']
case 220: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryDebugFilterState_enter, env,pc,arg0,arg1) ; 
}; break;
// 221 NTSTATUS NtQueryDefaultLocale ['BOOLEAN UserProfile', ' PLCID DefaultLocaleId']
case 221: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryDefaultLocale_enter, env,pc,arg0,arg1) ; 
}; break;
// 222 NTSTATUS NtQueryDefaultUILanguage ['PLANGID LanguageId']
case 222: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryDefaultUILanguage_enter, env,pc,arg0) ; 
}; break;
// 223 NTSTATUS NtQueryDirectoryFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass', ' BOOLEAN ReturnSingleEntry', ' PUNICODE_STRING FileName', ' BOOLEAN RestartScan']
case 223: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 9))
    AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryDirectoryFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10) ; 
}; break;
// 224 NTSTATUS NtQueryDirectoryObject ['HANDLE DirectoryHandle', ' PVOID Buffer', ' ULONG BufferLength', ' BOOLEAN ReturnSingleEntry', ' BOOLEAN RestartScan', ' PULONG Context', ' PULONG ReturnLength']
case 224: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, arg2) == -1)
        AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryDirectoryObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 225 NTSTATUS NtQueryDriverEntryOrder ['PULONG Ids', ' PULONG Count']
case 225: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryDriverEntryOrder_enter, env,pc,arg0,arg1) ; 
}; break;
// 226 NTSTATUS NtQueryEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID EaList', ' ULONG EaListLength', ' PULONG EaIndex', ' BOOLEAN RestartScan']
case 226: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, arg6) == -1)
        AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryEaFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 227 NTSTATUS NtQueryEvent ['HANDLE EventHandle', ' EVENT_INFORMATION_CLASS EventInformationClass', ' PVOID EventInformation', ' ULONG EventInformationLength', ' PULONG ReturnLength']
case 227: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryEvent_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 228 NTSTATUS NtQueryFullAttributesFile ['POBJECT_ATTRIBUTES ObjectAttributes', ' PFILE_NETWORK_OPEN_INFORMATION FileInformation']
case 228: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryFullAttributesFile_enter, env,pc,arg0,arg1) ; 
}; break;
// 229 NTSTATUS NtQueryInformationAtom [' RTL_ATOM Atom', '  ATOM_INFORMATION_CLASS AtomInformationClass', ' PVOID AtomInformation', '  ULONG AtomInformationLength', ' PULONG ReturnLength']
case 229: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationAtom_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 230 NTSTATUS NtQueryInformationEnlistment ['HANDLE EnlistmentHandle', ' ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass', ' PVOID EnlistmentInformation', ' ULONG EnlistmentInformationLength', ' PULONG ReturnLength']
case 230: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryInformationEnlistment_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 231 NTSTATUS NtQueryInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
case 231: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 232 NTSTATUS NtQueryInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobInformationClass', ' PVOID JobInformation', ' ULONG JobInformationLength', ' PULONG ReturnLength']
case 232: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationJobObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 233 NTSTATUS NtQueryInformationPort ['HANDLE PortHandle', ' PORT_INFORMATION_CLASS PortInformationClass', ' PVOID PortInformation', ' ULONG PortInformationLength', ' PULONG ReturnLength']
case 233: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationPort_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 234 NTSTATUS NtQueryInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength', ' PULONG ReturnLength']
case 234: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationProcess_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 235 NTSTATUS NtQueryInformationResourceManager ['HANDLE ResourceManagerHandle', ' RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', ' PVOID ResourceManagerInformation', ' ULONG ResourceManagerInformationLength', ' PULONG ReturnLength']
case 235: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryInformationResourceManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 236 NTSTATUS NtQueryInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength', ' PULONG ReturnLength']
case 236: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationThread_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 237 NTSTATUS NtQueryInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength', ' PULONG ReturnLength']
case 237: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInformationToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 238 NTSTATUS NtQueryInformationTransaction ['HANDLE TransactionHandle', ' TRANSACTION_INFORMATION_CLASS TransactionInformationClass', ' PVOID TransactionInformation', ' ULONG TransactionInformationLength', ' PULONG ReturnLength']
case 238: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryInformationTransaction_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 239 NTSTATUS NtQueryInformationTransactionManager ['HANDLE TransactionManagerHandle', ' TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', ' PVOID TransactionManagerInformation', ' ULONG TransactionManagerInformationLength', ' PULONG ReturnLength']
case 239: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryInformationTransactionManager_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 240 NTSTATUS NtQueryInformationWorkerFactory ['HANDLE WorkerFactoryHandle', ' WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', ' PVOID WorkerFactoryInformation', ' ULONG WorkerFactoryInformationLength', ' PULONG ReturnLength']
case 240: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryInformationWorkerFactory_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 241 NTSTATUS NtQueryInstallUILanguage ['PLANGID LanguageId']
case 241: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryInstallUILanguage_enter, env,pc,arg0) ; 
}; break;
// 242 NTSTATUS NtQueryIntervalProfile [' KPROFILE_SOURCE ProfileSource', ' PULONG Interval']
case 242: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryIntervalProfile_enter, env,pc,arg0,arg1) ; 
}; break;
// 243 NTSTATUS NtQueryIoCompletion ['HANDLE IoCompletionHandle', ' IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass', ' PVOID IoCompletionInformation', ' ULONG IoCompletionInformationLength', ' PULONG ResultLength']
case 243: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryIoCompletion_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 244 NTSTATUS NtQueryKey ['HANDLE KeyHandle', ' KEY_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG Length', ' PULONG ResultLength']
case 244: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 245 NTSTATUS NtQueryLicenseValue ['PUNICODE_STRING Name', ' PULONG Type', ' PVOID Buffer', ' ULONG Length', ' PULONG ReturnedLength']
case 245: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryLicenseValue_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 246 NTSTATUS NtQueryMultipleValueKey ['HANDLE KeyHandle', ' PKEY_VALUE_ENTRY ValueList', ' ULONG NumberOfValues', ' PVOID Buffer', ' PULONG Length', ' PULONG ReturnLength']
case 246: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//if(AddArgument_pointer(env, 3, arg4) == -1)
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryMultipleValueKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 247 NTSTATUS NtQueryMutant ['HANDLE MutantHandle', ' MUTANT_INFORMATION_CLASS MutantInformationClass', ' PVOID MutantInformation', ' ULONG Length', ' PULONG ResultLength']
case 247: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryMutant_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 248 NTSTATUS NtQueryObject ['HANDLE ObjectHandle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG Length', ' PULONG ResultLength']
case 248: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 249 NTSTATUS NtQueryOpenSubKeys ['POBJECT_ATTRIBUTES TargetKey', ' ULONG HandleCount']
case 249: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryOpenSubKeys_enter, env,pc,arg0,arg1) ; 
}; break;
// 250 NTSTATUS NtQueryOpenSubKeysEx ['POBJECT_ATTRIBUTES TargetKey', ' ULONG BufferLength', ' PVOID Buffer', ' PULONG RequiredSize']
case 250: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueryOpenSubKeysEx_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 251 NTSTATUS NtQueryPerformanceCounter ['PLARGE_INTEGER Counter', ' PLARGE_INTEGER Frequency']
case 251: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryPerformanceCounter_enter, env,pc,arg0,arg1) ; 
}; break;
// 252 NTSTATUS NtQueryPortInformationProcess ['VOID']
case 252: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryPortInformationProcess_enter, env,pc,arg0) ; 
}; break;
// 253 NTSTATUS NtQueryQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' BOOLEAN ReturnSingleEntry', ' PVOID SidList', ' ULONG SidListLength', ' PSID StartSid', ' BOOLEAN RestartScan']
case 253: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, arg6) == -1)
        AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryQuotaInformationFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 254 NTSTATUS NtQuerySection ['HANDLE SectionHandle', ' SECTION_INFORMATION_CLASS SectionInformationClass', ' PVOID SectionInformation', ' SIZE_T Length', ' PSIZE_T ResultLength']
case 254: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySection_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 255 NTSTATUS NtQuerySecurityAttributesToken ['HANDLE TokenHandle', ' PUNICODE_STRING Attributes', ' ULONG NumberOfAttributes', ' PVOID Buffer', ' ULONG Length', ' PULONG ReturnLength']
case 255: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQuerySecurityAttributesToken_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 256 NTSTATUS NtQuerySecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor', ' ULONG Length', ' PULONG ResultLength']
case 256: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySecurityObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 257 NTSTATUS NtQuerySemaphore ['HANDLE SemaphoreHandle', ' SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass', ' PVOID SemaphoreInformation', ' ULONG Length', ' PULONG ReturnLength']
case 257: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySemaphore_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 258 NTSTATUS NtQuerySymbolicLinkObject ['HANDLE SymLinkObjHandle', ' PUNICODE_STRING LinkTarget', ' PULONG DataWritten']
case 258: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySymbolicLinkObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 259 NTSTATUS NtQuerySystemEnvironmentValue ['PUNICODE_STRING Name', ' PWSTR Value', ' ULONG Length', ' PULONG ReturnLength']
case 259: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_pwstr(env, 1, arg2))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySystemEnvironmentValue_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 260 NTSTATUS NtQuerySystemEnvironmentValueEx ['PUNICODE_STRING VariableName', ' LPGUID VendorGuid', ' PVOID Value', ' PULONG ReturnLength', ' PULONG Attributes']
case 260: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySystemEnvironmentValueEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 261 NTSTATUS NtQuerySystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' SIZE_T Length', ' PSIZE_T ResultLength']
case 261: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySystemInformation_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 262 NTSTATUS NtQuerySystemInformationEx ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID QueryInformation', ' ULONG QueryInformationLength', ' PVOID SystemInformation', ' ULONG SystemInformationLength', ' PULONG ReturnLength']
case 262: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQuerySystemInformationEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 263 NTSTATUS NtQuerySystemTime ['PLARGE_INTEGER CurrentTime']
case 263: {
uint32_t arg0 = get_32(env, 0);
if(AddArgument_pointer(env, 0, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtQuerySystemTime_enter, env,pc,arg0) ; 
}; break;
// 264 NTSTATUS NtQueryTimer ['HANDLE TimerHandle', ' TIMER_INFORMATION_CLASS TimerInformationClass', ' PVOID TimerInformation', ' ULONG Length', ' PULONG ResultLength']
case 264: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryTimer_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 265 NTSTATUS NtQueryTimerResolution ['PULONG MinimumResolution', ' PULONG MaximumResolution', ' PULONG ActualResolution']
case 265: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryTimerResolution_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 266 NTSTATUS NtQueryValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass', ' PVOID KeyValueInformation', ' ULONG Length', ' PULONG ResultLength']
case 266: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryValueKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 267 NTSTATUS NtQueryVirtualMemory ['HANDLE ProcessHandle', ' PVOID Address', ' MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass', ' PVOID VirtualMemoryInformation', ' SIZE_T Length', ' PSIZE_T ResultLength']
case 267: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 268 NTSTATUS NtQueryVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
case 268: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueryVolumeInformationFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 269 NTSTATUS NtQueueApcThread ['HANDLE ThreadHandle', ' PKNORMAL_ROUTINE ApcRoutine', ' PVOID NormalContext', ' PVOID SystemArgument1', ' PVOID SystemArgument2']
case 269: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtQueueApcThread_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 270 NTSTATUS NtQueueApcThreadEx ['HANDLE ThreadHandle', ' HANDLE UserApcReserveHandle', ' PPS_APC_ROUTINE ApcRoutine', ' PVOID ApcArgument1', ' PVOID ApcArgument2', ' PVOID ApcArgument3']
case 270: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtQueueApcThreadEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 271 NTSTATUS NtRaiseException ['PEXCEPTION_RECORD ExceptionRecord', ' PCONTEXT Context', ' BOOLEAN SearchFrames']
case 271: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtRaiseException_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 272 NTSTATUS NtRaiseHardError ['NTSTATUS ErrorStatus', ' ULONG NumberOfParameters', ' ULONG UnicodeStringParameterMask', ' PULONG_PTR Parameters', ' ULONG ValidResponseOptions', ' PULONG Response']
case 272: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtRaiseHardError_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 273 NTSTATUS NtReadFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE UserApcRoutine', ' PVOID UserApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG BufferLength', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
case 273: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//if(AddArgument_pointer(env, 5, arg6) == -1)
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtReadFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 274 NTSTATUS NtReadFileScatter ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE UserApcRoutine', '  PVOID UserApcContext', ' PIO_STATUS_BLOCK UserIoStatusBlock', ' FILE_SEGMENT_ELEMENT BufferDescription[]', ' ULONG BufferLength', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
case 274: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtReadFileScatter_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 275 NTSTATUS NtReadOnlyEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 275: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtReadOnlyEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 276 NTSTATUS NtReadRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG Index', ' PVOID Buffer', ' ULONG BufferLength', ' PULONG ReturnLength']
case 276: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, arg4) == -1)
        AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtReadRequestData_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 277 NTSTATUS NtReadVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' PVOID Buffer', ' SIZE_T NumberOfBytesToRead', ' PSIZE_T NumberOfBytesRead']
case 277: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtReadVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 278 NTSTATUS NtRecoverEnlistment ['HANDLE EnlistmentHandle', ' PVOID EnlistmentKey']
case 278: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRecoverEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 279 NTSTATUS NtRecoverResourceManager ['HANDLE ResourceManagerHandle']
case 279: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRecoverResourceManager_enter, env,pc,arg0) ; 
}; break;
// 280 NTSTATUS NtRecoverTransactionManager ['HANDLE TransactionManagerHandle']
case 280: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRecoverTransactionManager_enter, env,pc,arg0) ; 
}; break;
// 281 NTSTATUS NtRegisterProtocolAddressInformation ['HANDLE ResourceManager', ' PCRM_PROTOCOL_ID ProtocolId', ' ULONG ProtocolInformationSize', ' PVOID ProtocolInformation', ' ULONG CreateOptions']
case 281: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRegisterProtocolAddressInformation_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 282 NTSTATUS NtRegisterThreadTerminatePort ['HANDLE TerminationPort']
case 282: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtRegisterThreadTerminatePort_enter, env,pc,arg0) ; 
}; break;
// 283 NTSTATUS NtReleaseKeyedEvent ['HANDLE EventHandle', ' PVOID Key', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
case 283: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtReleaseKeyedEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 284 NTSTATUS NtReleaseMutant ['HANDLE MutantHandle', ' PLONG ReleaseCount']
case 284: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtReleaseMutant_enter, env,pc,arg0,arg1) ; 
}; break;
// 285 NTSTATUS NtReleaseSemaphore ['HANDLE SemaphoreHandle', ' LONG ReleaseCount', ' PLONG PreviousCount']
case 285: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(int32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtReleaseSemaphore_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 286 NTSTATUS NtReleaseWorkerFactoryWorker ['HANDLE WorkerFactoryHandle']
case 286: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtReleaseWorkerFactoryWorker_enter, env,pc,arg0) ; 
}; break;
// 287 NTSTATUS NtRemoveIoCompletion ['HANDLE IoCompletionHandle', ' PVOID *CompletionKey', ' PVOID *CompletionContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER Timeout']
case 287: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(target_ulong));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtRemoveIoCompletion_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 289 NTSTATUS NtRemoveProcessDebug ['HANDLE Process', ' HANDLE DebugObject']
case 289: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtRemoveProcessDebug_enter, env,pc,arg0,arg1) ; 
}; break;
// 290 NTSTATUS NtRenameKey ['HANDLE KeyHandle', ' PUNICODE_STRING ReplacementName']
case 290: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtRenameKey_enter, env,pc,arg0,arg1) ; 
}; break;
// 291 NTSTATUS NtRenameTransactionManager ['PUNICODE_STRING LogFileName', ' LPGUID ExistingTransactionManagerGuid']
case 291: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRenameTransactionManager_enter, env,pc,arg0,arg1) ; 
}; break;
// 292 NTSTATUS NtReplaceKey ['POBJECT_ATTRIBUTES ObjectAttributes', ' HANDLE Key', ' POBJECT_ATTRIBUTES ReplacedObjectAttributes']
case 292: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_struct_obj_attr(env, 2))
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtReplaceKey_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 293 NTSTATUS NtReplacePartitionUnit ['PUNICODE_STRING TargetInstancePath', ' PUNICODE_STRING SpareInstancePath', ' ULONG Flags']
case 293: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
//PPP_RUN_CB(on_NtReplacePartitionUnit_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 294 NTSTATUS NtReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE LpcReply']
case 294: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtReplyPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 295 NTSTATUS NtReplyWaitReceivePort ['HANDLE PortHandle', ' PVOID *PortContext', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage']
case 295: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtReplyWaitReceivePort_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 296 NTSTATUS NtReplyWaitReceivePortEx ['HANDLE PortHandle', ' PVOID *PortContext', ' PPORT_MESSAGE ReplyMessage', ' PPORT_MESSAGE ReceiveMessage', ' PLARGE_INTEGER Timeout']
case 296: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(target_ulong));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtReplyWaitReceivePortEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 297 NTSTATUS NtReplyWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE ReplyMessage']
case 297: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtReplyWaitReplyPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 298 NTSTATUS NtRequestPort ['HANDLE PortHandle', ' PPORT_MESSAGE LpcMessage']
case 298: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtRequestPort_enter, env,pc,arg0,arg1) ; 
}; break;
// 299 NTSTATUS NtRequestWaitReplyPort ['HANDLE PortHandle', ' PPORT_MESSAGE LpcReply', ' PPORT_MESSAGE LpcRequest']
case 299: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtRequestWaitReplyPort_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 300 NTSTATUS NtResetEvent ['HANDLE EventHandle', ' PLONG NumberOfWaitingThreads']
case 300: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtResetEvent_enter, env,pc,arg0,arg1) ; 
}; break;
// 301 NTSTATUS NtResetWriteWatch ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T RegionSize']
case 301: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtResetWriteWatch_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 302 NTSTATUS NtRestoreKey ['HANDLE KeyHandle', ' HANDLE FileHandle', ' ULONG RestoreFlags']
case 302: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtRestoreKey_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 303 NTSTATUS NtResumeProcess ['HANDLE ProcessHandle']
case 303: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtResumeProcess_enter, env,pc,arg0) ; 
}; break;
// 304 NTSTATUS NtResumeThread ['HANDLE ThreadHandle', ' PULONG SuspendCount']
case 304: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtResumeThread_enter, env,pc,arg0,arg1) ; 
}; break;
// 305 NTSTATUS NtRollbackComplete ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 305: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRollbackComplete_enter, env,pc,arg0,arg1) ; 
}; break;
// 306 NTSTATUS NtRollbackEnlistment ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 306: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
     AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRollbackEnlistment_enter, env,pc,arg0,arg1) ; 
}; break;
// 307 NTSTATUS NtRollbackTransaction ['HANDLE TransactionHandle', ' BOOLEAN Wait']
case 307: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRollbackTransaction_enter, env,pc,arg0,arg1) ; 
}; break;
// 308 NTSTATUS NtRollforwardTransactionManager ['HANDLE TransactionManagerHandle', ' PLARGE_INTEGER TmVirtualClock']
case 308: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtRollforwardTransactionManager_enter, env,pc,arg0,arg1) ; 
}; break;
// 309 NTSTATUS NtSaveKey ['HANDLE KeyHandle', ' HANDLE FileHandle']
case 309: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSaveKey_enter, env,pc,arg0,arg1) ; 
}; break;
// 310 NTSTATUS NtSaveKeyEx ['HANDLE KeyHandle', ' HANDLE FileHandle', ' ULONG Flags']
case 310: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSaveKeyEx_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 311 NTSTATUS NtSaveMergedKeys ['HANDLE HighPrecedenceKeyHandle', ' HANDLE LowPrecedenceKeyHandle', ' HANDLE FileHandle']
case 311: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSaveMergedKeys_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 312 NTSTATUS NtSecureConnectPort ['PHANDLE PortHandle', ' PUNICODE_STRING PortName', ' PSECURITY_QUALITY_OF_SERVICE SecurityQos', ' PPORT_VIEW ClientView', ' PSID Sid', ' PREMOTE_PORT_VIEW ServerView', ' PULONG MaxMessageLength', ' PVOID ConnectionInformation', ' PULONG ConnectionInformationLength']
case 312: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
if(AddArgument_pointer(env, 0, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, POINTER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
if(AddArgument_pointer(env, 6, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtSecureConnectPort_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 313 NTSTATUS NtSerializeBoot ['']
case 313: {
//PPP_RUN_CB(on_NtSerializeBoot_enter, env,pc) ; 
}; break;
// 314 NTSTATUS NtSetBootEntryOrder ['PULONG Ids', ' ULONG Count']
case 314: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetBootEntryOrder_enter, env,pc,arg0,arg1) ; 
}; break;
// 315 NTSTATUS NtSetBootOptions ['PBOOT_OPTIONS BootOptions', ' ULONG FieldsToChange']
case 315: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetBootOptions_enter, env,pc,arg0,arg1) ; 
}; break;
// 316 NTSTATUS NtSetContextThread ['HANDLE ThreadHandle', ' PCONTEXT Context']
case 316: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetContextThread_enter, env,pc,arg0,arg1) ; 
}; break;
// 317 NTSTATUS NtSetDebugFilterState ['ULONG ComponentId', ' ULONG Level', ' BOOLEAN State']
case 317: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetDebugFilterState_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 318 NTSTATUS NtSetDefaultHardErrorPort ['HANDLE PortHandle']
case 318: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetDefaultHardErrorPort_enter, env,pc,arg0) ; 
}; break;
// 319 NTSTATUS NtSetDefaultLocale ['BOOLEAN UserProfile', ' LCID DefaultLocaleId']
case 319: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetDefaultLocale_enter, env,pc,arg0,arg1) ; 
}; break;
// 320 NTSTATUS NtSetDefaultUILanguage ['LANGID LanguageId']
case 320: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetDefaultUILanguage_enter, env,pc,arg0) ; 
}; break;
// 321 NTSTATUS NtSetDriverEntryOrder ['PULONG Ids', ' ULONG Count']
case 321: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetDriverEntryOrder_enter, env,pc,arg0,arg1) ; 
}; break;
// 322 NTSTATUS NtSetEaFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID EaBuffer', ' ULONG EaBufferSize']
case 322: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetEaFile_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 323 NTSTATUS NtSetEvent ['HANDLE EventHandle', ' PLONG PreviousState ']
case 323: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetEvent_enter, env,pc,arg0,arg1) ; 
}; break;
// 324 NTSTATUS NtSetEventBoostPriority ['HANDLE EventHandle']
case 324: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetEventBoostPriority_enter, env,pc,arg0) ; 
}; break;
// 325 NTSTATUS NtSetHighEventPair ['HANDLE EventPairHandle']
case 325: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetHighEventPair_enter, env,pc,arg0) ; 
}; break;
// 326 NTSTATUS NtSetHighWaitLowEventPair ['HANDLE EventPairHandle']
case 326: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetHighWaitLowEventPair_enter, env,pc,arg0) ; 
}; break;
// 327 NTSTATUS NtSetInformationDebugObject ['HANDLE DebugObject', ' DEBUGOBJECTINFOCLASS InformationClass', ' PVOID Information', ' ULONG InformationLength', ' PULONG ReturnLength']
case 327: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationDebugObject_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 329 NTSTATUS NtSetInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FileInformation', ' ULONG Length', ' FILE_INFORMATION_CLASS FileInformationClass']
case 329: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 330 NTSTATUS NtSetInformationJobObject ['HANDLE JobHandle', ' JOBOBJECTINFOCLASS JobInformationClass', ' PVOID JobInformation', ' ULONG JobInformationLength']
case 330: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationJobObject_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 331 NTSTATUS NtSetInformationKey ['HANDLE KeyHandle', ' KEY_SET_INFORMATION_CLASS KeyInformationClass', ' PVOID KeyInformation', ' ULONG KeyInformationLength']
case 331: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationKey_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 332 NTSTATUS NtSetInformationObject ['HANDLE ObjectHandle', ' OBJECT_INFORMATION_CLASS ObjectInformationClass', ' PVOID ObjectInformation', ' ULONG Length']
case 332: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationObject_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 333 NTSTATUS NtSetInformationProcess ['HANDLE ProcessHandle', ' PROCESSINFOCLASS ProcessInformationClass', ' PVOID ProcessInformation', ' ULONG ProcessInformationLength']
case 333: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationProcess_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 334 NTSTATUS NtSetInformationResourceManager ['HANDLE ResourceManagerHandle', ' RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass', ' PVOID ResourceManagerInformation', ' ULONG ResourceManagerInformationLength']
case 334: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetInformationResourceManager_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 335 NTSTATUS NtSetInformationThread ['HANDLE ThreadHandle', ' THREADINFOCLASS ThreadInformationClass', ' PVOID ThreadInformation', ' ULONG ThreadInformationLength']
case 335: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationThread_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 336 NTSTATUS NtSetInformationToken ['HANDLE TokenHandle', ' TOKEN_INFORMATION_CLASS TokenInformationClass', ' PVOID TokenInformation', ' ULONG TokenInformationLength']
case 336: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetInformationToken_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 337 NTSTATUS NtSetInformationTransaction ['HANDLE TransactionHandle', ' TRANSACTION_INFORMATION_CLASS TransactionInformationClass', ' PVOID TransactionInformation', ' ULONG TransactionInformationLength']
case 337: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetInformationTransaction_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 338 NTSTATUS NtSetInformationTransactionManager ['HANDLE TmHandle', ' TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass', ' PVOID TransactionManagerInformation', ' ULONG TransactionManagerInformationLength']
case 338: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetInformationTransactionManager_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 339 NTSTATUS NtSetInformationWorkerFactory ['HANDLE WorkerFactoryHandle', ' WORKERFACTORYINFOCLASS WorkerFactoryInformationClass', ' PVOID WorkerFactoryInformation', ' ULONG WorkerFactoryInformationLength']
case 339: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetInformationWorkerFactory_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 340 NTSTATUS NtSetIntervalProfile ['ULONG Interval', ' KPROFILE_SOURCE ClockSource']
case 340: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetIntervalProfile_enter, env,pc,arg0,arg1) ; 
}; break;
// 341 NTSTATUS NtSetIoCompletion ['HANDLE IoCompletionPortHandle', ' PVOID CompletionKey', ' PVOID CompletionContext', ' NTSTATUS CompletionStatus', ' ULONG CompletionInformation']
case 341: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetIoCompletion_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 342 NTSTATUS NtSetIoCompletionEx ['HANDLE IoCompletionHandle', ' HANDLE IoCompletionReserveHandle', ' PVOID KeyContext', ' PVOID ApcContext', ' NTSTATUS IoStatus', ' ULONG_PTR IoStatusInformation']
case 342: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetIoCompletionEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 343 NTSTATUS NtSetLdtEntries ['ULONG Selector1', ' LDT_ENTRY LdtEntry1', ' ULONG Selector2', ' LDT_ENTRY LdtEntry2']
case 343: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetLdtEntries_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 344 NTSTATUS NtSetLowEventPair ['HANDLE EventPair']
case 344: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetLowEventPair_enter, env,pc,arg0) ; 
}; break;
// 345 NTSTATUS NtSetLowWaitHighEventPair ['HANDLE EventPair']
case 345: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetLowWaitHighEventPair_enter, env,pc,arg0) ; 
}; break;
// 346 NTSTATUS NtSetQuotaInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG BufferLength']
case 346: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, arg3) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetQuotaInformationFile_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 347 NTSTATUS NtSetSecurityObject ['HANDLE Handle', ' SECURITY_INFORMATION SecurityInformation', ' PSECURITY_DESCRIPTOR SecurityDescriptor']
case 347: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, SECURITY_DESCRIPTOR_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetSecurityObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 348 NTSTATUS NtSetSystemEnvironmentValue ['PUNICODE_STRING VariableName', ' PUNICODE_STRING Value']
case 348: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetSystemEnvironmentValue_enter, env,pc,arg0,arg1) ; 
}; break;
// 349 NTSTATUS NtSetSystemEnvironmentValueEx ['PUNICODE_STRING VariableName', ' LPGUID VendorGuid', ' PVOID Value', ' ULONG ValueLength', ' ULONG Attributes']
case 349: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetSystemEnvironmentValueEx_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 350 NTSTATUS NtSetSystemInformation ['SYSTEM_INFORMATION_CLASS SystemInformationClass', ' PVOID SystemInformation', ' SIZE_T SystemInformationLength']
case 350: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetSystemInformation_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 351 NTSTATUS NtSetSystemPowerState ['POWER_ACTION SystemAction', ' SYSTEM_POWER_STATE MinSystemState', ' ULONG Flags']
case 351: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetSystemPowerState_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 352 NTSTATUS NtSetSystemTime ['PLARGE_INTEGER SystemTime', ' PLARGE_INTEGER NewSystemTime']
case 352: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(AddArgument_pointer(env, 0, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetSystemTime_enter, env,pc,arg0,arg1) ; 
}; break;
// 353 NTSTATUS NtSetThreadExecutionState ['EXECUTION_STATE esFlags', ' PEXECUTION_STATE PreviousFlags']
case 353: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetThreadExecutionState_enter, env,pc,arg0,arg1) ; 
}; break;
// 354 NTSTATUS NtSetTimer ['HANDLE TimerHandle', ' PLARGE_INTEGER DueTime', ' PTIMER_APC_ROUTINE TimerApcRoutine', ' PVOID TimerContext', ' BOOLEAN WakeTimer', ' LONG Period', ' PBOOLEAN PreviousState']
case 354: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
int32_t arg5 = get_s32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
     AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(int32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetTimer_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6) ; 
}; break;
// 355 NTSTATUS NtSetTimerEx ['HANDLE TimerHandle', ' TIMER_SET_INFORMATION_CLASS TimerSetInformationClass', ' PVOID TimerSetInformation', ' ULONG TimerSetInformationLength']
case 355: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSetTimerEx_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 356 NTSTATUS NtSetTimerResolution ['ULONG RequestedResolution', ' BOOLEAN SetOrUnset', ' PULONG ActualResolution']
case 356: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetTimerResolution_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 357 NTSTATUS NtSetUuidSeed ['PUCHAR UuidSeed']
case 357: {
uint32_t arg0 = get_32(env, 0);
//if(AddArgument_pointer(env, 2, 6) == -1)
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetUuidSeed_enter, env,pc,arg0) ; 
}; break;
// 358 NTSTATUS NtSetValueKey ['HANDLE KeyHandle', ' PUNICODE_STRING ValueName', ' ULONG TitleIndex', ' ULONG Type', ' PVOID Data', ' ULONG DataSize']
case 358: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(!AddArgument_struct_unicode_str(env, 1))
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetValueKey_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 359 NTSTATUS NtSetVolumeInformationFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID FsInformation', ' ULONG Length', ' FS_INFORMATION_CLASS FsInformationClass']
case 359: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtSetVolumeInformationFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 360 NTSTATUS NtShutdownSystem ['SHUTDOWN_ACTION Action']
case 360: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtShutdownSystem_enter, env,pc,arg0) ; 
}; break;
// 361 NTSTATUS NtShutdownWorkerFactory ['HANDLE WorkerFactoryHandle', ' LONG *PendingWorkerCount']
case 361: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtShutdownWorkerFactory_enter, env,pc,arg0,arg1) ; 
}; break;
// 362 NTSTATUS NtSignalAndWaitForSingleObject ['HANDLE SignalObject', ' HANDLE WaitObject', ' BOOLEAN Alertable', ' PLARGE_INTEGER Time']
case 362: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtSignalAndWaitForSingleObject_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 363 NTSTATUS NtSinglePhaseReject ['HANDLE EnlistmentHandle', ' PLARGE_INTEGER TmVirtualClock']
case 363: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, LARGE_INTEGER_SIZE) == -1)
     AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtSinglePhaseReject_enter, env,pc,arg0,arg1) ; 
}; break;
// 364 NTSTATUS NtStartProfile ['HANDLE ProfileHandle']
case 364: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtStartProfile_enter, env,pc,arg0) ; 
}; break;
// 365 NTSTATUS NtStopProfile ['HANDLE ProfileHandle']
case 365: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtStopProfile_enter, env,pc,arg0) ; 
}; break;
// 366 NTSTATUS NtSuspendProcess ['HANDLE ProcessHandle']
case 366: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtSuspendProcess_enter, env,pc,arg0) ; 
}; break;
// 367 NTSTATUS NtSuspendThread ['HANDLE ThreadHandle', ' PULONG PreviousSuspendCount']
case 367: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtSuspendThread_enter, env,pc,arg0,arg1) ; 
}; break;
// 368 NTSTATUS NtSystemDebugControl ['SYSDBG_COMMAND ControlCode', ' PVOID InputBuffer', ' ULONG InputBufferLength', ' PVOID OutputBuffer', ' ULONG OutputBufferLength', ' PULONG ReturnLength']
case 368: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
if(AddArgument_pointer(env, 1, arg2) == -1)
        AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, arg4) == -1)
        AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtSystemDebugControl_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 369 NTSTATUS NtTerminateJobObject ['HANDLE JobHandle', ' NTSTATUS ExitStatus']
case 369: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtTerminateJobObject_enter, env,pc,arg0,arg1) ; 
}; break;
// 370 NTSTATUS NtTerminateProcess ['HANDLE ProcessHandle', ' NTSTATUS ExitStatus']
case 370: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtTerminateProcess_enter, env,pc,arg0,arg1) ; 
}; break;
// 371 NTSTATUS NtTerminateThread ['HANDLE ThreadHandle', ' NTSTATUS ExitStatus']
case 371: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtTerminateThread_enter, env,pc,arg0,arg1) ; 
}; break;
// 372 NTSTATUS NtTestAlert ['VOID']
case 372: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtTestAlert_enter, env,pc,arg0) ; 
}; break;
// 373 NTSTATUS NtThawRegistry ['']
case 373: {
//PPP_RUN_CB(on_NtThawRegistry_enter, env,pc) ; 
}; break;
// 374 NTSTATUS NtThawTransactions ['']
case 374: {
//PPP_RUN_CB(on_NtThawTransactions_enter, env,pc) ; 
}; break;
// 375 NTSTATUS NtTraceControl ['ULONG FunctionCode', ' PVOID InBuffer', ' ULONG InBufferLen', ' PVOID OutBuffer', ' ULONG OutBufferLen', ' PULONG ReturnLength']
case 375: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//PPP_RUN_CB(on_NtTraceControl_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 376 NTSTATUS NtTraceEvent ['ULONG TraceHandle', ' ULONG Flags', ' ULONG TraceHeaderLength', ' PEVENT_TRACE_HEADER TraceHeader']
case 376: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtTraceEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 377 NTSTATUS NtTranslateFilePath ['PFILE_PATH InputFilePath', ' ULONG OutputType', ' PFILE_PATH OutputFilePath', ' ULONG OutputFilePathLength']
case 377: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtTranslateFilePath_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 378 NTSTATUS NtUmsThreadYield ['PVOID SchedulerParam']
case 378: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtUmsThreadYield_enter, env,pc,arg0) ; 
}; break;
// 379 NTSTATUS NtUnloadDriver ['PUNICODE_STRING DriverServiceName']
case 379: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_unicode_str(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnloadDriver_enter, env,pc,arg0) ; 
}; break;
// 380 NTSTATUS NtUnloadKey ['POBJECT_ATTRIBUTES KeyObjectAttributes']
case 380: {
uint32_t arg0 = get_32(env, 0);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnloadKey_enter, env,pc,arg0) ; 
}; break;
// 381 NTSTATUS NtUnloadKey2 ['POBJECT_ATTRIBUTES TargetKey', ' ULONG Flags']
case 381: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtUnloadKey2_enter, env,pc,arg0,arg1) ; 
}; break;
// 382 NTSTATUS NtUnloadKeyEx ['POBJECT_ATTRIBUTES TargetKey', ' HANDLE Event']
case 382: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
if(!AddArgument_struct_obj_attr(env, 0))
    AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnloadKeyEx_enter, env,pc,arg0,arg1) ; 
}; break;
// 383 NTSTATUS NtUnlockFile ['HANDLE FileHandle', ' PIO_STATUS_BLOCK IoStatusBlock', ' PLARGE_INTEGER ByteOffset', ' PLARGE_INTEGER Lenght', ' ULONG Key']
case 383: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnlockFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 384 NTSTATUS NtUnlockVirtualMemory ['HANDLE ProcessHandle', ' PVOID BaseAddress', ' SIZE_T  NumberOfBytesToUnlock', ' PSIZE_T NumberOfBytesUnlocked']
case 384: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnlockVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 385 NTSTATUS NtUnmapViewOfSection ['HANDLE ProcessHandle', ' PVOID BaseAddress']
case 385: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtUnmapViewOfSection_enter, env,pc,arg0,arg1) ; 
}; break;
// 386 NTSTATUS NtVdmControl ['ULONG ControlCode', ' PVOID ControlData']
case 386: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
PPP_RUN_CB(on_NtVdmControl_enter, env,pc,arg0,arg1) ; 
}; break;
// 387 NTSTATUS NtWaitForDebugEvent ['HANDLE DebugObject', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout', ' PDBGUI_WAIT_STATE_CHANGE StateChange']
case 387: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, LARGE_INTEGER_SIZE) == -1)
     AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitForDebugEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 388 NTSTATUS NtWaitForKeyedEvent ['HANDLE EventHandle', ' PVOID Key', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
case 388: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitForKeyedEvent_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 389 NTSTATUS NtWaitForMultipleObjects ['ULONG Count', ' HANDLE Object[]', ' WAIT_TYPE WaitType', ' BOOLEAN Alertable', ' PLARGE_INTEGER Time']
case 389: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitForMultipleObjects_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 390 NTSTATUS NtWaitForMultipleObjects32 ['ULONG Count', ' LONG Handles[]', ' WAIT_TYPE WaitType', ' BOOLEAN Alertable', ' PLARGE_INTEGER Timeout']
case 390: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
if(AddArgument_pointer(env, 4, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
//PPP_RUN_CB(on_NtWaitForMultipleObjects32_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 391 NTSTATUS NtWaitForSingleObject ['HANDLE Object', ' BOOLEAN Alertable', ' PLARGE_INTEGER Time']
case 391: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(AddArgument_pointer(env, 2, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitForSingleObject_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 392 NTSTATUS NtWaitForWorkViaWorkerFactory ['HANDLE WorkerFactoryHandle', ' PFILE_IO_COMPLETION_INFORMATION MiniPacket']
case 392: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//PPP_RUN_CB(on_NtWaitForWorkViaWorkerFactory_enter, env,pc,arg0,arg1) ; 
}; break;
// 393 NTSTATUS NtWaitHighEventPair ['HANDLE EventPairHandle']
case 393: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitHighEventPair_enter, env,pc,arg0) ; 
}; break;
// 394 NTSTATUS NtWaitLowEventPair ['HANDLE EventPairHandle']
case 394: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
PPP_RUN_CB(on_NtWaitLowEventPair_enter, env,pc,arg0) ; 
}; break;
// 395 NTSTATUS NtWorkerFactoryWorkerReady ['HANDLE WorkerFactoryHandle']
case 395: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
//PPP_RUN_CB(on_NtWorkerFactoryWorkerReady_enter, env,pc,arg0) ; 
}; break;
// 396 NTSTATUS NtWriteFile ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' PVOID Buffer', ' ULONG Length', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
case 396: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
//AddArgument_pointer(env, 5, arg6);
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtWriteFile_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 397 NTSTATUS NtWriteFileGather ['HANDLE FileHandle', ' HANDLE Event', ' PIO_APC_ROUTINE ApcRoutine', ' PVOID ApcContext', ' PIO_STATUS_BLOCK IoStatusBlock', ' FILE_SEGMENT_ELEMENT BufferDescription[]', ' ULONG BufferLength', ' PLARGE_INTEGER ByteOffset', ' PULONG Key']
case 397: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
if(AddArgument_pointer(env, 7, LARGE_INTEGER_SIZE) == -1)
    AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
if(AddArgument_pointer(env, 8, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
PPP_RUN_CB(on_NtWriteFileGather_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) ; 
}; break;
// 398 NTSTATUS NtWriteRequestData ['HANDLE PortHandle', ' PPORT_MESSAGE Message', ' ULONG Index', ' PVOID Buffer', ' ULONG BufferLength', ' PULONG ReturnLength']
case 398: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(AddArgument_pointer(env, 3, arg4) == -1)
        AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
if(AddArgument_pointer(env, 5, ULONG_SIZE) == -1)
    AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
PPP_RUN_CB(on_NtWriteRequestData_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 399 NTSTATUS NtWriteVirtualMemory ['HANDLE ProcessHandle', ' PVOID  BaseAddress', ' PVOID Buffer', ' SIZE_T NumberOfBytesToWrite', ' PSIZE_T NumberOfBytesWritten']
case 399: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
PPP_RUN_CB(on_NtWriteVirtualMemory_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 400 NTSTATUS NtYieldExecution ['VOID']
case 400: {
//PPP_RUN_CB(on_NtYieldExecution_enter, env,pc,arg0) ; 
}; break;

// 4103 NtGdiAlphaBlend
case 4103: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4105 NtGdiAnyLinkedFonts
case 4105: {
}; break;

//<FAROS MG>
// 4106 NtGdiFontIsLinked
case 4106: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4110 NtGdiBitBlt
case 4110: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4122 NtGdiCreateBitmap
case 4122: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

// 4127 NtGdiCreateCompatibleBitmap
case 4127: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4128 NtGdiCreateCompatibleDC
case 4128: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4130 NtGdiCreateDIBitmapInternal
case 4130: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);//pointer
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
}; break;

// 4131 NtGdiCreateDIBSection
case 4131: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4137 NtGdiCreatePaletteInternal
case 4137: {
uint32_t arg0 = get_32(env, 0);//pointer
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4138 NtGdiCreatePatternBrushInterna
case 4138: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4139 NtGdiCreatePen
case 4139: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4140 NtGdiCreateRectRgn
case 4140: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4143 NtGdiCreateSolidBrush
case 4143: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4221 NtGdiDeleteObjectApp
case 4221: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4226 NtGdiDoPalette
case 4226: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4228 NtGdiEllipse
case 4228: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);//pointer
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4234 NtGdiEnumFonts
case 4234: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);//pointer
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);//pointer
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
}; break;

// 4238 NtGdiExcludeClipRect
case 4238: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

// 4240 NtGdiExtCreateRegion
case 4240: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4243 NtGdiExtGetObjectW
case 4243: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4244 NtGdiExtSelectClipRgn
case 4244: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4245 NtGdiExtTextOutW
case 4245: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4249 NtGdiFlush
case 4249: {
}; break;

//<FAROS MG>
// 4255 NtGdiGetBitmapBits
case 4255: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4257 NtGdiGetBoundsRect
case 4257: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4260 NtGdiGetCharABCWidthsW
case 4260: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
}; break;

// 4262 NtGdiGetCharSet
case 4262: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4264 NtGdiGetCharWidthInfo
case 4264: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4268 NtGdiGetDCDword
case 4268: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4269 NtGdiGetDCforBitmap
case 4269: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4270 NtGdiGetDCObject
case 4270: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4271 NtGdiGetDCPoint
case 4271: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4272 NtGdiGetDeviceCaps
case 4272: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4275 NtGdiGetDIBitsInternal
case 4275: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);//pointer
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4278 NtGdiGetFontData
case 4278: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4282 NtGdiGetGlyphIndicesW
case 4282: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);//pointer
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4294 NtGdiGetOutlineTextMetricsInternalW
case 4294: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4297 NtGdiGetRandomRgn
case 4297: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4299 NtGdiGetRealizationInfo
case 4299: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4301 NtGdiGetRgnBox
case 4301: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4305 NtGdiGetStockObject
case 4305: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4309 NtGdiGetTextCharsetInfo
case 4309: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4311 NtGdiGetTextExtentExW ???
case 4311: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4312 NtGdiGetTextFaceW
case 4312: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4313 NtGdiGetTextMetricsW
case 4313: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4322 NtGdiGetWidthTable
case 4322: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);//pointer
uint32_t arg5 = get_32(env, 5);//pointer
uint32_t arg6 = get_32(env, 6);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
}; break;

// 4324 NtGdiHfontCreate
case 4324: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4326 IsIMMEnabledSystem
case 4326: {
}; break;

// 4328 NtGdiIntersectClipRect
case 4328: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

// 4330 NtGdiLineTo
case 4330: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4338 NtGdiOffsetRgn
case 4338: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4339 NtGdiOpenDCW
case 4339: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4350 NtGdiQueryFontAssocInfo
case 4350: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//4353 NtGdiRectVisible
case 4353: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4358 NtGdiRestoreDC
case 4358: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 43360 NtGdiSaveDC
case 4360: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4363 GreSelectBitmap
case 4363: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4366 NtGdiSelectFont
case 4366: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4377 NtGdiSetDIBitsToDeviceInternal
case 4377: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);//pointer
uint32_t arg10 = get_32(env, 10);//pointer
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);//pointer
uint32_t arg15 = get_32(env, 15);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
}; break;

// 4387 NtGdiSetLayout
case 4387: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//4398 NtGdiStretchBlt
case 4398: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4399 NtGdiStretchDIBitsInternal
case 4399: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);//pointer
uint32_t arg10 = get_32(env, 10);//pointer
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);
uint32_t arg15 = get_32(env, 15);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4403 NtGdiTransformPoints
case 4403: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4410 NtUserActivateKeyboardLayout
case 4410: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4414 NtUserAttachThreadInput
case 4414: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4415 NtUserBeginPaint
case 4415: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4419 NtUserBuildHwndList
case 4419: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
}; break;

// 4423 NtUserCallHwndLock
case 4423: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4425 NtUserCallHwndParam
case 4425: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4426 NtUserCallHwndParam
case 4426: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4429 NtUserCallNoParam
case 4429: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4430 NtUserCallOneParam
case 4430: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4431 NtUserCallTwoParam
case 4431: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4445 NtUserCloseClipboard
case 4445: {
}; break;

//<FAROS MG>
// 4450 NtUserCopyAcceleratorTable
case 4450: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4452 NtUserCreateAcceleratorTable
case 4452: {
uint32_t arg0 = get_32(env, 0);//pointer
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4457 NtUserCreateWindowEx
case 4457: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);//pointer
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
uint32_t arg11 = get_32(env, 11);
uint32_t arg12 = get_32(env, 12);
uint32_t arg13 = get_32(env, 13);
uint32_t arg14 = get_32(env, 14);
uint32_t arg15 = get_32(env, 15);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
AddArgument(env, (void *)&arg11, 11, sizeof(uint32_t));
AddArgument(env, (void *)&arg12, 12, sizeof(uint32_t));
AddArgument(env, (void *)&arg13, 13, sizeof(uint32_t));
AddArgument(env, (void *)&arg14, 14, sizeof(uint32_t));
AddArgument(env, (void *)&arg15, 15, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4460 NtUserDeferWindowPos
case 4460: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4462 NtUserDeleteMenu
case 4462: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4463 NtUserDestroyAcceleratorTable
case 4463: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4464 NtUserDestroyCursor
case 4464: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4466 NtUserDestroyMenu
case 4466: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4467 NtUserDestroyWindow
case 4467: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4469 NtUserDispatchMessage
case 4469: {
uint32_t arg0 = get_32(env, 0);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4477 NtUserDrawIconEx
case 4477: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
uint32_t arg7 = get_32(env, 7);
uint32_t arg8 = get_32(env, 8);
uint32_t arg9 = get_32(env, 9);
uint32_t arg10 = get_32(env, 10);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
AddArgument(env, (void *)&arg7, 7, sizeof(uint32_t));
AddArgument(env, (void *)&arg8, 8, sizeof(uint32_t));
AddArgument(env, (void *)&arg9, 9, sizeof(uint32_t));
AddArgument(env, (void *)&arg10, 10, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4479 NtUserEmptyClipboard
case 4479: {
}; break;

//<FAROS MG>
// 4482 NtUserEndDeferWindowPosEx
case 4482: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4483 NtUserEndMenu
case 4483: {
}; break;

// 4484 NtUserEndPaint
case 4484: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4485 NtUserEnumDisplayDevices
case 4485: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4486 NtUserEnumDisplayMonitors
case 4486: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4491 NtUserFindExistingCursorIcon
case 4491: {
uint32_t arg0 = get_32(env, 0);// double pointer
uint32_t arg1 = get_32(env, 1);//pointer
uint32_t arg2 = get_32(env, 2);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4492 NtUserFindWindowEx
case 4492: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);// double pointer
uint32_t arg3 = get_32(env, 3);//pointer
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

// 4496 NtUserGetAncestor
case 4496: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4497 NtGdiGetRandomRgn
case 4497: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4498 NtUserGetAsyncKeyState
case 4498: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4499 NtUserGetAtomName
case 4499: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//double pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4502 NtUserGetClassInfoEx
case 4502: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//double pointer
uint32_t arg2 = get_32(env, 2);//double pointer
uint32_t arg3 = get_32(env, 3);//pointer
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4503 NtUserGetClassName
case 4503: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//double pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4513 NtUserGetCPD
case 4513: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4516 NtUserGetDC
case 4516: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4517 NtUserGetDCEx
case 4517: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4518 NtUserGetDoubleClickTime
case 4518: {
}; break;

// 4519 NtUserGetForegroundWindow
case 4519: {
}; break;

//<FAROS MG>
// 4521 NtUserGetGUIThreadInfo
case 4521: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4522 NtUserGetIconInfo
case 4522: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
uint32_t arg2 = get_32(env, 2);//double pointer
uint32_t arg3 = get_32(env, 3);//double pointer
uint32_t arg4 = get_32(env, 4);//pointer
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4523 NtUserGetIconSize
case 4523: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4525 NtUserGetImeInfoEx
case 4525: {
uint32_t arg0 = get_32(env, 0);//triple pointer ?
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4528 NtUserGetKeyboardLayoutList
case 4528: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4532 NtUserGetKeyState
case 4532: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4534 NtUserGetMenuBarInfo
case 4534: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4537 NtUserGetMessage
case 4537: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4539 NtUserGetObjectInformation
case 4539: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4542 NtUserGetMenuBarInfo
case 4542: {
}; break;

//<FAROS MG>
// 4548 NtUserGetScrollBarInfo
case 4548: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4549 NtUserGetSystemMenu
case 4549: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4550 NtUserGetThreadDesktop
case 4550: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4551 NtUserGetThreadState
case 4551: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4552 NtUserGetTitleBarInfo
case 4552: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4559 NtUserGetWindowDC
case 4559: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4565 NtUserHideCaret
case 4565: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4572 NtUserInternalGetWindowText
case 4572: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4574 NtUserInvalidateRect
case 4574: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4575 NtUserInvalidateRgn
case 4575: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4578 NtUserGetAncestor
case 4578: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4583 NtUserLogicalToPhysicalPoint
case 4583: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4586 NtUserMessageCall
case 4586: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4591 NtUserMoveWindow
case 4591: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
}; break;

// 4592 NtUserNotifyIMEStatus
case 4592: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4594 NtUserNotifyWinEvent
case 4594: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4595 NtUserOpenClipboard
case 4595: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4602 NtUserPeekMessage
case 4602: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4604 NtUserPostMessage
case 4604: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4605 NtUserPostThreadMessage
case 4605: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4609 NtUserQueryInputContext
case 4609: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4611 NtUserQueryWindow
case 4611: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4613 NtUserRealInternalGetMessage
case 4613: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
}; break;

// 4615 NtUserRedrawWindow
case 4615: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4616  NtUserRegisterClassExWOW
case 4616: {
uint32_t arg0 = get_32(env, 0);//pointer
uint32_t arg1 = get_32(env, 1);//double pointer
uint32_t arg2 = get_32(env, 2);//double pointer
uint32_t arg3 = get_32(env, 3);//double pointer
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4619  NtUserRegisterHotKey
case 4619: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4623  NtUserRegisterWindowMessage
case 4623: {
uint32_t arg0 = get_32(env, 0);//triple pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

// 4626 NtUserRemoveProp
case 4626: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4628 NtUserSBGetParms
case 4628: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
if(!AddArgument_pointer(env, 2, 16) == -1)
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
if(!AddArgument_pointer(env, 3, 28) == -1)
        AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4631  NtUserSelectPalette
case 4631: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4635  NtUserSetCapture
case 4635: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4637  NtUserSetClassLong
case 4637: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4639  NtUserSetClipboardData
case 4639: {
uint32_t arg0 = get_32(env, 0);//pointer
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4641  NtUserSetCursor
case 4641: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4643  NtUserSetCursorIconData
case 4643: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);//double pointer
uint32_t arg2 = get_32(env, 2);//pointer
uint32_t arg3 = get_32(env, 3);//pointer
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4644 NtUserSetFocus
case 4644: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4647 NtUserSetImeOwnerWindow
case 4647: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4656 NtUserSetParent
case 4656: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4658 NtUserGetProp
case 4658: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4659 NtUserSetProp
case 4659: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4660 NtUserSetScrollInfo
case 4660: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
//if(!AddArgument_pointer(env, 2, arg3))
        AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4669 NtUserSetTimer
case 4669: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

//<FAROS MG>
// 4673 NtUserSetWindowFNID
case 4673: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4674 NtUserSetWindowLong
case 4674: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4676 NtUserSetWindowPos
case 4676: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
uint32_t arg6 = get_32(env, 6);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
AddArgument(env, (void *)&arg5, 5, sizeof(uint32_t));
AddArgument(env, (void *)&arg6, 6, sizeof(uint32_t));
}; break;

// 4677 NtUserSetWindowRgn
case 4677: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;

// 4687 NtUserShowWindow
case 4687: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
}; break;

// 4699 NtUserCalcMenuBar
case 4699: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
AddArgument(env, (void *)&arg4, 4, sizeof(uint32_t));
}; break;

// 4714 NtUserSetLayeredWindowAttributes
case 4714: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
AddArgument(env, (void *)&arg3, 3, sizeof(uint32_t));
}; break;

// 4719 NtUserValidateTimerCallback
case 4719: {
uint32_t arg0 = get_32(env, 0);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
}; break;

//4723 NtUserWaitMessage
case 4723: {
}; break;

// 4827 NtGdiDrawStream
case 4827: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
AddArgument(env, (void *)&arg0, 0, sizeof(uint32_t));
AddArgument(env, (void *)&arg1, 1, sizeof(uint32_t));
AddArgument(env, (void *)&arg2, 2, sizeof(uint32_t));
}; break;*/

default:
PPP_RUN_CB(on_unknown_sys_enter, env, pc, EAX);
}
PPP_RUN_CB(on_all_sys_enter, env, pc, EAX);//, SyscallArgs);
appendReturnPoint(rp);
//}// end if
#endif
 } 
