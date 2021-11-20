/*
 * Copyright (C) 2007-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <iostream>

#include <sys/shm.h> 
#include <sys/ipc.h> 
//#include <json/json.h>

using namespace std;
using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 insCount    = 0; //number of dynamically executed instructions
UINT64 bblCount    = 0; //number of dynamically executed basic blocks
UINT64 threadCount = 0; //total number of threads, including main thread
typedef struct heap_element{
    unsigned long addr;
    unsigned int size;// If size>0xffffffff => too big size. So pass.
}heap_element;

heap_element * heap_table = 0;


unsigned long base_address=0;
typedef UINT8 byte;
typedef ADDRINT app_pc;
typedef ADDRINT ptr_uint_t;
std::ostream* out = &cerr;
typedef enum {
	DRLTRC_NONE_POINTER,
	DRLTRC_CODE_POINTER,
	DRLTRC_DATA_POINTER
} drltrc_pointer_type_t;
class MUTEX {
public:
	MUTEX() {
		PIN_LockClient();
		// PIN_MutexLock(&as_built_lock);
	}

	~MUTEX() {
		PIN_UnlockClient();
		// PIN_MutexUnlock(&as_built_lock);
	}
};

typedef struct args_mem{
    unsigned long addr;
    unsigned int num;
}args_mem;
args_mem  * args_table;
unsigned long table_size;
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                       "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}
void con() {
    int shmid;
    printf("con\n");
    shmid = shmget(getpid(),sizeof(heap_element)*0xfffff0, IPC_CREAT|0666);
    if(shmid==-1){
        printf("shmget error\n");
        exit(-1);
    }
    heap_table= (heap_element * )shmat(shmid,NULL,0);
    if(heap_table==(void*)0){
        printf("heap_table create error\n");
        exit(-1);
    }
    printf("heap_table = %p\n",heap_table);
}
/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
void itoh(long address,char buf[0x10]){
    for(int i=0;i<0x8;i++){
        buf[i] = (address&0xff); //+ 0x30;
        address = address>>8;
    }
}


VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) { threadCount++; }

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
    *out << "===============================================" << endl;
    *out << "MyPinTool analysis results: " << endl;
    *out << "Number of instructions: " << insCount << endl;
    *out << "Number of basic blocks: " << bblCount << endl;
    *out << "Number of threads: " << threadCount << endl;
    *out << "===============================================" << endl;
}




ifstream  log_fd;
int log_num;
void init_log(){
    ifstream log_fd("log_file");
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */

void InsFunction(RTN rtn,int id , VOID* v){
    unsigned long addr = RTN_Address(rtn);
    *out <<"id : "<<PIN_GetPid() << " , "<< "address : "<<hex <<addr <<endl;
    cerr<<"InsFunction"<<endl;

}

//from winnie

//FIXME: I assume that all writable region as DATA pointer (regardless of execution)
/* determine whether a pointer is code pointer or data pointer
   implement for the print structure feature for harness generation */
bool fast_safe_read(void* base, size_t size, void* out_buf, size_t* outsize)
{
	/* For all of our uses, a failure is rare, so we do not want
	 * to pay the cost of the syscall (DrMemi#265).
	 */
	bool res = true;
	char fmem[0x100];

    //res = !!W::ReadProcessMemory(current_process, base, out_buf, size, (W::SIZE_T*)outsize);
	NATIVE_PID pid;
    OS_GetPid(&pid);
    //need to root priv
    
    sprintf(fmem,"/proc/%d/mem",pid);
    FILE *f = fopen(fmem, "rb");
    fseek(f, (unsigned long)base, SEEK_SET);
    res = fread(out_buf,1,size,f);
    fclose(f);
    return res;
}
/*
static bool is_code_pointer(ptr_uint_t arg_val)
{
	//fprintf(outf, "\naddr:%x\n", arg_val);
	VOID* pAddress = (void*)arg_val;
	OS_MEMORY_AT_ADDR_INFORMATION info;
	NATIVE_PID pid;
	OS_GetPid(&pid);
//    cout<<"query"<<endl;
    if (OS_QueryMemory(pid, pAddress, &info).generic_err != OS_RETURN_CODE_QUERY_FAILED) {
//        cout<<"query end"<<endl;
		if (info.Protection == (OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_EXECUTE))
			return true;
		else
			return false;
	}
	return false;
}
*/
static bool is_pointer(ptr_uint_t arg_val)
{
    if(arg_val>0x7fffffffffff){
        return false;
    }
	//fprintf(outf, "\naddr:%x\n", arg_val);
	VOID* pAddress = (void*)arg_val;
	OS_MEMORY_AT_ADDR_INFORMATION info;
	NATIVE_PID pid;
	OS_GetPid(&pid);
//    cout<<"query"<<endl;
    if (OS_QueryMemory(pid, pAddress, &info).generic_err == OS_RETURN_CODE_QUERY_FAILED) {
        return false;
	}
/*
 *                                On Unix, if there is no mapped memory block that contains @b memoryAddr
 *                                         the next mapped memory block will be returned.
 *                                         If no such mapped memory block exists, an empty memory block will be returned
*/
	
    if((unsigned long) arg_val < (unsigned long)info.BaseAddress){//Ingore code pointer
        return false;
    }
//    cerr<<"arg_val = "<<hex<<arg_val<<", base = "<<info.BaseAddress<<endl;
    return true;
}


/*
static drltrc_pointer_type_t _is_pointer(ptr_uint_t arg_val, int sz)
{
	ptr_uint_t deref = 0;
	bool ret = fast_safe_read((void*)arg_val, sz, &deref, NULL);
	
 //   cout<<"fast_safe_read_end"<<endl;
    if (ret) {
		if (is_code_pointer(arg_val))
			return DRLTRC_CODE_POINTER;
		else
			return DRLTRC_DATA_POINTER;
	}
	return DRLTRC_NONE_POINTER;
}

*/
int is_valid_address(unsigned int address){
    //address
    //using /proc/self/maps
    return 1;   
}

void dump_arg(){
    //get count of function arg from IDA
}

void dump_ret(){
}
void dump_global(){
}

unsigned int get_arg_num(unsigned long addr){
// 57 args_mem  * args_table;
    for(unsigned int i =0; i<table_size ; i++){
        if(addr == args_table[i].addr + base_address){
            return args_table[i].num;
        }
    }
    return 0; 
}
unsigned int search_heap_size(unsigned long  address){
    //TODO Need to trace malloc and free. And Use that information for get chunk size
    //TODO not start of chunk, ex) chunk + 0x18
    if(!heap_table){
        con();
    }
    if(!address){
        return 0;
    }
    for(unsigned int i =0 ; i<0xfffff0;i++){
        if (heap_table[i].addr==address){
            return heap_table[i].size;
        }
        else if(heap_table[i].addr-address < heap_table[i].size){
            //not start of chunk
            //Ingnore this case? 
            //Mabye this is not struct just pointer
            //cerr<<"base = "<<hex<<heap_table[i].addr <<" address = "<<address<<" size = "<<heap_table[i].size<<endl;
            //return heap_table[i].size;
            return 1;
        }
        else if(heap_table[i].addr==0){
            break;
        }

    }
 //   cerr<<hex<<address<< " is not found"<<endl;
    return 0;
}
int is_heap(unsigned long address){
    //TODO more Quickly and accurately??
    FILE * fd = fopen("/proc/self/maps","r");
    char buf[0x300];
    char * tmp;
    unsigned long start =0;
    unsigned long end = 0;
    unsigned int i=0;
    while(fgets(buf,0x2ff,fd)){
        tmp = strstr(buf,"[heap]");
        if(tmp){
            break;
        }
    }
    start = strtol(buf, NULL, 16);

    while(buf[i]!='-')i++;
    end = strtol(buf+i+1,0,16);
    fclose(fd);
 //   cerr <<hex<<start<<","<<hex<<address<<","<<hex<<end<<endl;
    return start< address  && address < end;
}

void  trace_pointer(unsigned long * chain ,unsigned long address){
    //if not pointer Just log and return
    //TODO stack overflow?
    unsigned long *  tmp = (unsigned long *)address;
    if(!is_pointer(address)){
       *out<<hex<<address<<endl;
        return;
    }
    for(int i =0 ;i<0x2fff;i++){
        if(!chain[i]){
            break;
        }
        if(chain[i]==address){
            *out<<hex<<address<<"    loop occur. end"<<endl;
            return;
        }else{
//            cerr<<"chain["<<i<<"] => "<<hex<<chain[i]<<" != "<<address<<endl;
        }
    }
    for(int i = 0 ; i<0x2fff;i++){
        if(!chain[i]){
            chain[i]=address;
//            cerr<<"chain["<<i<<"] <= "<<hex<<" set "<<address<<endl;
            break;
        }
    }

    if(is_heap(address)){
        unsigned int size = search_heap_size(address);
        if(size>0x1000){
//            cerr<<hex<<address<<" : "<<size<<endl;
        }
        for(unsigned int i =8 ;i<size;i = i+8){
            //*out<<"dump heap : "<<hex<<address+i<<endl;
            *out<<hex<<address+i<<"->";
            trace_pointer(chain,address+i);
        }
    }else{
        //TODO Non heap. Mabye stack or global variable. How to handle these?
        *out<<hex<<address<<"->";
    }
    trace_pointer(chain,tmp[0]);
    
    //cerr<<"is_pointer = True => "<<hex<<address<<endl;
}
void  trace_args(unsigned int num, unsigned long addr , unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long rcx, unsigned long r8, unsigned long r9){
    *out<<"trace_args : "<<hex<<addr-base_address<<" = "<<num<<endl;
    
    unsigned long chain[0x3000];
    for(int i=0;i<0x3000;i++){
        chain[i]=0;
    }
    switch(num){
        //more than 6 => ida error?
        case 6:*out<<"============= trace r9 ============="<<endl;
            trace_pointer(chain,r9);
//            *out<<endl<<"=================================="<<endl;
        case 5: *out<<"============= trace r8 ============="<<endl;
            trace_pointer(chain,r8);
//            *out<<endl <<"==========================================="<<endl;
        case 4:
            *out<<"============= trace rcx ============="<<endl;
            trace_pointer(chain,rcx);
//            *out<<endl<<"====================================="<<endl;
        case 3:
            *out<<"============= trace rdx ============="<<endl;
            trace_pointer(chain,rdx);
//            *out<<endl<<"====================================="<<endl;
        case 2:
            *out<<"============= trace rsi ============="<<endl;
            trace_pointer(chain,rsi);
//            *out<<endl<<"====================================="<<endl;
        case 1:
            *out<<"============= trace rdi ============="<<endl;
            trace_pointer(chain,rdi);
//            *out<<endl << "==================================="<<endl;
        case 0: break;
        default : *out<< hex<<addr<<": more than 6 args"<<endl;
    }
}
static void PIN_FAST_ANALYSIS_CALL at_call_ind(app_pc instr_addr, app_pc target_addr, app_pc RSP, int tid, app_pc next_addr, unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long rcx, unsigned long r8, unsigned long r9){

    //Not linux calling convention?
    PIN_LockClient();
    IMG img = IMG_FindByAddress(target_addr);
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)){
        return;
    }
    int num = get_arg_num(target_addr);
    if(!num){
        return;
    }
    trace_args(num, target_addr, rdi,rsi,rdx,rcx,r8,r9);//TODO edit addr
    *out << "AT_CALL_IND, thread id : "<<tid << ", pc : "<<hex<< instr_addr-base_address <<  ", rdi : "<<hex<<rdi << endl;
    PIN_UnlockClient();
}
static void PIN_FAST_ANALYSIS_CALL at_call(app_pc instr_addr, app_pc target_addr, app_pc RSP, int tid, app_pc next_addr, unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long rcx, unsigned long r8, unsigned long     r9){
    PIN_LockClient();
    IMG img = IMG_FindByAddress(target_addr);
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)){
        return;
    }
    int num = get_arg_num(target_addr);
    if(!num){
        return;
    }
    trace_args(num, target_addr, rdi,rsi,rdx,rcx,r8,r9);//TODO edit addr
    *out << "AT_CALL, thread id : "<<tid << ", pc : "<<hex<< instr_addr -base_address << endl;
    PIN_UnlockClient();
}
static void PIN_FAST_ANALYSIS_CALL at_return(app_pc instr_addr, app_pc target_addr, ADDRINT RSP, ADDRINT RAX, int tid, unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long rcx, unsigned long r8, unsigned long     r9){
//    *out << "AT_RETURN, thread id : "<<tid << ", pc : "<<hex<< instr_addr -base_address << endl;
}
static void PIN_FAST_ANALYSIS_CALL at_jmp_ind(app_pc instr_addr, app_pc target_addr, ADDRINT RSP, int tid, unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long rcx, unsigned long r8, unsigned long     r9){
    
    //trace_args(get_arg_num(target_addr), target_addr, rdi,rsi,rdx,rcx,r8,r9);//TODO edit addr
    //*out << "AT_JMP_INS, thread id : "<<tid << ", pc : "<<hex<< instr_addr -base_address << endl;

}

static VOID event_app_instruction(TRACE trace, VOID*)
{

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS instr = BBL_InsHead(bbl); INS_Valid(instr); instr = INS_Next(instr)) {
            IMG img = IMG_FindByAddress(TRACE_Address(trace));
            if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)){
                continue;
            }
            if(!base_address){
                base_address = IMG_LowAddress(img);
            }
			auto next_addr = INS_Address(instr) + INS_Size(instr);
//            _is_pointer(next_addr,1);
            if (INS_IsDirectCall(instr)) {
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_call, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_ADDRINT, next_addr, IARG_REG_VALUE, REG_RDI, IARG_REG_VALUE,REG_RSI,IARG_REG_VALUE,REG_RDX,IARG_REG_VALUE, REG_RCX, IARG_REG_VALUE,REG_R8,IARG_REG_VALUE,REG_R9, IARG_END);
			}

			else if (INS_IsRet(instr)) {
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_return, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_REG_VALUE, REG_EAX, IARG_THREAD_ID, IARG_END);
			}

			else if (INS_IsIndirectControlFlow(instr)) {
				if (INS_Opcode(instr) != XED_ICLASS_JMP){
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_call_ind, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_ADDRINT, next_addr, IARG_END);
				}
                else{
					INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_jmp_ind, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_END);
			    }
            }

		}
	}
	return;
}


void init_arg_table(){
    FILE * fd =  fopen("functype_","r");
    fseek(fd,0,SEEK_END);
    unsigned long size = ftell(fd);
    char * buf = (char * ) malloc(size+1);  
    char * tmp=buf ;
    fseek(fd,0,SEEK_SET);
    if (fread(buf,1,size,fd)!=size){
        cerr<<"arg_table parsing error"<<endl;
        exit(1);
    }
    char *ptr = buf;
    size=0;
    cerr <<"test2"<<endl;
    while(ptr[0]){
        ptr++;
        if(ptr[0]=='\n'){
            size++;
        }
    }
    table_size= size;
    cerr <<"test"<<endl;
    args_table = (args_mem * )malloc(sizeof(args_mem) *size);
    ptr= tmp;
    for( unsigned  int i=0; i < size;i++){
        tmp = ptr;
        while(ptr[0]!='|')ptr++;
        ptr[0]='\x00';
        args_table[i].addr = strtol(tmp,0,0x10);
//        cerr <<"addr : " <<hex<<args_table[i].addr<<endl;
        ptr++;
        tmp=ptr;
        while(ptr[0]!='\n')ptr++;     
        ptr[0]='\x00';
        args_table[i].num = atoi(tmp);
        ptr++;
//        cerr <<"num : " <<hex<<args_table[i].num<<endl;
    }
    free(buf);
}


int main(int argc, char* argv[])
{
//    sleep(0x8);
    init_arg_table();
    init_log();
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName ="output"; //KnobOutputFile.Value();

    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        //TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        //PIN_AddThreadStartFunction(ThreadStart, 0);

//        RTN_AddInstrumentFunction(InsFunction,0,IARG_THREAD_ID, 0);
        // Register function to be called when the application exits
        TRACE_AddInstrumentFunction(event_app_instruction, nullptr);
        //PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
