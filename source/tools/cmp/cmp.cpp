// cmptrace.cpp
//https://github.com/inaz2/pintools/blob/master/cmptrace.cpp
#include <cstdio>
#include "pin.H"
#include <iostream>
#include<fstream>
using namespace std;
std::ostream* out = &std::cerr;
VOID log_f(){
    string fileName = "trace";
    out = new std::ofstream(fileName.c_str());
}



VOID print_cmp_mem(VOID *ip, UINT64 * addr, ADDRINT value) {
    PIN_LockClient();
    IMG img = IMG_FindByAddress((unsigned long )ip);
    unsigned long base = IMG_LowAddress(img);
    string name = IMG_Name(img);
    *out <<name << " + 0x"<<hex<< (unsigned long )ip -base << " : cmp 0x" <<*addr<<" , 0x"<<value<< endl ;
    //fprintf(stderr, "[%016lx] cmp 0x%lx, 0x%lx\n", (UINT64)ip, *addr, value);
    PIN_UnlockClient();
}

VOID print_cmp_reg(VOID *ip, ADDRINT lvalue, ADDRINT rvalue) {
//    cerr<<"start, ip : "<<hex<<ip<<endl;
    PIN_LockClient();
    IMG img = IMG_FindByAddress((unsigned long )ip);
    if(!IMG_Valid(img)){
        return;
    }
    unsigned long base = IMG_LowAddress(img);
    string name = IMG_Name(img);
    
//    *out<<hex<< (unsigned long )ip << " : cmp 0x" <<lvalue<<" , 0x"<<rvalue<< endl ;
    *out <<name << " + 0x"<<hex<< (unsigned long )ip -base << " : cmp 0x" <<lvalue<<" , 0x"<<rvalue<< endl ;
    //fprintf(stderr, "[%016lx] cmp 0x%lx, 0x%lx\n", (UINT64)ip, *addr, value);
    PIN_UnlockClient();
//    cerr << "end"<<endl;
}

VOID Instruction(INS ins, VOID *v)
{
    if (INS_Opcode(ins) == XED_ICLASS_CMP) {//missing one??
        if (INS_MemoryOperandCount(ins) == 1) {
            if (INS_OperandIsImmediate(ins, 1)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_cmp_mem, IARG_INST_PTR, IARG_MEMORYOP_EA, 0, IARG_ADDRINT, INS_OperandImmediate(ins, 1), IARG_END);
            } else if (INS_OperandIsReg(ins, 0)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_cmp_mem, IARG_INST_PTR, IARG_MEMORYOP_EA, 0, IARG_REG_VALUE, INS_OperandReg(ins, 0), IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_cmp_mem, IARG_INST_PTR, IARG_MEMORYOP_EA, 0, IARG_REG_VALUE, INS_OperandReg(ins, 1), IARG_END);
            }
        } else {
            if (INS_OperandIsImmediate(ins, 1)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_cmp_reg, IARG_INST_PTR, IARG_REG_VALUE, INS_OperandReg(ins, 0), IARG_ADDRINT, INS_OperandImmediate(ins, 1), IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_cmp_reg, IARG_INST_PTR, IARG_REG_VALUE, INS_OperandReg(ins, 0), IARG_REG_VALUE, INS_OperandReg(ins, 1), IARG_END);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    log_f();
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    return 0;
}
