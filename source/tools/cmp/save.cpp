/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include "pin.H"
#include <iostream>
using std::endl;
using namespace std;
UINT64 icount = 0;
vector<string> split(string s, string divid) {
	vector<string> v;
	int start = 0;
	int d = s.find(divid);
	while (d != -1){
		v.push_back(s.substr(start, d - start));
		start = d + 1;
		d = s.find(divid, start);
	}
	v.push_back(s.substr(start, d - start));

	return v;
}
VOID docount() { 
    icount++; 
}


VOID Instruction(INS ins, VOID* v) { 
    string dis = INS_Disassemble(ins);
    //vpcmpeqb
    //pcmpeqb ==>useless?
    //cmp
    vector<string> v_dis = split(dis," ");
    if(v_dis[0]!="cmp"){
        return;
    }
    //UINT64 value = INS_OperandImmediate(ins,0);
    cerr<<hex<<value<<endl;
    cerr<<dis<<endl;

    for (string i : v_dis) {
		cerr << i << "\n";
	}
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END); 
}

VOID Fini(INT32 code, VOID* v) { std::cerr << "Count: " << icount << endl; }

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
