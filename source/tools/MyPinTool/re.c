#define _GNU_SOURCE
//https://github.com/tharina/heap-tracer
#define GREEN ""
#define YELLOW ""
#define BLUE ""
#define RESET ""

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <malloc.h>
#include <inttypes.h>
#include <fcntl.h>
#include <math.h>
#include <sys/shm.h> 
#include <sys/ipc.h> 
// gcc -o hook.so -fPIC -shared hook.c -ldl
// LD_PRELOAD=./hook.so ./myexecutable

// in GDB: set exec-wrapper env 'LD_PRELOAD=./hook.so'


#define BEGIN_HOOK \
        reentrancy_guard++;

#define HOOK \
    if (reentrancy_guard == 1)

#define END_HOOK \
        reentrancy_guard--;


int reentrancy_guard;

typedef struct heap_element{
    void * addr;
    unsigned int size;// If size>0xffffffff => too big size. So pass.
}heap_element;

heap_element * heap_table = 0;

void* (*real_calloc)(size_t size,size_t size2); 

static void con() __attribute__((constructor));
int fd ; 
void insert(void * address, unsigned int size){
    if(!heap_table){
        printf("heap_table null\n");
        exit(1);
        con();
    }
    for(unsigned int i =0; i <0xfffff0;i++){
        if(!heap_table[i].addr || heap_table[i].addr==0xffffffffffffffff){
            heap_table[i].addr=address;
            heap_table[i].size= size;
            return; 
        }
    }
    //OOM?
    printf("insert error %p\n",address);
    exit(-1);
}
void rm(void * address){
    if(!address){
        return;
    }
    for(unsigned int i =0; i <0xfffff0;i++){
        if(heap_table[i].addr==address){
            heap_table[i].addr=0xffffffffffffffff;
            heap_table[i].size=0;
            return; 
        }
    }
//    printf("rm error %p\n",address); //TODO why???

    //exit(-1);   
}


void* (*real_malloc)(size_t size); 
void* hook_malloc(size_t size) {
    __malloc_hook=0;
    if(!real_malloc){
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }
    void* chunk = real_malloc(size);
//    fprintf("malloc = %p\n",chunk);
    insert(chunk,size);

    __malloc_hook=&hook_malloc;
    return chunk;
}

void (*real_free)(void* ptr);
void hook_free(void* ptr) {
    __free_hook=0;
    if(!real_free){
        real_free = dlsym(RTLD_NEXT, "free");
    }
        
//    printf("free %p\n",ptr);
    real_free(ptr);
    rm(ptr);
    __free_hook=&hook_free;
}

void* (*real_realloc)(void* ptr, size_t size);
void* hook_realloc(void* ptr, size_t size) {
    __realloc_hook=0;
    if(!real_realloc){
        real_realloc = dlsym(RTLD_NEXT, "realloc");
    }
    void* old_chunk = ptr;
    void* chunk = real_realloc(ptr, size);

//    printf("realloc %p,%p\n",old_chunk,chunk);//error in here. => result in rm error?? 
    rm(old_chunk);
    insert(chunk,size);
    __realloc_hook = &hook_realloc;

    return chunk;
}
void con() {
    int shmid;
    printf("con\n");
    shmid = shmget(getpid(),sizeof(heap_element)*0xfffff0, IPC_CREAT|0666);
    if(shmid==-1){
        printf("shmget error\n");
        exit(-1);
    }
    heap_table=shmat(shmid,NULL,0);
    if(heap_table==(void*)0){
        printf("heap_table create error\n");
        exit(-1);
    }

    printf("heap_table = %p\n",heap_table);
    __malloc_hook = &hook_malloc;
    __free_hook = &hook_free;
    __realloc_hook = &hook_realloc;
}
