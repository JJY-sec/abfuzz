#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>




typedef void *(*malloc_t)(size_t size);
typedef void *(*free_t)(void *addr);
typedef void *(*realloc_t)(void * addr,size_t size);
int fd;


void *malloc(size_t size)
{
    char buf[0x100]; 
    void * ret ;
    if(!fd){
        memcpy(buf,"malloc_trace_",0x5);
        memcpy(buf+4,"a",0x4);
        fd = open(buf, O_RDWR|O_CREAT );
        if(!fd){
            //printf("open error\n");
            exit(1);
        }
    }
	malloc_t malloc_fn;
	malloc_fn = (malloc_t)dlsym(RTLD_NEXT, "malloc");
    ret = malloc_fn(size);
   // snprintf(buf,0xff,"%p|0x%ld\n",ret,size);
    write(fd,buf,strlen(buf));
	return ret;
}

void *free(void * addr )
{
    char buf[0x100]; 
    void * ret ;
    if(!fd){
        snprintf(buf,0xff,"%d_malloc_trace",getpid());
        fd = open(buf, O_RDWR|O_CREAT );
        if(!fd){
            printf("open error\n");
            exit(1);
        }
    }
	free_t free_fn;
	free_fn = (free_t)dlsym(RTLD_NEXT, "free");
    ret = free(addr);
//    snprintf(buf,0xff,"%p|0x%ld\n",ret,size);
    write(fd,buf,strlen(buf));
	return 0;
}

void *realloc(void * addr , size_t size)
{
    char buf[0x100]; 
    void * ret ;
    if(!fd){
        snprintf(buf,0xff,"%d_malloc_trace",getpid());
        fd = open(buf, O_RDWR|O_CREAT );
        if(!fd){
            printf("open error\n");
            exit(1);
        }
    }
	realloc_t realloc_fn;
	realloc_fn = (malloc_t)dlsym(RTLD_NEXT, "realloc");
    ret = realloc_fn(addr, size);
//    snprintf(buf,0xff,"%p|0x%ld\n",ret,size);
    write(fd,buf,strlen(buf));
	return ret;
}


