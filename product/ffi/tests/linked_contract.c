/* C ABI v1 consumer. Runs against the REAL Rust library; never a mock shim.
 * Valid pointer allocations only: a C library cannot validate arbitrary pointers.
 * POSIX pthread/Win32 dependencies belong only to this development harness. */
#include "../pcap_evidence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#define CHECK(test) do { if (!(test)) { fprintf(stderr,"ABI check failed at %s:%d: %s\n",__FILE__,__LINE__,#test); return 1; } } while (0)
static const unsigned char capture[] = {
  0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,101,0,0,0,
  1,0,0,0,0,0,0,0,28,0,0,0,28,0,0,0,
  0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,192,0,2,2,
  0x9c,0x40,0,53,0,8,0,0
};
static int lifecycle(void) {
    uint64_t h=0; size_t n=777,used=0; unsigned char *a,*b;
    CHECK(pcap_create(4096,1024*1024,&h)==PCAP_OK && h!=0);
    CHECK(pcap_output_size(h,&n)==PCAP_INVALID && n==777);
    CHECK(pcap_feed(h,NULL,0)==PCAP_OK);
    CHECK(pcap_feed(h,NULL,1)==PCAP_INVALID);
    CHECK(pcap_feed(h,capture,7)==PCAP_OK);
    CHECK(pcap_feed(h,capture+7,sizeof(capture)-7)==PCAP_OK);
    CHECK(pcap_analyze(h)==PCAP_OK);
    CHECK(pcap_analyze(h)==PCAP_INVALID);
    CHECK(pcap_feed(h,capture,1)==PCAP_INVALID);
    CHECK(pcap_output_size(h,NULL)==PCAP_INVALID);
    CHECK(pcap_output_size(h,&n)==PCAP_OK && n>0 && n<1024*1024);
    a=(unsigned char*)malloc(n+1);b=(unsigned char*)malloc(n+1);
    CHECK(a!=NULL && b!=NULL);memset(a,0xa5,n+1);memset(b,0x5a,n+1);
    CHECK(pcap_copy_output(h,a,n-1,&used)==PCAP_BUFFER_TOO_SMALL && used==n);
    for(size_t i=0;i<=n;i++) CHECK(a[i]==0xa5);
    CHECK(pcap_copy_output(h,NULL,0,&used)==PCAP_BUFFER_TOO_SMALL && used==n);
    CHECK(pcap_copy_output(h,NULL,n,&used)==PCAP_INVALID);
    CHECK(pcap_copy_output(h,a,n,NULL)==PCAP_INVALID);
    CHECK(pcap_copy_output(h,a,n,&used)==PCAP_OK && used==n && a[n]==0xa5);
    CHECK(pcap_copy_output(h,b,n,&used)==PCAP_OK && used==n && b[n]==0x5a);
    CHECK(memcmp(a,b,n)==0 && a[0]=='{' && a[n-1]=='\n');
    CHECK(pcap_destroy(h)==PCAP_OK);
    CHECK(pcap_destroy(h)==PCAP_NO_HANDLE);
    CHECK(pcap_analyze(h)==PCAP_NO_HANDLE);
    CHECK(pcap_output_size(h,&n)==PCAP_NO_HANDLE);
    free(a);free(b);return 0;
}
static int failure_contracts(void) {
    uint64_t h=123,slots[8];size_t n=12;
    CHECK(pcap_abi_version()==1);
    CHECK(pcap_create(1,1,NULL)==PCAP_INVALID);
    CHECK(pcap_create(0,4096,&h)==PCAP_INVALID && h==123);
    CHECK(pcap_create(4096,0,&h)==PCAP_INVALID);
    CHECK(pcap_create(64*1024*1024+1,4096,&h)==PCAP_INVALID);
    CHECK(pcap_create(4096,64*1024*1024+1,&h)==PCAP_INVALID);
    CHECK(pcap_destroy(0)==PCAP_NO_HANDLE);
    CHECK(pcap_create(2,4096,&h)==PCAP_OK);
    CHECK(pcap_feed(h,capture,3)==PCAP_LIMIT);
    CHECK(pcap_analyze(h)==PCAP_ANALYSIS_ERROR);
    CHECK(pcap_output_size(h,&n)==PCAP_INVALID && n==12);
    CHECK(pcap_analyze(h)==PCAP_INVALID);
    CHECK(pcap_destroy(h)==PCAP_OK);
    CHECK(pcap_create(4096,1,&h)==PCAP_OK);
    CHECK(pcap_feed(h,capture,sizeof(capture))==PCAP_OK);
    CHECK(pcap_analyze(h)==PCAP_LIMIT);
    CHECK(pcap_output_size(h,&n)==PCAP_INVALID);
    CHECK(pcap_destroy(h)==PCAP_OK);
    for(unsigned i=0;i<8;i++)CHECK(pcap_create(4096,4096,&slots[i])==PCAP_OK);
    CHECK(pcap_create(4096,4096,&h)==PCAP_LIMIT);
    for(unsigned i=0;i<8;i++)CHECK(pcap_destroy(slots[i])==PCAP_OK);
    return 0;
}
struct worker_state {int result;};
#ifdef _WIN32
static DWORD WINAPI threaded(LPVOID argument)
#else
static void *threaded(void *argument)
#endif
{
    struct worker_state *s=(struct worker_state*)argument;
    s->result=0;for(unsigned n=0;n<20;n++){if(lifecycle()){s->result=1;break;}}
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
static int concurrent_contract(void) {
    struct worker_state states[4];
#ifdef _WIN32
    HANDLE threads[4];
    for(unsigned i=0;i<4;i++){threads[i]=CreateThread(NULL,0,threaded,&states[i],0,NULL);CHECK(threads[i]!=NULL);}
    CHECK(WaitForMultipleObjects(4,threads,TRUE,30000)==WAIT_OBJECT_0);
    for(unsigned i=0;i<4;i++){CHECK(CloseHandle(threads[i]));CHECK(states[i].result==0);}
#else
    pthread_t threads[4];
    for(unsigned i=0;i<4;i++)CHECK(pthread_create(&threads[i],NULL,threaded,&states[i])==0);
    for(unsigned i=0;i<4;i++){CHECK(pthread_join(threads[i],NULL)==0);CHECK(states[i].result==0);}
#endif
    return 0;
}
int main(void) {
    CHECK(failure_contracts()==0);
    for(unsigned n=0;n<20;n++)CHECK(lifecycle()==0);
    CHECK(concurrent_contract()==0);
    puts("{\"schema\":\"pcap-evidence.linked-abi-check.v1\",\"status\":\"PASS\",\"abi\":1,\"sequential_cycles\":20,\"concurrent_cycles\":80,\"panic_injection\":\"NOT_RUN\"}");
    return 0;
}
