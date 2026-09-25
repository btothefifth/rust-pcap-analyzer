#include "pcap_evidence.h"
#include <assert.h>
#include <stdlib.h>
/* Minimal valid classic PCAP with no packets. Built independently. */
static const uint8_t empty_pcap[24]={0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,255,255,0,0,1,0,0,0};
int main(void){assert(pcap_abi_version()==1);for(int i=0;i<100;i++){
 uint64_t h=0;size_t n=0,w=0;assert(pcap_create(1024,65536,&h)==PCAP_OK);
 assert(pcap_feed(h,empty_pcap,sizeof empty_pcap)==PCAP_OK);assert(pcap_analyze(h)==PCAP_OK);
 assert(pcap_output_size(h,&n)==PCAP_OK&&n>0);uint8_t *out=malloc(n);assert(out);
 assert(pcap_copy_output(h,out,n-1,&w)==PCAP_BUFFER_TOO_SMALL&&w==n);
 assert(pcap_copy_output(h,out,n,&w)==PCAP_OK&&w==n);free(out);
 assert(pcap_destroy(h)==PCAP_OK);assert(pcap_destroy(h)==PCAP_NO_HANDLE);
 }return 0;}
