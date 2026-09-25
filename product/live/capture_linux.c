/* Optional standalone Linux acquisition adapter. Never linked into the parser.
 * Requires an explicit --allow-live-capture flag. No escalation or telemetry.
 * Only Ethernet interfaces; kernel socket timestamps; software EtherType filter.
 */
#define _GNU_SOURCE
#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t stopped=0;
static void stop_capture(int sig){(void)sig;stopped=1;}
static void le32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));}
static int write_all(int fd,const void *p,size_t n){const uint8_t *b=p;while(n){ssize_t k=write(fd,b,n);if(k<0&&errno==EINTR)continue;if(k<=0)return -1;b+=(size_t)k;n-=(size_t)k;}return 0;}
static int raw_socket(void){
#ifdef PCAP_TEST_DENY_SOCKET
 errno=EPERM;return -1;
#else
 return socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_ALL));
#endif
}
static int failure(const char *stage){fprintf(stderr,"{\"status\":\"FAILED\",\"stage\":\"%s\",\"errno\":%d}\n",stage,errno);return 3;}
static int integer(const char *s,uint64_t *out){char *end=NULL;if(!s||!s[0]||s[0]=='-')return -1;errno=0;unsigned long long n=strtoull(s,&end,10);if(errno||!end||*end)return -1;*out=(uint64_t)n;return 0;}
int main(int argc,char **argv){const char *iface=NULL,*output=NULL;bool allowed=false;uint64_t maximum=100000,disk=1024ULL*1024*1024,filter=0;
 for(int i=1;i<argc;i++){if(strcmp(argv[i],"--allow-live-capture")==0){allowed=true;continue;}if(i+1>=argc)return 2;
  const char *flag=argv[i],*v=argv[++i];if(strcmp(flag,"--interface")==0)iface=v;else if(strcmp(flag,"--output")==0)output=v;
  else if(strcmp(flag,"--max-packets")==0){if(integer(v,&maximum))return 2;}
  else if(strcmp(flag,"--max-bytes")==0){if(integer(v,&disk))return 2;}
  else if(strcmp(flag,"--ethertype")==0){if(integer(v,&filter)||filter>65535)return 2;}else return 2;
 }
 if(!allowed||!iface||!output||!maximum||disk<24||strlen(iface)>=IFNAMSIZ){fprintf(stderr,"Explicit authorization, Ethernet interface, NEW output and finite budgets required.\n");return 2;}
 int fd=raw_socket();if(fd<0)return failure("cap_net_raw_or_socket");
 struct ifreq request;memset(&request,0,sizeof request);memcpy(request.ifr_name,iface,strlen(iface));
 if(ioctl(fd,SIOCGIFHWADDR,&request)<0||request.ifr_hwaddr.sa_family!=ARPHRD_ETHER){close(fd);errno=EAFNOSUPPORT;return failure("ethernet_interface_required");}
 unsigned index=if_nametoindex(iface);if(!index){close(fd);return failure("interface_index");}
 struct sockaddr_ll address;memset(&address,0,sizeof address);address.sll_family=AF_PACKET;address.sll_protocol=htons(ETH_P_ALL);address.sll_ifindex=(int)index;
 if(bind(fd,(struct sockaddr *)&address,sizeof address)<0){close(fd);return failure("bind");}
 int one=1,buffer=4*1024*1024;
 if(setsockopt(fd,SOL_SOCKET,SO_TIMESTAMPNS,&one,sizeof one)<0||setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof buffer)<0){close(fd);return failure("socket_options");}
 char temp[PATH_MAX];if(snprintf(temp,sizeof temp,"%s.partial.%ld",output,(long)getpid())>=(int)sizeof temp){close(fd);return 2;}
 int file=open(temp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(file<0){close(fd);return failure("new_temporary_output");}
 uint8_t header[24]={0x4d,0x3c,0xb2,0xa1,2,0,4,0};le32(header+16,65535);le32(header+20,1);
 int error=write_all(file,header,sizeof header);uint64_t packets=0,total=24,filtered=0;uint8_t data[65535];
 struct sigaction action;memset(&action,0,sizeof action);action.sa_handler=stop_capture;sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
 while(!error&&!stopped&&packets<maximum){struct pollfd poller={fd,POLLIN,0};int ready=poll(&poller,1,250);if(ready<0){if(errno==EINTR)continue;error=1;break;}if(!ready)continue;
  struct iovec iov={data,sizeof data};union{struct cmsghdr alignment;char raw[CMSG_SPACE(sizeof(struct timespec))];} control;
  struct msghdr message;memset(&message,0,sizeof message);message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control.raw;message.msg_controllen=sizeof control.raw;
  ssize_t n=recvmsg(fd,&message,MSG_TRUNC);if(n<0){if(errno==EINTR)continue;error=1;break;}
  size_t cap=(size_t)n>sizeof data?sizeof data:(size_t)n;
  if(filter&&(cap<14||(((unsigned)data[12]<<8)|data[13])!=filter)){filtered++;continue;}
  struct timespec stamp={0,0};bool have=false;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_TIMESTAMPNS&&c->cmsg_len>=CMSG_LEN(sizeof stamp)){memcpy(&stamp,CMSG_DATA(c),sizeof stamp);have=true;}
  if(!have||message.msg_flags&MSG_CTRUNC||stamp.tv_sec<0||(uint64_t)stamp.tv_sec>UINT32_MAX||stamp.tv_nsec<0||stamp.tv_nsec>=1000000000||n>UINT32_MAX){errno=EBADMSG;error=1;break;}
  if(total>disk||16+cap>disk-total){errno=ENOSPC;error=1;break;}
  uint8_t record[16];le32(record,(uint32_t)stamp.tv_sec);le32(record+4,(uint32_t)stamp.tv_nsec);le32(record+8,(uint32_t)cap);le32(record+12,(uint32_t)n);
  error=write_all(file,record,sizeof record)||write_all(file,data,cap);if(!error){packets++;total+=16+cap;}
 }
 struct tpacket_stats stats;memset(&stats,0,sizeof stats);socklen_t length=sizeof stats;bool have_stats=getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&length)==0;close(fd);
 if(!error&&fsync(file)<0){error=1;}
 if(close(file)<0){error=1;}
 if(error){unlink(temp);return failure("capture_or_output");}if(link(temp,output)<0){unlink(temp);return failure("no_clobber_publication");}unlink(temp);
 fprintf(stderr,"{\"status\":\"CAPTURE_CLOSED\",\"packets\":\"%llu\",\"bytes\":\"%llu\",\"filtered\":\"%llu\",\"kernel_drop_counter_available\":%s,\"kernel_drops\":%u,\"timestamp_source\":\"SO_TIMESTAMPNS\",\"analysis_performed\":false}\n",(unsigned long long)packets,(unsigned long long)total,(unsigned long long)filtered,have_stats?"true":"false",stats.tp_drops);return 0;
}
#else
#include <stdio.h>
int main(void){fputs("Linux AF_PACKET is unavailable on this target.\n",stderr);return 2;}
#endif
