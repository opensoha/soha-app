//go:build darwin && cgo

#include <mach/mach.h>
#include <mach/task_info.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 1 means the PID is proven absent; other failures remain unknown.
int ni_recovery_meta(unsigned int pid,uint64_t *out) {
 struct proc_bsdinfo info={0};errno=0;
 int n=proc_pidinfo((int)pid,PROC_PIDTBSDINFO,0,&info,sizeof(info));
 if(n!=sizeof(info))return n<=0&&errno==ESRCH?1:2;
 out[0]=info.pbi_start_tvsec;out[1]=info.pbi_start_tvusec;out[2]=info.pbi_uid;out[3]=info.pbi_ruid;out[4]=info.pbi_ppid;out[5]=info.pbi_pgid;out[6]=info.pbi_status;
 return 0;
}
int ni_recovery_path(unsigned int pid,char *path,int capacity) {
 int n=proc_pidpath((int)pid,path,(uint32_t)capacity);return n>0&&n<capacity?0:-1;
}
// Only argv is copied out. The sysctl's environment-containing buffer is erased.
char *ni_recovery_args(unsigned int pid,int *length) {
 int mib[]={CTL_KERN,KERN_PROCARGS2,(int)pid};size_t size=0;
 if(sysctl(mib,3,NULL,&size,NULL,0)||size<sizeof(int)||size>1048576)return NULL;
 char *raw=calloc(1,size);if(!raw)return NULL;
 size_t received=size;char *result=NULL;
 if(sysctl(mib,3,raw,&received,NULL,0)||received>size||received<sizeof(int))goto done;
 int argc=0;memcpy(&argc,raw,sizeof(argc));if(argc<1||argc>16)goto done;
 size_t pos=sizeof(int),start=pos,total=0;
 while(pos<received&&raw[pos])pos++;
 if(pos==received)goto done;
 while(pos<received&&!raw[pos])pos++;
 start=pos;
 for(int i=0;i<argc;i++) {
  size_t begin=pos;while(pos<received&&raw[pos])pos++;
  if(pos==received||pos-begin>4096)goto done;
  pos++;total=pos-start;if(total>65536)goto done;
 }
 result=malloc(total);if(result){memcpy(result,raw+start,total);*length=(int)total;}
done:;
 volatile unsigned char *wipe=(volatile unsigned char *)raw;for(size_t i=0;i<size;i++)wipe[i]=0;free(raw);return result;
}
int ni_recovery_task(unsigned int pid,unsigned int *port,unsigned int *token) {
 mach_port_t task=MACH_PORT_NULL;
 kern_return_t status=task_for_pid(mach_task_self(),(int)pid,&task);
 if(status!=KERN_SUCCESS){if(task!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),task);return (int)status;}
 audit_token_t audit={0};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
 status=task_info(task,TASK_AUDIT_TOKEN,(task_info_t)&audit,&count);
 if(status!=KERN_SUCCESS||count!=TASK_AUDIT_TOKEN_COUNT){mach_port_deallocate(mach_task_self(),task);return status==KERN_SUCCESS?-1:(int)status;}
 memcpy(token,&audit,sizeof(audit));*port=task;return 0;
}
int ni_recovery_audit(unsigned int port,unsigned int *token) {
 audit_token_t audit={0};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
 kern_return_t status=task_info(port,TASK_AUDIT_TOKEN,(task_info_t)&audit,&count);
 if(status!=KERN_SUCCESS||count!=TASK_AUDIT_TOKEN_COUNT)return -1;
 memcpy(token,&audit,sizeof(audit));return 0;
}
int ni_recovery_terminate(unsigned int port){return (int)task_terminate(port);}
void ni_recovery_release(unsigned int port){mach_port_deallocate(mach_task_self(),port);}

static int ni_controller_tuple(const struct socket_fdinfo *info,int family,const void *server,unsigned short serverPort,const void *client,unsigned short clientPort) {
 const struct socket_info *so=&info->psi;
 if(so->soi_family!=family||so->soi_protocol!=IPPROTO_TCP||so->soi_kind!=SOCKINFO_TCP||so->soi_proto.pri_tcp.tcpsi_state!=TSI_S_ESTABLISHED)return 0;
 const struct in_sockinfo *in=&so->soi_proto.pri_tcp.tcpsi_ini;
 if(ntohs((unsigned short)in->insi_lport)!=serverPort||ntohs((unsigned short)in->insi_fport)!=clientPort)return 0;
 if((family==AF_INET&&in->insi_vflag!=INI_IPV4)||(family==AF_INET6&&in->insi_vflag!=INI_IPV6))return 0;
 const void *local=family==AF_INET?(const void *)&in->insi_laddr.ina_46.i46a_addr4:(const void *)&in->insi_laddr.ina_6;
 const void *remote=family==AF_INET?(const void *)&in->insi_faddr.ina_46.i46a_addr4:(const void *)&in->insi_faddr.ina_6;
 int n=family==AF_INET?4:16;
 return !memcmp(local,server,n)&&!memcmp(remote,client,n);
}
// A listener alone is insufficient: require the exact accepted TCP tuple in this PID.
int ni_recovery_controller(unsigned int pid,int family,const void *server,unsigned short serverPort,const void *client,unsigned short clientPort,uint64_t *cookie) {
 if(pid<2||pid>INT_MAX||(family!=AF_INET&&family!=AF_INET6)||!server||!client||!cookie)return -1;
 int needed=proc_pidinfo((int)pid,PROC_PIDLISTFDS,0,NULL,0);
 if(needed<=0||needed>(int)(4096*sizeof(struct proc_fdinfo)))return -1;
 int capacity=needed+(int)(32*sizeof(struct proc_fdinfo));struct proc_fdinfo *fds=calloc(1,capacity);if(!fds)return -1;
 int size=proc_pidinfo((int)pid,PROC_PIDLISTFDS,0,fds,capacity);
 if(size<=0||size>=capacity||size%(int)sizeof(*fds)){free(fds);return -1;}
 int matches=0,fd=-1;struct socket_fdinfo selected={0};
 for(int i=0;i<size/(int)sizeof(*fds);i++) {
  if(fds[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;
  struct socket_fdinfo current={0};
  if(proc_pidfdinfo((int)pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&current,sizeof(current))!=sizeof(current)){free(fds);return -1;}
  if(!ni_controller_tuple(&current,family,server,serverPort,client,clientPort))continue;
  matches++;fd=fds[i].proc_fd;selected=current;
 }
 free(fds);if(matches==0)return 1;if(matches!=1||!selected.psi.soi_so||!selected.psi.soi_pcb||!selected.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt)return -1;
 struct socket_fdinfo final={0};
 if(proc_pidfdinfo((int)pid,fd,PROC_PIDFDSOCKETINFO,&final,sizeof(final))!=sizeof(final)||!ni_controller_tuple(&final,family,server,serverPort,client,clientPort))return -1;
 if(final.psi.soi_so!=selected.psi.soi_so||final.psi.soi_pcb!=selected.psi.soi_pcb||final.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt!=selected.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt)return -1;
 cookie[0]=(uint64_t)fd;cookie[1]=final.psi.soi_so;cookie[2]=final.psi.soi_pcb;cookie[3]=final.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt;return 0;
}
