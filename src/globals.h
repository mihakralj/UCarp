#ifndef __GLOBALS_H__
#define __GLOBALS_H__ 1

#ifdef DEFINE_GLOBALS
# define GLOBAL0(A) A
# define GLOBAL(A, B) A = B
#else
# define GLOBAL0(A) extern A
# define GLOBAL(A, B) extern A
#endif

GLOBAL0(char *interface);
GLOBAL0(struct in_addr srcip);
GLOBAL0(int srcip_prefix);
#ifdef INET6
GLOBAL0(struct in6_addr srcip6);
GLOBAL0(int srcip6_prefix);
GLOBAL0(struct in6_addr vaddr6);
GLOBAL0(int vaddr6_prefix);
GLOBAL0(char *vaddr6_arg);
GLOBAL0(int address_family);  /* AF_INET or AF_INET6 */
#endif
GLOBAL0(struct in_addr mcastip);
GLOBAL0(unsigned char vhid);
GLOBAL0(char *pass);
GLOBAL0(struct in_addr vaddr);
GLOBAL0(int vaddr_prefix);
GLOBAL(unsigned char advbase, DEFAULT_ADVBASE);
GLOBAL(unsigned int dead_ratio, DEFAULT_DEAD_RATIO);
GLOBAL0(unsigned char advskew);
GLOBAL0(char *upscript);
GLOBAL0(char *downscript);
GLOBAL0(signed char debug);
GLOBAL0(signed char preempt);
GLOBAL0(signed char neutral);
GLOBAL0(signed char shutdown_at_exit);
GLOBAL0(unsigned char hwaddr[6]);
GLOBAL0(signed char no_syslog);
GLOBAL0(signed char daemonize);
GLOBAL0(signed char ignoreifstate);
GLOBAL0(signed char no_mcast);
GLOBAL(int syslog_facility, DEFAULT_FACILITY);
GLOBAL0(char *vaddr_arg);
GLOBAL0(char *xparam);
GLOBAL0(sig_atomic_t received_signal);
#endif
