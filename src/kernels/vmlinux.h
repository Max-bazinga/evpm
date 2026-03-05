/* Minimal vmlinux.h for eVPM - avoid conflicts with system headers */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

/* Use standard linux headers */
#include <linux/bpf.h>

#endif /* __VMLINUX_H__ */
