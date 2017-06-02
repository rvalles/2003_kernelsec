/* PTrace access control module.
 *
 * With this module loaded, only UID 0 and defined GID are allowed to use ptrace() syscall.
 * Have fun.
 *
 * Roc Vallès Domènech
 */

#define __KERNEL__
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/unistd.h>

/* set the group that's allowed here */
#define GID 4

MODULE_AUTHOR("rvalles");
MODULE_DESCRIPTION("Limits ptrace() syscall access.");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
int (*o_ptrace)(int, int, void *, void *);

int my_ptrace(int request, int pid, void *addr, void *data) {
	int returnvalue;
	int group;
	
	if(current->uid)
		for(group = 0;(group < current->ngroups - 1) && (current->groups[group] != GID);group++);
	if((!current->uid) || (current->groups[group] == GID))
	{ 
		returnvalue = (*o_ptrace)(request, pid, addr, data);
	}
	else
	{
		return -1;
	}
	
	return returnvalue;
}

int init_module() {
	o_ptrace = sys_call_table[__NR_ptrace];
	sys_call_table[__NR_ptrace] = my_ptrace;
	printk("ptrace hook loaded correctly\n");
	return 0;
}
void cleanup_module() {
	sys_call_table[__NR_ptrace] = o_ptrace;
	printk("ptrace hook removed\n");
}
	
