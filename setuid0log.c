/* setuid(0) logging module.
 *
 * Roc Vallès Domènech
 */

#define __KERNEL__
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/unistd.h>

/* set the group that's allowed here */
#define GID 4

MODULE_AUTHOR("rvalles");
MODULE_DESCRIPTION("Logs all setuid(0) calls.");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
int (*o_setuid)(int);

int my_setuid(int uid) {
	int returncode;
	if(uid == 0) printk("setuid(0) has been called by %s with pid %d\n", current->comm, current->pid);
	returncode = (*o_setuid)(uid);
	return returncode;
}

int init_module() {
	o_setuid = sys_call_table[__NR_setuid];
	sys_call_table[__NR_setuid] = my_setuid;
	printk("setuid hook loaded correctly\n");
	return 0;
}

void cleanup_module() {
	sys_call_table[__NR_setuid] = o_setuid;
	printk("setuid hook removed\n");
}

