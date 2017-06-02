/* Module against setuid(0).
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
#define LOG

MODULE_AUTHOR("rvalles");
MODULE_DESCRIPTION("When a process calls setuid(0), it gets killed and logged.");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
int (*o_setuid)(int);
int (*kill)(int, int);

int my_setuid(int uid) {
	int returncode;
	if(uid == 0) {
#ifdef LOG
		printk("setuid(0) has been called by %s with pid %d. Killing it.\n", current->comm, current->pid);
#endif
		(*kill)(current->pid, SIGKILL);
	}
	returncode = (*o_setuid)(uid);
	return returncode;
}

int init_module() {
	o_setuid = sys_call_table[__NR_setuid];
	kill = sys_call_table[__NR_kill];
	sys_call_table[__NR_setuid] = my_setuid;
	printk("setuid hook loaded correctly\n");
	return 0;
}

void cleanup_module() {
	sys_call_table[__NR_setuid] = o_setuid;
	printk("setuid hook removed\n");
}

