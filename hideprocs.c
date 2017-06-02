/* Module to hide non-owned processes to users.
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
#include <linux/dirent.h>
#include <linux/fs.h>

#define LOG
#define ALLOWED_GID 4 //adm
#define OPEN_SUPPORT
#define GETDENTS64_SUPPORT

#ifdef GETDENTS64_SUPPORT
#define ATOI_SUPPORT
#define GET_TASK_STRUCT_BY_PID
#endif

#ifdef OPEN_SUPPORT
#define ATOI_SUPPORT
#define GET_TASK_STRUCT_BY_PID
#endif

MODULE_AUTHOR("Roc Vallès Domènech");
MODULE_DESCRIPTION("This module allow non-root users to list only their own processes");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
#ifdef GETDENTS64_SUPPORT
int (*o_getdents64)(unsigned int fd, struct dirent *dirp, unsigned int count);
#endif
#ifdef OPEN_SUPPORT
int (*o_open)(const char *pathname, int flags, mode_t mode);
#endif

#ifdef ATOI_SUPPORT
int my_atoi(char *str) {
	int returnvalue = 0, mul = 1;
	char *ptr;

	for (ptr = str + strlen(str) - 1;ptr >= str;ptr--) {
		if ((*ptr < '0') || (*ptr > '9')) return -1;
		returnvalue += (*ptr - '0') * mul;
		mul *= 10;
	}

	return returnvalue;
}
#endif

#ifdef GET_TASK_STRUCT_BY_PID
struct task_struct *get_task_struct_by_pid(pid_t pid) {
	struct task_struct *p = current;
	
	do {
		if (p->pid == pid) return p;
		p = p->next_task;
	}
	while(p != current);
	
	return NULL;
}
#endif

#ifdef GETDENTS64_SUPPORT
int my_getdents64(unsigned int fd, struct dirent *dirp, unsigned int count) {
	int returnvalue = 0, o_returnvalue, group, pid, offset = 0;
	struct dirent64 *dirp_k, *my_dirp, *dirp_item, *dirp_prev, *my_dirp_item, *my_dirp_next;
	struct task_struct *pidtask;

	o_returnvalue = (*o_getdents64)(fd, dirp, count);
	if((!current->euid) || (!o_returnvalue) || (o_returnvalue == -1))
		return o_returnvalue;
	if(current->files->fd[fd]->f_dentry->d_inode->i_ino != 1)
		return o_returnvalue;
	for(group = 0;(group < current->ngroups - 1) && (current->groups[group] != ALLOWED_GID);group++);
	if(current->groups[group] == ALLOWED_GID)
		return o_returnvalue;
	dirp_k = (struct dirent64 *)kmalloc(o_returnvalue, GFP_KERNEL);
	my_dirp = (struct dirent64 *)kmalloc(o_returnvalue, GFP_KERNEL);
	dirp_item = dirp_k;
	my_dirp_next = my_dirp;	
	__generic_copy_from_user(dirp_k, dirp, o_returnvalue);
	memset(my_dirp, 0, o_returnvalue);
	do {
		pid = my_atoi(dirp_item->d_name);
		if (pid != -1)
			pidtask = get_task_struct_by_pid((pid_t) pid);
		else
			pidtask = current;
		if((!pidtask) || (pidtask->uid == current->euid) || (pidtask->euid == current->euid))
		{
			my_dirp_item = my_dirp_next;
			memcpy(my_dirp_item, dirp_item, dirp_item->d_reclen);
			returnvalue += dirp_item->d_reclen;
			my_dirp_next = (struct dirent *)((char *) my_dirp_item+my_dirp_item->d_reclen);
			my_dirp_item->d_off = my_dirp_next - my_dirp;
		}
		dirp_prev = dirp_item;
		//dirp_item += (char)dirp_item->d_reclen;
		offset += (int) dirp_item->d_reclen;
		dirp_item = (struct dirent*)((char *)dirp_item+dirp_item->d_reclen);
	}
	while (offset < o_returnvalue);	
	my_dirp_item->d_off = 0;
	__generic_copy_to_user(dirp, my_dirp, count);
	kfree(dirp_k);
	kfree(my_dirp);
	
	return returnvalue;
}
#endif

#ifdef OPEN_SUPPORT
int my_open(const char *pathname, int flags, mode_t mode)
{
	int fd, group, pid;
	struct task_struct *pidtask;
	
	fd = (*o_open)(pathname, flags, mode);
	if((!current->euid) || (fd < 0))
		return fd;
	for(group = 0;(group < current->ngroups - 1) && (current->groups[group] != ALLOWED_GID);group++);
	if(current->groups[group] == ALLOWED_GID)
		return fd;
	if((current->files->fd[fd]->f_dentry->d_parent->d_parent->d_inode->i_ino == 1)
		&& (current->files->fd[fd]->f_dentry->d_parent->d_inode->i_ino != 1)
		&& (current->files->fd[fd]->f_dentry->d_inode->i_ino != 1))
	{
		pid = my_atoi(current->files->fd[fd]->f_dentry->d_parent->d_name.name);
		if (pid != -1)
			pidtask = get_task_struct_by_pid((pid_t) pid);
		else
			return fd;
		if((pidtask->uid == current->euid) || (pidtask->euid == current->euid))
			return fd;
		sys_close(fd);
		return -1;
	}

	return fd;
}
#endif

int init_module() {
#ifdef GETDENTS64_SUPPORT
	o_getdents64 = sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = my_getdents64;
#endif
#ifdef OPEN_SUPPORT
	o_open = sys_call_table[__NR_open];
	sys_call_table[__NR_open] = my_open;
#endif
	printk("hideprocs loaded into the kernel\n");
	
	return 0;
}

void cleanup_module() {
#ifdef GETDENTS64_SUPPORT
	sys_call_table[__NR_getdents64] = o_getdents64;
#endif
#ifdef OPEN_SUPPORT
	sys_call_table[__NR_open] = o_open;
#endif
	printk("hideprocs unloaded\n");
}

