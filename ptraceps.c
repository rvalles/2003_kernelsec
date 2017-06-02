/* ptrace() powered ps
 *
 * Set STACKEXECVEPATCH to whatever apropiate in your box.
 *
 * Roc Vallès Domènech
 */

#include <stdio.h>
#include <sys/ptrace.h>

#define STACKEXECVEPATCH	0xbffffffa
#define MAXPATHSIZE		256
#define PIDMAX			65536	

int main()
{
	int pid,pathread;
	long int *peekbuf;
	char *path;
	peekbuf=(long int *)malloc(MAXPATHSIZE);
	for(pid=0;pid<PIDMAX;pid++)
	{
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)!=-1)
		{
			for(pathread=0;pathread<MAXPATHSIZE/4;pathread++)
			{
				peekbuf[pathread]=ptrace(PTRACE_PEEKDATA, pid, 0xbfffffff-MAXPATHSIZE+(pathread*4), NULL);
			}
			ptrace(PTRACE_DETACH, pid, NULL, NULL);
			path=(char *)peekbuf+MAXPATHSIZE;
			while(*path == 0)
				path--;
			while(*path != 0)
				path--;
			path++;
			printf("%d %s\n", pid, path);	
		}	
	}
	return 0;
}
