/* Fake SU
 *
 * Roc Vallès Domènech
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/poll.h>

#define BUF 1

int main(int argc, char **argv, char **envp)
{
	int masterfd, slavefd, readed;
	char *slavefilename,*execveargv[2],*buffer;
	struct pollfd *polli, *pollo;
	
	masterfd = open ("/dev/ptmx", O_RDWR);
	slavefilename = (char *) ptsname(masterfd);
	printf("ptsname is %s\n", slavefilename);
	grantpt(masterfd);
	unlockpt(masterfd);
	slavefd = open (slavefilename, O_RDWR);
	ioctl(slavefd, I_PUSH, "ptem");
	ioctl(slavefd, I_PUSH, "ldterm");
	
	printf("slavefd = %d\n",slavefd);
	buffer = (char *)malloc(BUF);
	if (fork()==0)
	{
		close(0);
		close(1);
		close(2);
		dup(4);
		dup(4);
		dup(4);
		execveargv[0] = "/bin/bash";
		execveargv[1] = NULL;
		execve(execveargv[0],execveargv,envp);
	}
	pollo = (struct pollfd *) malloc(sizeof(struct pollfd));
	pollo->fd = masterfd;
	pollo->events = 0x0001; /* READ */
	polli = (struct pollfd *) malloc(sizeof(struct pollfd));
	polli->fd = 0;
	polli->events = 0x0001; /* READ */
	while(1)
	{
		if(poll(pollo, 1, 5)>0)
		{
			readed = read(masterfd, buffer, BUF);
			write(1, buffer, readed);
		}
		if(poll(polli, 1, 5)>0)
		{
			readed = read(1, buffer, BUF);
			write(masterfd, buffer, readed);
		}
	}
}
