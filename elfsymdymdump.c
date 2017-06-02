/* ELF .dynsym dump
 *
 * Roc Vallès Domènech
 */

#include <stdio.h>

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


int main(int argc,char *argv[])
{
	int elffd, currprogramheader=0, currsectionheader=0, currsymbyte=0, readed=0;
	unsigned int dt_pltgot, dt_rel, dt_relent, dt_relsz, dt_symtab, dt_syment;
	unsigned char *symname;
	Elf32_Ehdr *elfheader;
	Elf32_Shdr *sectionheader, *strtabheader;
	Elf32_Sym *symheader;
	elffd = open(argv[1], 0);
	elfheader = malloc(52); /* 52 = sizeof(Elf32_Ehdr) */
	read(elffd, elfheader, 52);
	printf("%d",sizeof(Elf32_Sym));
	if(!(elfheader->e_ident[0]==0x7f && elfheader->e_ident[1]=='E' && elfheader->e_ident[2]=='L' && elfheader->e_ident[3]=='F'))
		printf("This is not a ELF!\n");
	if(elfheader->e_machine!=3)
		printf("This ELF isn't for x86 %d\n",elfheader->e_machine);
	printf("e_shnum %i\n",elfheader->e_shnum);
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
			printf("%s - 0x%x\n", symname, symheader->st_value);
		}
		currsymbyte = currsymbyte+sectionheader->sh_entsize;
	}
	while((sectionheader->sh_size)+(sectionheader->sh_offset)>currsymbyte);
	
	return 0;
}
