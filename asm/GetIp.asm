[BITS 64]

GLOBAL GetIp

[SECTION .text$C]

GetIp:
	; Exec next instruction
	call	get_ret_ptr

get_ret_ptr:
	pop	  rax
	sub	  rax, 5
	ret

Leave:
	db 'S', 'W', 'E', 'E', 'T', 'D', 'R', 'E', 'A', 'M'
