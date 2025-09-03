[BITS 64]

EXTERN SweetDreamEntry

GLOBAL GetIp
GLOBAL Start

[SECTION .text$A]

Start:
  push  rsi
  mov	  rsi, rsp
	and	  rsp, 0FFFFFFFFFFFFFFF0h

	;; Execute Ldr
	sub	  rsp, 020h
	call	SweetDreamEntry

	;; Cleanup stack
	mov	  rsp, rsi
	pop	  rsi

	ret


