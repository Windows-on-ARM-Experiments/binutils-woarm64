	.text
	.align	2
	.global	add
	.seh_proc	add
add:
	sub	sp, sp, #16
	.seh_stackalloc	16
	.seh_endprologue
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 12]
	ldr	w0, [sp, 8]
	add	w0, w1, w0
	.seh_startepilogue
	add	sp, sp, 16
	.seh_stackalloc	16
	ret
	.seh_endepilogue
	.seh_endproc
	.def	__main;	.scl	2;	.type	32;	.endef
	.align	2
	.global	main
	.seh_proc	main
main:
	sub	x10, sp, #8192
	.seh_nop
	str	xzr, [x10, 4064]
	.seh_nop
	.seh_nop
	stp	x29, x30, [sp, -32]!
	.seh_save_regp_x	x29, 32
	mov	x29, sp
	.seh_set_fp
	.seh_endprologue
	adrp	x0, .refptr.__main
	add	x0, x0, :lo12:.refptr.__main
	ldr	x0, [x0]
	blr	x0
	mov	w0, 20
	str	w0, [sp, 28]
	mov	w0, 30
	str	w0, [sp, 24]
	ldr	w1, [sp, 24]
	ldr	w0, [sp, 28]
	bl	add
	.seh_startepilogue
	ldp	x29, x30, [sp], 32
	.seh_save_regp_x	x29, 32
	ret
	.seh_endepilogue
	.seh_endproc
