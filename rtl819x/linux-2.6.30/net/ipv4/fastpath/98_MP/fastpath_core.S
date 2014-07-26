	.file	1 "fastpath_core.c"
	.section .mdebug.abi32
	.previous
#APP
	.macro _ssnop; sll $0, $0, 1; .endm
	.macro _ehb; sll $0, $0, 3; .endm
	.macro mtc0_tlbw_hazard; nop; nop; .endm
	.macro tlbw_use_hazard; nop; nop; nop; .endm
	.macro tlb_probe_hazard; nop; nop; nop; .endm
	.macro irq_enable_hazard; _ssnop; _ssnop; _ssnop;; .endm
	.macro irq_disable_hazard; nop; nop; nop; .endm
	.macro back_to_back_c0_hazard; _ssnop; _ssnop; _ssnop;; .endm
		.macro	raw_local_irq_enable				
	.set	push						
	.set	reorder						
	.set	noat						
	mfc0	$1,$12						
	ori	$1,0x1f						
	xori	$1,0x1e						
	mtc0	$1,$12						
	irq_enable_hazard					
	.set	pop						
	.endm
		.macro	raw_local_irq_disable
	.set	push						
	.set	noat						
	mfc0	$1,$12						
	ori	$1,0x1f						
	xori	$1,0x1f						
	.set	noreorder					
	mtc0	$1,$12						
	irq_disable_hazard					
	.set	pop						
	.endm							

		.macro	raw_local_save_flags flags			
	.set	push						
	.set	reorder						
	mfc0	\flags, $12					
	.set	pop						
	.endm							

		.macro	raw_local_irq_save result			
	.set	push						
	.set	reorder						
	.set	noat						
	mfc0	\result, $12					
	ori	$1, \result, 0x1f				
	xori	$1, 0x1f					
	.set	noreorder					
	mtc0	$1, $12						
	irq_disable_hazard					
	.set	pop						
	.endm							

		.macro	raw_local_irq_restore flags			
	.set	push						
	.set	noreorder					
	.set	noat						
	mfc0	$1, $12						
	andi	\flags, 1					
	ori	$1, 0x1f					
	xori	$1, 0x1f					
	or	\flags, $1					
	mtc0	\flags, $12					
	irq_disable_hazard					
	.set	pop						
	.endm							

#NO_APP
	.section	.exitcall.exit,"aw",@progbits
	.align	2
	.type	__exitcall_fastpath_exit, @object
	.size	__exitcall_fastpath_exit, 4
__exitcall_fastpath_exit:
	.word	fastpath_exit
	.section	.initcall6.init,"aw",@progbits
	.align	2
	.type	__initcall_fastpath_init6, @object
	.size	__initcall_fastpath_init6, 4
__initcall_fastpath_init6:
	.word	fastpath_init
	.data
	.align	2
	.type	res1, @object
	.size	res1, 4
res1:
	.word	0
	.align	2
	.type	fast_nat_fw, @object
	.size	fast_nat_fw, 4
fast_nat_fw:
	.word	1
	.section	.text.arp_req_get_ha,"ax",@progbits
	.align	2
	.globl	arp_req_get_ha
	.ent	arp_req_get_ha
	.type	arp_req_get_ha, @function
arp_req_get_ha:
	.set	nomips16
	.frame	$sp,48,$31		# vars= 8, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-48
	sw	$18,32($sp)
	move	$18,$5
	sw	$4,16($sp)
	lui	$4,%hi(arp_tbl)
	sw	$19,36($sp)
	addiu	$4,$4,%lo(arp_tbl)
	move	$19,$6
	addiu	$5,$sp,16
	move	$6,$18
	sw	$17,28($sp)
	sw	$16,24($sp)
	sw	$31,40($sp)
	.set	noreorder
	.set	nomacro
	jal	neigh_lookup
	li	$17,-6			# 0xfffffffa
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L2
	move	$16,$2
	.set	macro
	.set	reorder

	jal	local_bh_disable
	move	$4,$19
	lbu	$6,256($18)
	.set	noreorder
	.set	nomacro
	jal	memcpy
	addiu	$5,$16,36
	.set	macro
	.set	reorder

	jal	local_bh_enable
#APP
	   

	1:	ll	$3, 72($16)		# atomic_sub_return	
	subu	$2, $3, 1				
	sc	$2, 72($16)					
	beqz	$2, 2f					
	subu	$2, $3, 1				
	.subsection 2					
2:	b	1b					
	.previous					

	   

#NO_APP
	move	$17,$0
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L2
	move	$4,$16
	.set	macro
	.set	reorder

	jal	neigh_destroy
$L2:
	move	$2,$17
	lw	$31,40($sp)
	lw	$19,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,48
	.set	macro
	.set	reorder

	.end	arp_req_get_ha
	.section	.text.cache_timeout,"ax",@progbits
	.align	2
	.ent	cache_timeout
	.type	cache_timeout, @function
cache_timeout:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$2,0($4)
	beq	$2,$0,$L19
	move	$7,$4

	lw	$2,8($4)
	lw	$3,4($4)
	lhu	$4,2($4)
	xor	$3,$3,$2
	srl	$2,$3,16
	xor	$2,$2,$4
	xor	$3,$3,$2
	lbu	$4,1($7)
	srl	$2,$3,8
	lw	$6,40($7)
	xor	$2,$2,$4
	xor	$3,$3,$2
	andi	$4,$3,0x3f
	sll	$2,$4,1
	addu	$2,$2,$4
	sb	$0,0($7)
	lw	$3,44($7)
	beq	$6,$0,$L15
	sll	$5,$2,2

	j	$L16
	sw	$3,44($6)

$L15:
	lui	$2,%hi(udp_cache_table)
	lw	$2,%lo(udp_cache_table)($2)
	addu	$2,$5,$2
	sw	$3,4($2)
$L16:
	lw	$2,40($7)
	sll	$3,$4,1
	lw	$5,44($7)
	addu	$3,$3,$4
	sll	$3,$3,2
	lui	$4,%hi(udp_cache_list_free)
	sw	$2,0($5)
	lui	$2,%hi(udp_cache_table)
	lw	$2,%lo(udp_cache_table)($2)
	addiu	$4,$4,%lo(udp_cache_list_free)
	addiu	$6,$7,48
	addu	$3,$3,$2
	lw	$2,8($3)
	addiu	$2,$2,-1
	sw	$2,8($3)
	sw	$0,48($7)
	lw	$2,4($4)
	sw	$2,52($7)
	lw	$2,4($4)
	sw	$7,0($2)
	lw	$2,8($4)
	sw	$6,4($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L19:
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	cache_timeout
	.section	.text.FastPath_Hash_NAPT_Entry,"ax",@progbits
	.align	2
	.ent	FastPath_Hash_NAPT_Entry
	.type	FastPath_Hash_NAPT_Entry, @function
FastPath_Hash_NAPT_Entry:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	srl	$2,$4,16
	srl	$3,$6,16
	xor	$3,$3,$6
	xor	$2,$2,$4
	xor	$2,$2,$3
	xor	$2,$2,$5
	lhu	$3,18($sp)
	xor	$2,$2,$7
	xor	$2,$2,$3
	srl	$3,$2,12
	xor	$2,$2,$3
	j	$31
	andi	$2,$2,0x3ff

	.set	macro
	.set	reorder
	.end	FastPath_Hash_NAPT_Entry
	.section	.text.rtk_addArp,"ax",@progbits
	.align	2
	.globl	rtk_addArp
	.ent	rtk_addArp
	.type	rtk_addArp, @function
rtk_addArp:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_addArp
	.section	.text.rtk_modifyArp,"ax",@progbits
	.align	2
	.globl	rtk_modifyArp
	.ent	rtk_modifyArp
	.type	rtk_modifyArp, @function
rtk_modifyArp:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_modifyArp
	.section	.text.rtk_delArp,"ax",@progbits
	.align	2
	.globl	rtk_delArp
	.ent	rtk_delArp
	.type	rtk_delArp, @function
rtk_delArp:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	li	$2,-4			# 0xfffffffc

	.set	macro
	.set	reorder
	.end	rtk_delArp
	.section	.text.rtk_addRoute,"ax",@progbits
	.align	2
	.globl	rtk_addRoute
	.ent	rtk_addRoute
	.type	rtk_addRoute, @function
rtk_addRoute:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_addRoute
	.section	.text.rtk_modifyRoute,"ax",@progbits
	.align	2
	.globl	rtk_modifyRoute
	.ent	rtk_modifyRoute
	.type	rtk_modifyRoute, @function
rtk_modifyRoute:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_modifyRoute
	.section	.text.rtk_delRoute,"ax",@progbits
	.align	2
	.globl	rtk_delRoute
	.ent	rtk_delRoute
	.type	rtk_delRoute, @function
rtk_delRoute:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	li	$2,-4			# 0xfffffffc

	.set	macro
	.set	reorder
	.end	rtk_delRoute
	.section	.text.rtk_addSession,"ax",@progbits
	.align	2
	.globl	rtk_addSession
	.ent	rtk_addSession
	.type	rtk_addSession, @function
rtk_addSession:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_addSession
	.section	.text.rtk_delSession,"ax",@progbits
	.align	2
	.globl	rtk_delSession
	.ent	rtk_delSession
	.type	rtk_delSession, @function
rtk_delSession:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	rtk_delSession
	.section	.text.FastPath_Route,"ax",@progbits
	.align	2
	.globl	FastPath_Route
	.ent	FastPath_Route
	.type	FastPath_Route, @function
FastPath_Route:
	.set	nomips16
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(route_list_inuse)
	move	$8,$0
	lw	$3,%lo(route_list_inuse)($2)
	move	$7,$0
$L37:
	beq	$3,$0,$L36
	nop

	lw	$5,8($3)
	sltu	$2,$5,$7
	bne	$2,$0,$L32
	and	$6,$4,$5

	lw	$2,4($3)
	bne	$6,$2,$L32
	nop

	move	$7,$5
	addiu	$8,$3,16
$L32:
	lw	$3,44($3)
	j	$L37
	nop

$L36:
	j	$31
	move	$2,$8

	.set	macro
	.set	reorder
	.end	FastPath_Route
	.rdata
	.align	2
$LC0:
	.ascii	"br0\000"
	.section	.text.rtk_addNaptConnection,"ax",@progbits
	.align	2
	.globl	rtk_addNaptConnection
	.ent	rtk_addNaptConnection
	.type	rtk_addNaptConnection, @function
rtk_addNaptConnection:
	.set	nomips16
	.frame	$sp,200,$31		# vars= 136, regs= 10/0, args= 24, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-200
	andi	$2,$4,0xffff
	sw	$fp,192($sp)
	lw	$fp,220($sp)
	sw	$7,212($sp)
	lw	$7,224($sp)
	sw	$18,168($sp)
	sw	$4,200($sp)
	move	$4,$5
	sw	$5,204($sp)
	move	$5,$6
	sw	$6,208($sp)
	move	$6,$fp
	sw	$2,16($sp)
	lw	$18,228($sp)
	sw	$16,160($sp)
	sw	$31,196($sp)
	sw	$23,188($sp)
	sw	$22,184($sp)
	sw	$21,180($sp)
	sw	$20,176($sp)
	sw	$19,172($sp)
	jal	FastPath_Hash_NAPT_Entry
	sw	$17,164($sp)

	move	$16,$2
	beq	$18,$0,$L38
	li	$2,-1			# 0xffffffff

	lw	$20,152($18)
	li	$2,6			# 0x6
	sw	$2,128($sp)
	li	$6,6			# 0x6
	lw	$3,200($sp)
	move	$4,$fp
	lbu	$2,0($20)
	xori	$5,$3,0x2
	li	$3,17			# 0x11
	andi	$2,$2,0xf
	movn	$6,$3,$5		#conditional move  
	sll	$2,$2,2
	sw	$6,128($sp)
	jal	filter_addconnect
	addu	$21,$20,$2

	lui	$11,%hi(table_napt)
	sll	$6,$16,1
	lw	$3,%lo(table_napt)($11)
	addu	$2,$6,$16
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$3,0($2)
$L171:
	beq	$3,$0,$L169
	lui	$7,%hi(napt_list_free)

	lw	$2,4($3)
	lw	$8,200($sp)
	bne	$2,$8,$L46
	nop

	lw	$2,8($3)
	lw	$9,204($sp)
	bne	$2,$9,$L46
	nop

	lw	$2,12($3)
	lw	$4,208($sp)
	bne	$2,$4,$L46
	nop

	lw	$2,16($3)
	lw	$8,212($sp)
	bne	$2,$8,$L46
	nop

	lw	$2,20($3)
	lw	$9,216($sp)
	bne	$2,$9,$L46
	nop

	lw	$2,24($3)
	bne	$2,$fp,$L46
	nop

	lw	$2,28($3)
	lw	$4,224($sp)
	beq	$2,$4,$L38
	move	$2,$0

$L46:
	lw	$3,36($3)
	j	$L171
	nop

$L169:
	lw	$10,%lo(napt_list_free)($7)
	beq	$10,$0,$L38
	li	$2,-1			# 0xffffffff

	lw	$2,236($sp)
	lw	$4,44($10)
	sw	$2,32($10)
	li	$2,-1
	sb	$2,0($10)
	lw	$8,200($sp)
	sw	$8,4($10)
	lw	$9,204($sp)
	sw	$9,8($10)
	lw	$2,208($sp)
	sw	$2,12($10)
	lw	$3,212($sp)
	sw	$3,16($10)
	lw	$8,216($sp)
	sw	$fp,24($10)
	sw	$8,20($10)
	lw	$9,224($sp)
	lw	$3,48($10)
	beq	$4,$0,$L51
	sw	$9,28($10)

	j	$L52
	sw	$3,48($4)

$L51:
	addiu	$2,$7,%lo(napt_list_free)
	sw	$3,4($2)
$L52:
	lw	$3,48($10)
	addiu	$7,$7,%lo(napt_list_free)
	lw	$2,44($10)
	lui	$5,%hi(napt_list_inuse)
	addiu	$5,$5,%lo(napt_list_inuse)
	addiu	$8,$10,44
	sw	$2,0($3)
	addu	$6,$6,$16
	lw	$3,8($7)
	sll	$6,$6,2
	lw	$4,204($sp)
	addiu	$9,$10,36
	addiu	$3,$3,-1
	sw	$3,8($7)
	srl	$2,$4,8
	lw	$3,204($sp)
	srl	$4,$fp,16
	sw	$0,44($10)
	xor	$4,$4,$fp
	lw	$7,4($5)
	xor	$2,$2,$3
	xor	$2,$2,$4
	lw	$4,208($sp)
	sw	$7,48($10)
	srl	$3,$4,4
	lw	$4,224($sp)
	xor	$2,$2,$3
	lw	$3,4($5)
	xor	$2,$2,$4
	lw	$4,128($sp)
	sw	$10,0($3)
	xor	$2,$2,$4
	lw	$3,8($5)
	srl	$4,$2,12
	xor	$2,$2,$4
	andi	$2,$2,0x3ff
	addiu	$3,$3,1
	sw	$2,132($sp)
	sw	$8,4($5)
	sw	$3,8($5)
	sw	$0,36($10)
	lw	$2,%lo(table_napt)($11)
	addu	$2,$6,$2
	lw	$2,4($2)
	sw	$2,40($10)
	lw	$2,%lo(table_napt)($11)
	addu	$2,$6,$2
	lw	$2,4($2)
	sw	$10,0($2)
	lw	$2,%lo(table_napt)($11)
	addu	$2,$6,$2
	sw	$9,4($2)
	lw	$2,%lo(table_napt)($11)
	addu	$6,$6,$2
	lw	$2,8($6)
	addiu	$2,$2,1
	sw	$2,8($6)
	lui	$6,%hi(path_list_free)
	lw	$17,%lo(path_list_free)($6)
	beq	$17,$0,$L56
	move	$4,$fp

	lw	$8,200($sp)
	sw	$8,4($17)
	lw	$9,204($sp)
	sw	$9,8($17)
	lw	$2,208($sp)
	sw	$fp,16($17)
	sw	$2,12($17)
	lw	$3,224($sp)
	sw	$3,20($17)
	lw	$6,212($sp)
	sw	$6,24($17)
	lw	$8,216($sp)
	sw	$3,36($17)
	sw	$8,28($17)
	jal	FastPath_Route
	sw	$fp,32($17)

	sw	$2,44($17)
	li	$2,1
	lw	$4,8($17)
	lw	$3,24($17)
	sb	$2,2($17)
	li	$2,-1
	sb	$2,0($17)
	beq	$4,$3,$L57
	sb	$0,1($17)

	li	$2,1			# 0x1
	sb	$2,1($17)
$L57:
	lw	$3,12($17)
	lw	$2,28($17)
	beq	$3,$2,$L58
	nop

	lbu	$2,1($17)
	ori	$2,$2,0x2
	sb	$2,1($17)
$L58:
	sw	$0,48($17)
	li	$2,33
	sw	$0,52($17)
	lhu	$9,106($18)
	sb	$2,65($sp)
	li	$2,8
	sw	$9,136($sp)
	sb	$2,72($sp)
	sb	$0,64($sp)
	sb	$0,73($sp)
	lw	$2,140($18)
	lw	$3,204($sp)
	sw	$2,144($sp)
	li	$2,2048			# 0x800
	lw	$16,12($20)
	lhu	$22,0($21)
	lhu	$23,2($21)
	sw	$3,12($20)
	lw	$4,208($sp)
	lw	$19,16($20)
	sh	$4,0($21)
	sw	$fp,16($20)
	lw	$6,224($sp)
	sh	$6,2($21)
	bne	$9,$2,$L59
	sw	$0,140($18)

	lui	$2,%hi(nf_hooks+128)
	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L59
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,136($18)
	move	$5,$0
	lw	$7,24($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L59:
	lw	$2,140($18)
	sw	$2,48($17)
	sw	$fp,12($20)
	lw	$8,224($sp)
	sh	$8,0($21)
	lw	$9,204($sp)
	sw	$9,16($20)
	lw	$2,208($sp)
	sh	$2,2($21)
	li	$2,2048			# 0x800
	sw	$0,140($18)
	lw	$3,136($sp)
	bne	$3,$2,$L64
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L64
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,24($18)
	li	$5,4			# 0x4
	lw	$7,136($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L64:
	lw	$2,140($18)
	sw	$2,52($17)
	sw	$16,12($20)
	sh	$22,0($21)
	sw	$19,16($20)
	sh	$23,2($21)
	lw	$2,48($17)
	beq	$2,$0,$L176
	addiu	$16,$sp,48

	lw	$2,52($17)
	bne	$2,$0,$L69
	nop

$L176:
	move	$5,$0
	move	$4,$16
	jal	memset
	li	$6,14			# 0xe

	lui	$19,%hi(init_net)
	lui	$5,%hi($LC0)
	addiu	$4,$19,%lo(init_net)
	jal	__dev_get_by_name
	addiu	$5,$5,%lo($LC0)

	beq	$2,$0,$L69
	move	$5,$2

	lw	$4,204($sp)
	jal	arp_req_get_ha
	move	$6,$16

	bne	$2,$0,$L69
	addiu	$5,$sp,64

	lw	$4,172($18)
	li	$6,2			# 0x2
	jal	memcmp
	addiu	$4,$4,-2

	bne	$2,$0,$L72
	nop

	lw	$3,156($18)
	beq	$3,$0,$L72
	nop

	lbu	$2,12($3)
	lbu	$3,13($3)
	sll	$2,$2,8
	or	$3,$3,$2
	li	$2,2048			# 0x800
	beq	$3,$2,$L72
	nop

	lw	$2,172($18)
	addiu	$2,$2,-22
	sw	$2,156($18)
$L72:
	lw	$5,156($18)
	addiu	$4,$sp,24
	li	$6,6			# 0x6
	addiu	$23,$sp,32
	jal	memcpy
	addiu	$5,$5,6

	move	$4,$23
	lw	$5,156($18)
	jal	memcpy
	li	$6,6			# 0x6

	lw	$2,48($17)
	bne	$2,$0,$L81
	move	$5,$16

	lw	$4,156($18)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$4,6

	li	$2,2048			# 0x800
	sw	$0,140($18)
	lw	$4,136($sp)
	bne	$4,$2,$L84
	lui	$2,%hi(nf_hooks+128)

	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L84
	addiu	$2,$19,%lo(init_net)

	move	$4,$18
	lw	$6,136($18)
	move	$5,$0
	lw	$7,24($18)
	lw	$2,204($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L84:
	lw	$2,140($18)
	addiu	$5,$sp,24
	li	$6,6			# 0x6
	sw	$2,48($17)
	lw	$4,156($18)
	jal	memcpy
	addiu	$4,$4,6

$L81:
	lw	$2,52($17)
	bne	$2,$0,$L69
	addiu	$22,$sp,48

	li	$6,6			# 0x6
	lw	$4,156($18)
	jal	memcpy
	move	$5,$22

	lw	$19,28($18)
	beq	$19,$0,$L94
	nop

	lw	$3,48($19)
	beq	$3,$0,$L94
	li	$2,-20			# 0xffffffec

	beq	$3,$2,$L94
	addiu	$16,$3,22

	addiu	$4,$sp,40
	li	$6,6			# 0x6
	move	$5,$16
	jal	memcpy
	sw	$3,140($sp)

	move	$4,$16
	move	$5,$22
	jal	memcpy
	li	$6,6			# 0x6

$L94:
	sw	$0,140($18)
	li	$2,2048			# 0x800
	lw	$6,136($sp)
	bne	$6,$2,$L95
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L95
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,24($18)
	li	$5,4			# 0x4
	lw	$7,136($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L95:
	lw	$2,140($18)
	beq	$19,$0,$L100
	sw	$2,52($17)

	lw	$3,48($19)
	beq	$3,$0,$L100
	li	$2,-20			# 0xffffffec

	beq	$3,$2,$L100
	addiu	$5,$sp,40

	lw	$8,140($sp)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$8,22

$L100:
	lw	$4,156($18)
	move	$5,$23
	jal	memcpy
	li	$6,6			# 0x6

$L69:
	lw	$9,144($sp)
	li	$2,2			# 0x2
	sw	$9,140($18)
	lw	$3,200($sp)
	bne	$3,$2,$L104
	lui	$2,%hi(nf_ct_udp_timeout_stream)

	lw	$6,232($sp)
	lbu	$4,176($6)
	jal	tcp_get_timeouts_by_state
	nop

	j	$L174
	sw	$2,60($17)

$L104:
	lw	$2,%lo(nf_ct_udp_timeout_stream)($2)
	sw	$2,60($17)
$L174:
	lui	$2,%hi(jiffies)
	lw	$8,232($sp)
	lw	$3,72($17)
	sw	$8,56($17)
	lw	$2,%lo(jiffies)($2)
	lw	$4,76($17)
	beq	$3,$0,$L107
	sw	$2,40($17)

	j	$L108
	sw	$4,76($3)

$L107:
	lui	$9,%hi(path_list_free)
	addiu	$2,$9,%lo(path_list_free)
	sw	$4,4($2)
$L108:
	lw	$3,76($17)
	lui	$5,%hi(path_list_free)
	lw	$2,72($17)
	addiu	$5,$5,%lo(path_list_free)
	addiu	$7,$17,72
	lui	$6,%hi(table_path)
	sw	$2,0($3)
	lui	$3,%hi(path_list_inuse)
	lw	$2,8($5)
	addiu	$3,$3,%lo(path_list_inuse)
	lw	$8,132($sp)
	addiu	$2,$2,-1
	sw	$2,8($5)
	sll	$4,$8,1
	lw	$9,132($sp)
	addiu	$8,$17,64
	sw	$0,72($17)
	lw	$2,4($3)
	addu	$4,$4,$9
	sll	$4,$4,2
	sw	$2,76($17)
	lw	$2,4($3)
	sw	$17,0($2)
	lw	$2,8($3)
	sw	$7,4($3)
	addiu	$2,$2,1
	sw	$2,8($3)
	sw	$0,64($17)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	lw	$2,4($2)
	sw	$2,68($17)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	lw	$2,4($2)
	sw	$17,0($2)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	sw	$8,4($2)
	lw	$2,%lo(table_path)($6)
	addu	$4,$4,$2
	lw	$2,8($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L56:
	lw	$4,212($sp)
	srl	$2,$fp,8
	lw	$6,224($sp)
	xor	$2,$2,$fp
	srl	$3,$4,16
	xor	$3,$3,$4
	lui	$4,%hi(path_list_free)
	xor	$2,$2,$3
	srl	$3,$6,4
	lw	$8,216($sp)
	xor	$2,$2,$3
	lw	$9,128($sp)
	xor	$2,$2,$8
	xor	$2,$2,$9
	srl	$3,$2,12
	xor	$2,$2,$3
	lw	$17,%lo(path_list_free)($4)
	andi	$2,$2,0x3ff
	beq	$17,$0,$L167
	sw	$2,132($sp)

	lw	$6,212($sp)
	sw	$6,16($17)
	lw	$4,204($sp)
	sw	$8,20($17)
	lw	$8,200($sp)
	sw	$fp,8($17)
	sw	$8,4($17)
	lw	$9,224($sp)
	sw	$fp,24($17)
	sw	$9,12($17)
	sw	$9,28($17)
	lw	$2,204($sp)
	sw	$2,32($17)
	lw	$3,208($sp)
	jal	FastPath_Route
	sw	$3,36($17)

	sw	$2,44($17)
	li	$2,2
	lw	$4,16($17)
	lw	$3,32($17)
	sb	$2,2($17)
	li	$2,-1
	sb	$2,0($17)
	beq	$4,$3,$L113
	sb	$0,1($17)

	li	$2,4			# 0x4
	sb	$2,1($17)
$L113:
	lw	$3,20($17)
	lw	$2,36($17)
	beq	$3,$2,$L114
	nop

	lbu	$2,1($17)
	ori	$2,$2,0x8
	sb	$2,1($17)
$L114:
	sw	$0,48($17)
	li	$2,33
	sw	$0,52($17)
	lhu	$4,106($18)
	sb	$2,73($sp)
	li	$2,8
	sb	$2,120($sp)
	sw	$4,148($sp)
	sb	$0,72($sp)
	sb	$0,121($sp)
	lw	$6,140($18)
	lw	$8,204($sp)
	sw	$6,156($sp)
	lw	$16,12($20)
	lhu	$22,0($21)
	lhu	$23,2($21)
	sw	$8,12($20)
	lw	$9,208($sp)
	lw	$19,16($20)
	sh	$9,0($21)
	sw	$fp,16($20)
	lw	$2,224($sp)
	sh	$2,2($21)
	li	$2,2048			# 0x800
	bne	$4,$2,$L115
	sw	$0,140($18)

	lui	$2,%hi(nf_hooks+128)
	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L115
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,136($18)
	move	$5,$0
	lw	$7,24($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L115:
	lw	$2,140($18)
	sw	$2,48($17)
	li	$2,2048			# 0x800
	sw	$fp,12($20)
	lw	$3,224($sp)
	sh	$3,0($21)
	lw	$4,204($sp)
	sw	$4,16($20)
	lw	$6,208($sp)
	sh	$6,2($21)
	sw	$0,140($18)
	lw	$8,148($sp)
	bne	$8,$2,$L120
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L120
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,24($18)
	li	$5,4			# 0x4
	lw	$7,136($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L120:
	lw	$2,140($18)
	sw	$2,52($17)
	sw	$16,12($20)
	sh	$22,0($21)
	sw	$19,16($20)
	sh	$23,2($21)
	lw	$2,48($17)
	beq	$2,$0,$L177
	addiu	$16,$sp,104

	lw	$2,52($17)
	bne	$2,$0,$L125
	nop

$L177:
	move	$5,$0
	move	$4,$16
	jal	memset
	li	$6,14			# 0xe

	lui	$20,%hi(init_net)
	lui	$5,%hi($LC0)
	addiu	$4,$20,%lo(init_net)
	jal	__dev_get_by_name
	addiu	$5,$5,%lo($LC0)

	beq	$2,$0,$L125
	move	$5,$2

	lw	$4,204($sp)
	jal	arp_req_get_ha
	move	$6,$16

	bne	$2,$0,$L125
	addiu	$5,$sp,72

	lw	$4,172($18)
	li	$6,2			# 0x2
	jal	memcmp
	addiu	$4,$4,-2

	bne	$2,$0,$L128
	nop

	lw	$3,156($18)
	beq	$3,$0,$L128
	nop

	lbu	$2,12($3)
	lbu	$3,13($3)
	sll	$2,$2,8
	or	$3,$3,$2
	li	$2,2048			# 0x800
	beq	$3,$2,$L128
	nop

	lw	$2,172($18)
	addiu	$2,$2,-22
	sw	$2,156($18)
$L128:
	lw	$5,156($18)
	addiu	$19,$sp,80
	move	$4,$19
	li	$6,6			# 0x6
	addiu	$5,$5,6
	jal	memcpy
	addiu	$21,$sp,88

	move	$4,$21
	lw	$5,156($18)
	jal	memcpy
	li	$6,6			# 0x6

	lw	$2,48($17)
	bne	$2,$0,$L137
	move	$5,$16

	lw	$4,156($18)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$4,6

	li	$2,2048			# 0x800
	sw	$0,140($18)
	lw	$9,148($sp)
	bne	$9,$2,$L140
	lui	$2,%hi(nf_hooks+128)

	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L140
	addiu	$2,$20,%lo(init_net)

	move	$4,$18
	lw	$6,136($18)
	move	$5,$0
	lw	$7,24($18)
	lw	$2,204($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L140:
	lw	$2,140($18)
	move	$5,$19
	li	$6,6			# 0x6
	sw	$2,48($17)
	lw	$4,156($18)
	jal	memcpy
	addiu	$4,$4,6

$L137:
	lw	$2,52($17)
	bne	$2,$0,$L125
	addiu	$20,$sp,104

	li	$6,6			# 0x6
	lw	$4,156($18)
	jal	memcpy
	move	$5,$20

	lw	$19,28($18)
	beq	$19,$0,$L150
	nop

	lw	$3,48($19)
	beq	$3,$0,$L150
	li	$2,-20			# 0xffffffec

	beq	$3,$2,$L150
	addiu	$16,$3,22

	addiu	$4,$sp,96
	li	$6,6			# 0x6
	move	$5,$16
	jal	memcpy
	sw	$3,152($sp)

	move	$4,$16
	move	$5,$20
	jal	memcpy
	li	$6,6			# 0x6

$L150:
	sw	$0,140($18)
	li	$2,2048			# 0x800
	lw	$3,148($sp)
	bne	$3,$2,$L151
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L151
	lui	$2,%hi(init_net+204)

	move	$4,$18
	lw	$6,24($18)
	li	$5,4			# 0x4
	lw	$7,136($18)
	lw	$2,%lo(init_net+204)($2)
	jal	ipt_do_table
	sw	$2,16($sp)

$L151:
	lw	$2,140($18)
	beq	$19,$0,$L156
	sw	$2,52($17)

	lw	$3,48($19)
	beq	$3,$0,$L156
	li	$2,-20			# 0xffffffec

	beq	$3,$2,$L156
	addiu	$5,$sp,96

	lw	$6,152($sp)
	addiu	$4,$6,22
	jal	memcpy
	li	$6,6			# 0x6

$L156:
	lw	$4,156($18)
	move	$5,$21
	jal	memcpy
	li	$6,6			# 0x6

$L125:
	lw	$8,156($sp)
	li	$2,2			# 0x2
	sw	$8,140($18)
	lw	$9,200($sp)
	bne	$9,$2,$L160
	lui	$2,%hi(nf_ct_udp_timeout_stream)

	lw	$2,232($sp)
	lbu	$4,176($2)
	jal	tcp_get_timeouts_by_state
	nop

	j	$L175
	sw	$2,60($17)

$L160:
	lw	$2,%lo(nf_ct_udp_timeout_stream)($2)
	sw	$2,60($17)
$L175:
	lui	$2,%hi(jiffies)
	lw	$3,232($sp)
	lw	$4,76($17)
	sw	$3,56($17)
	lw	$2,%lo(jiffies)($2)
	lw	$3,72($17)
	beq	$3,$0,$L163
	sw	$2,40($17)

	j	$L164
	sw	$4,76($3)

$L163:
	lui	$6,%hi(path_list_free)
	addiu	$2,$6,%lo(path_list_free)
	sw	$4,4($2)
$L164:
	lw	$3,76($17)
	lui	$5,%hi(path_list_free)
	lw	$2,72($17)
	addiu	$5,$5,%lo(path_list_free)
	addiu	$7,$17,72
	lui	$6,%hi(table_path)
	sw	$2,0($3)
	lui	$3,%hi(path_list_inuse)
	lw	$2,8($5)
	addiu	$3,$3,%lo(path_list_inuse)
	lw	$8,132($sp)
	addiu	$2,$2,-1
	sw	$2,8($5)
	sll	$4,$8,1
	lw	$9,132($sp)
	addiu	$8,$17,64
	sw	$0,72($17)
	lw	$2,4($3)
	addu	$4,$4,$9
	sll	$4,$4,2
	sw	$2,76($17)
	lw	$2,4($3)
	sw	$17,0($2)
	lw	$2,8($3)
	sw	$7,4($3)
	addiu	$2,$2,1
	sw	$2,8($3)
	sw	$0,64($17)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	lw	$2,4($2)
	sw	$2,68($17)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	lw	$2,4($2)
	sw	$17,0($2)
	lw	$2,%lo(table_path)($6)
	addu	$2,$4,$2
	sw	$8,4($2)
	lw	$2,%lo(table_path)($6)
	addu	$4,$4,$2
	lw	$2,8($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L167:
	move	$2,$0
$L38:
	lw	$31,196($sp)
	lw	$fp,192($sp)
	lw	$23,188($sp)
	lw	$22,184($sp)
	lw	$21,180($sp)
	lw	$20,176($sp)
	lw	$19,172($sp)
	lw	$18,168($sp)
	lw	$17,164($sp)
	lw	$16,160($sp)
	j	$31
	addiu	$sp,$sp,200

	.set	macro
	.set	reorder
	.end	rtk_addNaptConnection
	.section	.text.rtk_delNaptConnection,"ax",@progbits
	.align	2
	.globl	rtk_delNaptConnection
	.ent	rtk_delNaptConnection
	.type	rtk_delNaptConnection, @function
rtk_delNaptConnection:
	.set	nomips16
	.frame	$sp,64,$31		# vars= 0, regs= 10/0, args= 24, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-64
	andi	$2,$4,0xffff
	sw	$18,32($sp)
	sw	$17,28($sp)
	lw	$18,88($sp)
	lw	$17,84($sp)
	sw	$23,52($sp)
	move	$23,$4
	sw	$22,48($sp)
	move	$4,$5
	sw	$21,44($sp)
	move	$22,$6
	sw	$19,36($sp)
	move	$21,$7
	move	$19,$5
	move	$7,$18
	move	$5,$6
	move	$6,$17
	sw	$2,16($sp)
	sw	$31,60($sp)
	sw	$fp,56($sp)
	sw	$20,40($sp)
	li	$20,6			# 0x6
	jal	FastPath_Hash_NAPT_Entry
	sw	$16,24($sp)

	xori	$3,$23,0x2
	move	$16,$2
	move	$4,$17
	li	$2,17			# 0x11
	lw	$fp,80($sp)
	jal	filter_delconnect
	movn	$20,$2,$3		#conditional move  

	lui	$10,%hi(table_napt)
	sll	$2,$16,1
	addu	$2,$2,$16
	lw	$3,%lo(table_napt)($10)
	sll	$2,$2,2
	addu	$3,$2,$3
	lw	$6,0($3)
	beq	$6,$0,$L220
	lui	$3,%hi(napt_list_inuse)

	move	$4,$2
	addiu	$7,$3,%lo(napt_list_inuse)
	srl	$2,$17,16
	lui	$3,%hi(napt_list_free)
	xor	$9,$2,$17
	addiu	$8,$3,%lo(napt_list_free)
	move	$5,$4
	lui	$11,%hi(path_list_inuse)
	lui	$12,%hi(path_list_free)
$L218:
	lw	$2,4($6)
	bne	$2,$23,$L183
	nop

	lw	$2,8($6)
	bne	$2,$19,$L183
	nop

	lw	$2,12($6)
	bne	$2,$22,$L183
	nop

	lw	$2,16($6)
	bne	$2,$21,$L183
	nop

	lw	$2,20($6)
	bne	$2,$fp,$L183
	nop

	lw	$2,24($6)
	bne	$2,$17,$L183
	nop

	lw	$2,28($6)
	bne	$2,$18,$L183
	nop

	lw	$2,36($6)
	sb	$0,0($6)
	lw	$3,40($6)
	beq	$2,$0,$L186
	nop

	j	$L187
	sw	$3,40($2)

$L186:
	lw	$2,%lo(table_napt)($10)
	addu	$2,$4,$2
	sw	$3,4($2)
$L187:
	lw	$3,40($6)
	lw	$2,36($6)
	sw	$2,0($3)
	lui	$2,%hi(table_napt)
	lw	$3,%lo(table_napt)($2)
	addu	$3,$5,$3
	lw	$2,8($3)
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$2,44($6)
	lw	$3,48($6)
	beq	$2,$0,$L189
	nop

	j	$L190
	sw	$3,48($2)

$L189:
	sw	$3,4($7)
$L190:
	srl	$2,$19,8
	srl	$3,$22,4
	lw	$5,48($6)
	xor	$2,$2,$19
	lw	$4,44($6)
	xor	$2,$2,$9
	xor	$2,$2,$3
	lui	$9,%hi(table_path)
	sw	$4,0($5)
	xor	$2,$2,$18
	lw	$3,8($7)
	xor	$2,$2,$20
	srl	$4,$2,12
	addiu	$3,$3,-1
	xor	$2,$2,$4
	sw	$3,8($7)
	andi	$4,$2,0x3ff
	sw	$0,44($6)
	sll	$2,$4,1
	lw	$3,4($8)
	addu	$2,$2,$4
	sll	$7,$2,2
	addiu	$4,$6,44
	sw	$3,48($6)
	lw	$2,4($8)
	sw	$6,0($2)
	lw	$2,8($8)
	lw	$3,%lo(table_path)($9)
	addiu	$2,$2,1
	sw	$2,8($8)
	addu	$3,$7,$3
	sw	$4,4($8)
	lw	$5,0($3)
	beq	$5,$0,$L194
	move	$3,$7

	addiu	$6,$12,%lo(path_list_free)
	addiu	$7,$11,%lo(path_list_inuse)
	move	$8,$3
	li	$4,1			# 0x1
	move	$10,$9
$L204:
	lw	$2,4($5)
	bne	$2,$23,$L195
	nop

	lbu	$2,2($5)
	bne	$2,$4,$L195
	nop

	lw	$2,8($5)
	bne	$2,$19,$L195
	nop

	lw	$2,12($5)
	bne	$2,$22,$L195
	nop

	lw	$2,24($5)
	bne	$2,$21,$L195
	nop

	lw	$2,28($5)
	bne	$2,$fp,$L195
	nop

	lw	$2,16($5)
	bne	$2,$17,$L195
	nop

	lw	$2,20($5)
	bne	$2,$18,$L195
	nop

	lw	$2,64($5)
	sb	$0,0($5)
	lw	$4,68($5)
	beq	$2,$0,$L198
	nop

	j	$L199
	sw	$4,68($2)

$L198:
	lw	$2,%lo(table_path)($9)
	addu	$2,$3,$2
	sw	$4,4($2)
$L199:
	lw	$3,68($5)
	lw	$2,64($5)
	sw	$2,0($3)
	lw	$3,%lo(table_path)($10)
	addu	$3,$8,$3
	lw	$2,8($3)
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$3,72($5)
	lw	$2,76($5)
	beq	$3,$0,$L201
	nop

	j	$L202
	sw	$2,76($3)

$L201:
	sw	$2,4($7)
$L202:
	lw	$2,72($5)
	addiu	$4,$5,72
	lw	$3,76($5)
	sw	$2,0($3)
	lw	$2,8($7)
	addiu	$2,$2,-1
	sw	$2,8($7)
	sw	$0,72($5)
	lw	$2,4($6)
	sw	$2,76($5)
	lw	$2,4($6)
	sw	$5,0($2)
	lw	$2,8($6)
	sw	$4,4($6)
	addiu	$2,$2,1
	j	$L194
	sw	$2,8($6)

$L195:
	lw	$5,64($5)
	bne	$5,$0,$L204
	nop

$L194:
	srl	$2,$17,8
	srl	$3,$21,16
	xor	$3,$3,$21
	xor	$2,$2,$17
	xor	$2,$2,$3
	srl	$3,$18,4
	xor	$2,$2,$3
	lui	$7,%hi(table_path)
	xor	$2,$2,$fp
	xor	$2,$2,$20
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$4,$2,0x3ff
	sll	$2,$4,1
	addu	$2,$2,$4
	lw	$3,%lo(table_path)($7)
	sll	$2,$2,2
	addu	$3,$2,$3
	lw	$5,0($3)
	beq	$5,$0,$L207
	nop

	move	$3,$2
	addiu	$8,$11,%lo(path_list_inuse)
	addiu	$6,$12,%lo(path_list_free)
	move	$9,$2
	li	$4,2			# 0x2
	move	$10,$7
$L217:
	lw	$2,4($5)
	bne	$2,$23,$L208
	nop

	lbu	$2,2($5)
	bne	$2,$4,$L208
	nop

	lw	$2,16($5)
	bne	$2,$21,$L208
	nop

	lw	$2,20($5)
	bne	$2,$fp,$L208
	nop

	lw	$2,24($5)
	bne	$2,$17,$L208
	nop

	lw	$2,28($5)
	bne	$2,$18,$L208
	nop

	lw	$2,32($5)
	bne	$2,$19,$L208
	nop

	lw	$2,36($5)
	bne	$2,$22,$L208
	nop

	lw	$2,64($5)
	sb	$0,0($5)
	lw	$4,68($5)
	beq	$2,$0,$L211
	nop

	j	$L212
	sw	$4,68($2)

$L211:
	lw	$2,%lo(table_path)($7)
	addu	$2,$3,$2
	sw	$4,4($2)
$L212:
	lw	$3,68($5)
	lw	$2,64($5)
	sw	$2,0($3)
	lw	$3,%lo(table_path)($10)
	addu	$3,$9,$3
	lw	$2,8($3)
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$3,72($5)
	lw	$2,76($5)
	beq	$3,$0,$L214
	nop

	j	$L215
	sw	$2,76($3)

$L214:
	sw	$2,4($8)
$L215:
	lw	$2,72($5)
	addiu	$4,$5,72
	lw	$3,76($5)
	sw	$2,0($3)
	lw	$2,8($8)
	addiu	$2,$2,-1
	sw	$2,8($8)
	sw	$0,72($5)
	lw	$2,4($6)
	sw	$2,76($5)
	lw	$2,4($6)
	sw	$5,0($2)
	lw	$2,8($6)
	sw	$4,4($6)
	addiu	$2,$2,1
	j	$L207
	sw	$2,8($6)

$L208:
	lw	$5,64($5)
	bne	$5,$0,$L217
	nop

$L207:
	j	$L178
	move	$2,$0

$L183:
	lw	$6,36($6)
	bne	$6,$0,$L218
	nop

$L220:
	li	$2,-4			# 0xfffffffc
$L178:
	lw	$31,60($sp)
	lw	$fp,56($sp)
	lw	$23,52($sp)
	lw	$22,48($sp)
	lw	$21,44($sp)
	lw	$20,40($sp)
	lw	$19,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	j	$31
	addiu	$sp,$sp,64

	.set	macro
	.set	reorder
	.end	rtk_delNaptConnection
	.section	.text.rtk_idleNaptConnection,"ax",@progbits
	.align	2
	.globl	rtk_idleNaptConnection
	.ent	rtk_idleNaptConnection
	.type	rtk_idleNaptConnection, @function
rtk_idleNaptConnection:
	.set	nomips16
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	srl	$2,$5,8
	lw	$9,52($sp)
	xor	$2,$2,$5
	lw	$10,56($sp)
	move	$11,$4
	srl	$3,$9,16
	xori	$4,$4,0x2
	xor	$3,$3,$9
	li	$8,6			# 0x6
	xor	$2,$2,$3
	srl	$3,$6,4
	xor	$2,$2,$3
	li	$3,17			# 0x11
	movn	$8,$3,$4		#conditional move  
	xor	$2,$2,$10
	xor	$2,$2,$8
	lui	$13,%hi(table_path)
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$3,$2,0x3ff
	sll	$2,$3,1
	addu	$2,$2,$3
	lui	$3,%hi(jiffies)
	lw	$4,%lo(table_path)($13)
	sll	$2,$2,2
	sw	$18,24($sp)
	sw	$31,28($sp)
	addu	$2,$2,$4
	sw	$17,20($sp)
	sw	$16,16($sp)
	lw	$12,%lo(jiffies)($3)
	lw	$16,0($2)
	lw	$4,48($sp)
	lw	$18,60($sp)
$L253:
	beq	$16,$0,$L256
	srl	$2,$9,8

	lw	$2,4($16)
	bne	$2,$11,$L229
	li	$2,1			# 0x1

	lbu	$3,2($16)
	bne	$3,$2,$L229
	nop

	lw	$2,8($16)
	bne	$2,$5,$L229
	nop

	lw	$2,12($16)
	bne	$2,$6,$L229
	nop

	lw	$2,24($16)
	bne	$2,$7,$L229
	nop

	lw	$2,28($16)
	bne	$2,$4,$L229
	nop

	lw	$2,16($16)
	bne	$2,$9,$L229
	nop

	lw	$2,20($16)
	bne	$2,$10,$L229
	subu	$2,$12,$18

	lw	$17,40($16)
	subu	$2,$2,$17
	bgez	$2,$L228
	nop

	j	$L255
	nop

$L229:
	lw	$16,64($16)
	j	$L253
	nop

$L228:
	srl	$2,$9,8
$L256:
	srl	$3,$7,16
	xor	$3,$3,$7
	xor	$2,$2,$9
	xor	$2,$2,$3
	srl	$3,$10,4
	xor	$2,$2,$3
	xor	$2,$2,$4
	xor	$2,$2,$8
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$3,$2,0x3ff
	sll	$2,$3,1
	addu	$2,$2,$3
	lw	$3,%lo(table_path)($13)
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$16,0($2)
$L254:
	beq	$16,$0,$L223
	move	$2,$0

	lw	$2,4($16)
	bne	$2,$11,$L241
	li	$2,2			# 0x2

	lbu	$3,2($16)
	bne	$3,$2,$L241
	nop

	lw	$2,16($16)
	bne	$2,$7,$L241
	nop

	lw	$2,20($16)
	bne	$2,$4,$L241
	nop

	lw	$2,24($16)
	bne	$2,$9,$L241
	nop

	lw	$2,28($16)
	bne	$2,$10,$L241
	nop

	lw	$2,32($16)
	bne	$2,$5,$L241
	nop

	lw	$2,36($16)
	bne	$2,$6,$L241
	subu	$2,$12,$18

	lw	$17,40($16)
	subu	$2,$2,$17
	bgez	$2,$L240
	nop

$L255:
	jal	local_bh_disable
	nop

	addu	$2,$17,$18
	lw	$3,56($16)
	sw	$2,116($3)
	lw	$4,56($16)
	jal	add_timer
	addiu	$4,$4,108

	jal	local_bh_enable
	nop

	j	$L223
	li	$2,-1			# 0xffffffff

$L241:
	lw	$16,64($16)
	j	$L254
	nop

$L240:
	move	$2,$0
$L223:
	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	rtk_idleNaptConnection
	.rdata
	.align	2
$LC1:
	.ascii	"lo\000"
	.align	2
$LC2:
	.ascii	"ppp0\000"
	.section	.text.FastPath_Enter,"ax",@progbits
	.align	2
	.globl	FastPath_Enter
	.ent	FastPath_Enter
	.type	FastPath_Enter, @function
FastPath_Enter:
	.set	nomips16
	.frame	$sp,88,$31		# vars= 24, regs= 10/0, args= 24, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-88
	sw	$17,52($sp)
	move	$17,$4
	sw	$16,48($sp)
	sw	$31,84($sp)
	sw	$fp,80($sp)
	sw	$23,76($sp)
	sw	$22,72($sp)
	sw	$21,68($sp)
	sw	$20,64($sp)
	sw	$19,60($sp)
	sw	$18,56($sp)
	lw	$2,0($4)
	sw	$2,24($sp)
	lw	$3,172($2)
	sw	$3,148($2)
	lw	$3,24($sp)
	lw	$2,172($3)
	sw	$2,152($3)
	lw	$4,24($sp)
	jal	filter_enter
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L258
	move	$16,$2
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	.set	noreorder
	.set	nomacro
	jal	kfree_skb
	li	$16,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L494
	move	$2,$16
	.set	macro
	.set	reorder

$L258:
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$16,$2,$L259
	move	$16,$0
	.set	macro
	.set	reorder

	lui	$2,%hi(fast_nat_fw)
	lw	$2,%lo(fast_nat_fw)($2)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L259
	lui	$3,%hi(fast_pptp_fw)
	.set	macro
	.set	reorder

	lw	$2,%lo(fast_pptp_fw)($3)
	beq	$2,$0,$L262
	lw	$4,24($sp)
	.set	noreorder
	.set	nomacro
	jal	fast_pptp_filter
	li	$16,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	fast_pptp_to_lan
	addiu	$4,$sp,24
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bltz	$2,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$2,24($sp)
	sw	$2,0($17)
$L262:
	lui	$4,%hi(fast_l2tp_fw)
	lw	$2,%lo(fast_l2tp_fw)($4)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L496
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	jal	fast_l2tp_rx
	li	$2,1			# 0x1
$L496:
	lw	$19,24($sp)
	sw	$2,28($sp)
	li	$2,6			# 0x6
	sw	$0,32($sp)
	lw	$18,152($19)
	sw	$0,36($sp)
	lbu	$21,9($18)
	.set	noreorder
	.set	nomacro
	beq	$21,$2,$L267
	move	$fp,$0
	.set	macro
	.set	reorder

	li	$2,17			# 0x11
	.set	noreorder
	.set	nomacro
	bne	$21,$2,$L268
	move	$5,$0
	.set	macro
	.set	reorder

$L267:
	lui	$3,%hi(fast_l2tp_fw)
	lw	$2,%lo(fast_l2tp_fw)($3)
	beq	$2,$0,$L269
	lw	$5,24($19)
	lw	$3,292($5)
	bne	$3,$0,$L269
	lui	$4,%hi(init_net)
	.set	noreorder
	.set	nomacro
	jal	__dev_get_by_name
	addiu	$4,$4,%lo(init_net)
	.set	macro
	.set	reorder

	beq	$2,$0,$L269
	lw	$3,292($2)
	beq	$3,$0,$L269
	lw	$2,24($19)
	sw	$3,292($2)
$L269:
	lbu	$2,0($18)
	lw	$22,12($18)
	andi	$2,$2,0xf
	sll	$2,$2,2
	addu	$23,$18,$2
	li	$2,6			# 0x6
	lw	$20,16($18)
	lhu	$11,0($23)
	lhu	$10,2($23)
	.set	noreorder
	.set	nomacro
	beq	$21,$2,$L274
	li	$2,17			# 0x11
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$21,$2,$L303
	move	$5,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L499
	lui	$3,%hi(fast_pptp_fw)
	.set	macro
	.set	reorder

$L274:
	lui	$4,%hi($LC1)
	lw	$2,24($19)
	addiu	$3,$4,%lo($LC1)
#APP
	.set	noreorder
	.set	noat
	lbu	$4,($2)
1:	lbu	$1,($3)
	addiu	$2,1
	bne	$1,$4,2f
	addiu	$3,1
	bnez	$4,1b
	lbu	$4,($2)
	move	$4,$1
2:	subu	$4,$1
3:	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L268
	move	$5,$0
	.set	macro
	.set	reorder

	lhu	$3,6($18)
	andi	$2,$3,0x3fff
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L280
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	xori	$2,$3,0x2000
	.set	noreorder
	.set	nomacro
	j	$L280
	sltu	$4,$2,1
	.set	macro
	.set	reorder

$L474:
	lw	$5,24($4)
	lhu	$6,30($4)
	j	$L285
$L280:
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$4,$2,$L273
	li	$2,65536			# 0x10000
	.set	macro
	.set	reorder

	lw	$3,12($23)
	and	$2,$3,$2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L282
	li	$2,458752			# 0x70000
	.set	macro
	.set	reorder

	srl	$2,$22,8
	srl	$3,$20,16
	xor	$3,$3,$20
	xor	$2,$2,$22
	xor	$2,$2,$3
	srl	$3,$11,4
	xor	$2,$2,$3
	lui	$7,%hi(table_path)
	xor	$2,$2,$10
	xor	$2,$2,$21
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$3,$2,0x3ff
	sll	$2,$3,1
	addu	$2,$2,$3
	lw	$3,%lo(table_path)($7)
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$4,0($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L306
	li	$3,255			# 0xff
	.set	macro
	.set	reorder

$L290:
	lw	$2,12($4)
	bne	$2,$11,$L286
	lw	$2,20($4)
	bne	$2,$10,$L286
	lw	$2,8($4)
	bne	$2,$22,$L286
	lw	$2,16($4)
	bne	$2,$20,$L286
	lbu	$2,0($4)
	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L286
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lbu	$3,2($4)
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L474
	sb	$0,0($4)
	.set	macro
	.set	reorder

	lw	$5,32($4)
	lhu	$6,38($4)
	j	$L285
$L286:
	lw	$4,64($4)
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L290
	move	$5,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L499
	lui	$3,%hi(fast_pptp_fw)
	.set	macro
	.set	reorder

$L285:
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L306
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lbu	$3,2($4)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L293
	srl	$3,$22,16
	.set	macro
	.set	reorder

	srl	$2,$20,8
	srl	$3,$5,16
	xor	$3,$3,$5
	xor	$2,$2,$20
	xor	$2,$2,$3
	srl	$3,$10,4
	xor	$2,$2,$3
	.set	noreorder
	.set	nomacro
	j	$L479
	xor	$2,$2,$6
	.set	macro
	.set	reorder

$L293:
	srl	$2,$5,8
	xor	$3,$3,$22
	xor	$2,$2,$5
	xor	$2,$2,$3
	srl	$3,$6,4
	xor	$2,$2,$3
	xor	$2,$2,$11
$L479:
	xor	$2,$2,$21
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$3,$2,0x3ff
	sll	$2,$3,1
	addu	$2,$2,$3
	lw	$3,%lo(table_path)($7)
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$4,0($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L306
	li	$3,255			# 0xff
	.set	macro
	.set	reorder

$L301:
	lw	$2,24($4)
	bne	$2,$20,$L299
	lw	$2,28($4)
	bne	$2,$10,$L299
	lw	$2,32($4)
	bne	$2,$22,$L299
	lw	$2,36($4)
	bne	$2,$11,$L299
	lbu	$2,0($4)
	bne	$2,$3,$L299
	sb	$0,0($4)
$L299:
	lw	$4,64($4)
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L301
	move	$5,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L499
	lui	$3,%hi(fast_pptp_fw)
	.set	macro
	.set	reorder

$L282:
	and	$2,$3,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L268
	move	$5,$0
	.set	macro
	.set	reorder

	j	$L273
$L303:
	lui	$4,%hi($LC1)
	lw	$2,24($19)
	addiu	$3,$4,%lo($LC1)
#APP
	.set	noreorder
	.set	noat
	lbu	$4,($2)
1:	lbu	$1,($3)
	addiu	$2,1
	bne	$1,$4,2f
	addiu	$3,1
	bnez	$4,1b
	lbu	$4,($2)
	move	$4,$1
2:	subu	$4,$1
3:	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L268
	move	$5,$0
	.set	macro
	.set	reorder

	j	$L273
$L306:
	.set	noreorder
	.set	nomacro
	j	$L268
	move	$5,$0
	.set	macro
	.set	reorder

$L273:
	lhu	$3,6($18)
	andi	$2,$3,0x3fff
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L497
	srl	$2,$22,8
	.set	macro
	.set	reorder

	li	$2,8192			# 0x2000
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L308
	andi	$2,$3,0x2000
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$L309
	sw	$4,32($sp)
	.set	macro
	.set	reorder

$L308:
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L309
	andi	$3,$3,0x1fff
	.set	macro
	.set	reorder

	lw	$4,36($sp)
	li	$2,1			# 0x1
	movn	$4,$2,$3		#conditional move
	sw	$4,36($sp)
$L309:
	xor	$3,$22,$20
	andi	$6,$21,0x00ff
	lhu	$5,4($18)
	srl	$2,$3,16
	xor	$2,$2,$5
	xor	$3,$3,$2
	srl	$2,$3,8
	xor	$2,$2,$6
	xor	$3,$3,$2
	andi	$3,$3,0x3f
	sll	$2,$3,1
	addu	$2,$2,$3
	lui	$3,%hi(udp_cache_table)
	lw	$3,%lo(udp_cache_table)($3)
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$4,0($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L471
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L317:
	lhu	$2,2($4)
	bne	$2,$5,$L314
	lw	$2,4($4)
	bne	$2,$22,$L314
	lw	$2,8($4)
	bne	$2,$20,$L314
	lbu	$2,1($4)
	bne	$2,$6,$L314
	lbu	$2,0($4)
	beq	$2,$3,$L475
$L314:
	lw	$4,40($4)
	bne	$4,$0,$L317
$L471:
	.set	noreorder
	.set	nomacro
	j	$L318
	move	$fp,$0
	.set	macro
	.set	reorder

$L475:
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L318
	move	$fp,$4
	.set	macro
	.set	reorder

	lw	$2,32($sp)
	lhu	$11,12($4)
	lhu	$10,14($4)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L497
	srl	$2,$22,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L497
	sw	$0,28($sp)
	.set	macro
	.set	reorder

$L318:
	lw	$3,32($sp)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L268
	move	$5,$0
	.set	macro
	.set	reorder

	srl	$2,$22,8
$L497:
	srl	$3,$20,16
	xor	$3,$3,$20
	xor	$2,$2,$22
	xor	$2,$2,$3
	srl	$3,$11,4
	xor	$2,$2,$3
	xor	$2,$2,$10
	xor	$2,$2,$21
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$2,$2,0x3ff
	sll	$3,$2,1
	addu	$3,$3,$2
	lui	$2,%hi(table_path)
	lw	$2,%lo(table_path)($2)
	sll	$3,$3,2
	addu	$3,$3,$2
	lw	$16,0($3)
$L480:
	beq	$16,$0,$L473
	lw	$2,12($16)
	bne	$2,$11,$L325
	lw	$2,20($16)
	bne	$2,$10,$L325
	lw	$2,8($16)
	bne	$2,$22,$L325
	lw	$2,16($16)
	.set	noreorder
	.set	nomacro
	bne	$2,$20,$L325
	li	$2,255			# 0xff
	.set	macro
	.set	reorder

	lbu	$3,0($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L325
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	lw	$3,4($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L498
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	li	$2,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$21,$2,$L327
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

$L498:
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L325
	li	$2,17			# 0x11
	.set	macro
	.set	reorder

	bne	$21,$2,$L325
$L327:
	lw	$5,32($16)
	move	$4,$19
	lw	$6,12($18)
	lbu	$7,1($18)
	lw	$2,24($19)
	sw	$10,40($sp)
	sw	$11,44($sp)
	.set	noreorder
	.set	nomacro
	jal	ip_route_input
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$10,40($sp)
	lw	$11,44($sp)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L268
	move	$5,$0
	.set	macro
	.set	reorder

	lw	$3,28($19)
	lw	$2,48($3)
	bne	$2,$0,$L332
	lw	$2,44($3)
	beq	$2,$0,$L488
$L332:
	lw	$2,72($3)
	lw	$3,84($19)
	sltu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L488
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	lw	$3,4($16)
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L336
	addiu	$17,$23,16
	.set	macro
	.set	reorder

	lhu	$3,6($23)
	addiu	$2,$23,6
	move	$17,$0
	movn	$17,$2,$3		#conditional move  
$L336:
	lw	$4,32($sp)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L339
	xor	$2,$22,$20
	.set	macro
	.set	reorder

	andi	$7,$21,0x00ff
	lhu	$5,4($18)
	srl	$3,$2,16
	lui	$6,%hi(udp_cache_list_free)
	xor	$3,$3,$5
	xor	$2,$2,$3
	srl	$3,$2,8
	xor	$3,$3,$7
	lw	$8,%lo(udp_cache_list_free)($6)
	xor	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$8,$0,$L342
	andi	$9,$2,0x3f
	.set	macro
	.set	reorder

$L488:
	lw	$4,28($19)
	jal	dst_release
	move	$5,$0
	.set	noreorder
	.set	nomacro
	j	$L268
	sw	$0,28($19)
	.set	macro
	.set	reorder

$L342:
	lw	$4,48($8)
	li	$2,1
	sh	$5,2($8)
	sw	$22,4($8)
	sw	$20,8($8)
	sb	$7,1($8)
	sh	$11,12($8)
	sh	$10,14($8)
	sb	$2,0($8)
	lw	$3,52($8)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L345
	addiu	$2,$6,%lo(udp_cache_list_free)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L346
	sw	$3,52($4)
	.set	macro
	.set	reorder

$L345:
	sw	$3,4($2)
$L346:
	lw	$4,52($8)
	addiu	$6,$6,%lo(udp_cache_list_free)
	lw	$2,48($8)
	lui	$5,%hi(udp_cache_table)
	sll	$3,$9,1
	addiu	$7,$8,40
	sw	$2,0($4)
	addu	$3,$3,$9
	lw	$2,8($6)
	sll	$3,$3,2
	addiu	$4,$8,16
	addiu	$2,$2,-1
	sw	$2,8($6)
	sw	$0,40($8)
	lw	$2,%lo(udp_cache_table)($5)
	addu	$2,$3,$2
	lw	$2,4($2)
	sw	$2,44($8)
	lw	$2,%lo(udp_cache_table)($5)
	addu	$2,$3,$2
	lw	$2,4($2)
	sw	$8,0($2)
	lw	$2,%lo(udp_cache_table)($5)
	addu	$2,$3,$2
	sw	$7,4($2)
	lw	$2,%lo(udp_cache_table)($5)
	addu	$3,$3,$2
	lw	$2,8($3)
	addiu	$2,$2,1
	sw	$2,8($3)
	lui	$2,%hi(jiffies)
	lw	$2,%lo(jiffies)($2)
	addiu	$2,$2,1000
	.set	noreorder
	.set	nomacro
	jal	add_timer
	sw	$2,24($8)
	.set	macro
	.set	reorder

	j	$L348
$L339:
	lw	$2,36($sp)
	beq	$2,$0,$L348
	.set	noreorder
	.set	nomacro
	jal	del_timer
	addiu	$4,$fp,16
	.set	macro
	.set	reorder

	lw	$2,8($fp)
	lw	$3,4($fp)
	lhu	$4,2($fp)
	xor	$3,$3,$2
	srl	$2,$3,16
	xor	$2,$2,$4
	xor	$3,$3,$2
	lbu	$4,1($fp)
	srl	$2,$3,8
	lw	$6,40($fp)
	xor	$2,$2,$4
	xor	$3,$3,$2
	sb	$0,0($fp)
	lw	$4,44($fp)
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L352
	andi	$5,$3,0x3f
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L353
	sw	$4,44($6)
	.set	macro
	.set	reorder

$L352:
	sll	$2,$5,1
	lui	$3,%hi(udp_cache_table)
	lw	$3,%lo(udp_cache_table)($3)
	addu	$2,$2,$5
	sll	$2,$2,2
	addu	$2,$2,$3
	sw	$4,4($2)
$L353:
	lw	$4,44($fp)
	sll	$3,$5,1
	lw	$2,40($fp)
	addu	$3,$3,$5
	sll	$3,$3,2
	addiu	$5,$fp,48
	sw	$2,0($4)
	lui	$2,%hi(udp_cache_table)
	lw	$2,%lo(udp_cache_table)($2)
	lui	$4,%hi(udp_cache_list_free)
	addiu	$4,$4,%lo(udp_cache_list_free)
	addu	$3,$3,$2
	lw	$2,8($3)
	addiu	$2,$2,-1
	sw	$2,8($3)
	sw	$0,48($fp)
	lw	$2,4($4)
	sw	$2,52($fp)
	lw	$2,4($4)
	sw	$fp,0($2)
	lw	$2,8($4)
	sw	$5,4($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L348:
	lbu	$3,1($16)
	sltu	$2,$3,13
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L417
	sll	$2,$3,2
	.set	macro
	.set	reorder

	lui	$3,%hi($L440)
	addiu	$3,$3,%lo($L440)
	addu	$2,$2,$3
	lw	$2,0($2)
	j	$2
	.rdata
	.align	2
$L440:
	.word	$L357
	.word	$L359
	.word	$L374
	.word	$L374
	.word	$L388
	.word	$L417
	.word	$L417
	.word	$L417
	.word	$L403
	.word	$L417
	.word	$L417
	.word	$L417
	.word	$L403
	.section	.text.FastPath_Enter
$L359:
	lw	$5,12($18)
	lw	$3,24($16)
	srl	$2,$5,16
	andi	$4,$5,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L361
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L360
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L361:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L360:
	lw	$3,28($sp)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L378
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L364
	andi	$4,$5,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L378
	lhu	$6,0($17)
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L378
	srl	$3,$5,16
	.set	macro
	.set	reorder

	lw	$2,24($16)
	andi	$4,$5,0xffff
	addu	$4,$4,$3
	andi	$3,$2,0xffff
	subu	$4,$4,$3
	srl	$2,$2,16
	subu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L489
	addu	$4,$4,$6
	.set	macro
	.set	reorder

$L364:
	lw	$3,24($16)
	srl	$2,$5,16
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,0($17)
	subu	$4,$4,$3
	addu	$4,$4,$2
$L489:
	.set	noreorder
	.set	nomacro
	bgez	$4,$L371
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L378
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L371:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L378
	sh	$4,0($17)
	.set	macro
	.set	reorder

$L374:
	lw	$5,12($18)
	lw	$3,24($16)
	srl	$2,$5,16
	andi	$4,$5,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L376
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L375
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L376:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L375:
	lw	$4,28($sp)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L378
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	bne	$3,$2,$L379
	beq	$17,$0,$L384
	lhu	$6,0($17)
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L384
	srl	$2,$5,16
	.set	macro
	.set	reorder

	lw	$3,24($16)
	andi	$5,$5,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	lhu	$4,0($23)
	subu	$5,$5,$3
	lw	$2,28($16)
	addu	$5,$5,$4
	subu	$5,$5,$2
	addu	$5,$5,$6
	.set	noreorder
	.set	nomacro
	bgez	$5,$L382
	sra	$3,$5,16
	.set	macro
	.set	reorder

	subu	$5,$0,$5
	sra	$2,$5,16
	andi	$3,$5,0xffff
	addu	$5,$2,$3
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L482
	nor	$2,$0,$5
	.set	macro
	.set	reorder

$L382:
	andi	$2,$5,0xffff
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L384
	sh	$5,0($17)
	.set	macro
	.set	reorder

$L379:
	lw	$3,24($16)
	srl	$2,$5,16
	andi	$4,$5,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,0($23)
	subu	$4,$4,$3
	lw	$3,28($16)
	addu	$4,$4,$2
	lhu	$2,0($17)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L386
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
$L482:
	.set	noreorder
	.set	nomacro
	j	$L384
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L386:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,0($17)
$L384:
	lw	$2,28($16)
	sh	$2,0($23)
$L378:
	lw	$2,24($16)
	.set	noreorder
	.set	nomacro
	j	$L357
	sw	$2,12($18)
	.set	macro
	.set	reorder

$L388:
	lw	$5,16($18)
	lw	$3,32($16)
	srl	$2,$5,16
	andi	$4,$5,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L390
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L389
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L390:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L389:
	lw	$2,28($sp)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L486
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L393
	andi	$4,$5,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L486
	lhu	$6,0($17)
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L486
	srl	$3,$5,16
	.set	macro
	.set	reorder

	lw	$2,32($16)
	andi	$4,$5,0xffff
	addu	$4,$4,$3
	andi	$3,$2,0xffff
	subu	$4,$4,$3
	srl	$2,$2,16
	subu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L490
	addu	$4,$4,$6
	.set	macro
	.set	reorder

$L393:
	lw	$3,32($16)
	srl	$2,$5,16
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,0($17)
	subu	$4,$4,$3
	addu	$4,$4,$2
$L490:
	.set	noreorder
	.set	nomacro
	bgez	$4,$L400
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L486
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L400:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L486
	sh	$4,0($17)
	.set	macro
	.set	reorder

$L403:
	lw	$5,16($18)
	lw	$3,32($16)
	srl	$2,$5,16
	andi	$4,$5,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L405
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L404
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L405:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L404:
	lw	$3,28($sp)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L486
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L408
	andi	$4,$5,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L413
	lhu	$6,0($17)
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L413
	srl	$2,$5,16
	.set	macro
	.set	reorder

	lw	$3,32($16)
	andi	$5,$5,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	lhu	$4,2($23)
	subu	$5,$5,$3
	lw	$2,36($16)
	addu	$5,$5,$4
	subu	$5,$5,$2
	addu	$5,$5,$6
	.set	noreorder
	.set	nomacro
	bgez	$5,$L411
	sra	$3,$5,16
	.set	macro
	.set	reorder

	subu	$5,$0,$5
	sra	$2,$5,16
	andi	$3,$5,0xffff
	addu	$5,$2,$3
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L484
	nor	$2,$0,$5
	.set	macro
	.set	reorder

$L411:
	andi	$2,$5,0xffff
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L413
	sh	$5,0($17)
	.set	macro
	.set	reorder

$L408:
	lw	$3,32($16)
	srl	$2,$5,16
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,2($23)
	subu	$4,$4,$3
	lw	$3,36($16)
	addu	$4,$4,$2
	lhu	$2,0($17)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L415
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
$L484:
	.set	noreorder
	.set	nomacro
	j	$L413
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L415:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,0($17)
$L413:
	lw	$2,36($16)
	.set	noreorder
	.set	nomacro
	j	$L486
	sh	$2,2($23)
	.set	macro
	.set	reorder

$L417:
	lw	$6,12($18)
	lw	$3,24($16)
	srl	$2,$6,16
	andi	$4,$6,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L419
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
	.set	noreorder
	.set	nomacro
	j	$L418
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L419:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L418:
	lw	$2,16($18)
	lw	$3,32($16)
	srl	$4,$2,16
	andi	$5,$2,0xffff
	addu	$5,$5,$4
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	lhu	$2,10($18)
	subu	$5,$5,$3
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	bgez	$5,$L422
	andi	$2,$5,0xffff
	.set	macro
	.set	reorder

	subu	$5,$0,$5
	sra	$2,$5,16
	andi	$3,$5,0xffff
	addu	$5,$2,$3
	sra	$2,$5,16
	addu	$5,$5,$2
	nor	$2,$0,$5
	.set	noreorder
	.set	nomacro
	j	$L421
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L422:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L421:
	lw	$4,28($sp)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L424
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	bne	$3,$2,$L425
	beq	$17,$0,$L433
	lhu	$7,0($17)
	.set	noreorder
	.set	nomacro
	beq	$7,$0,$L433
	srl	$2,$6,16
	.set	macro
	.set	reorder

	lw	$3,24($16)
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	lhu	$4,0($23)
	subu	$5,$5,$3
	lw	$2,28($16)
	addu	$5,$5,$4
	subu	$5,$5,$2
	addu	$5,$5,$7
	.set	noreorder
	.set	nomacro
	bgez	$5,$L428
	sra	$3,$5,16
	.set	macro
	.set	reorder

	subu	$5,$0,$5
	sra	$2,$5,16
	andi	$3,$5,0xffff
	addu	$5,$2,$3
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L492
	nor	$2,$0,$5
	.set	macro
	.set	reorder

$L428:
	andi	$2,$5,0xffff
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L434
	sh	$5,0($17)
	.set	macro
	.set	reorder

$L425:
	lw	$3,24($16)
	srl	$2,$6,16
	andi	$4,$6,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	lhu	$2,0($23)
	subu	$4,$4,$3
	lw	$3,28($16)
	addu	$4,$4,$2
	lhu	$2,0($17)
	subu	$4,$4,$3
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	bgez	$4,$L435
	andi	$2,$4,0xffff
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	nor	$2,$0,$4
$L492:
	.set	noreorder
	.set	nomacro
	j	$L434
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L435:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,0($17)
$L434:
	lw	$2,16($18)
	lw	$3,32($16)
	srl	$4,$2,16
	andi	$5,$2,0xffff
	addu	$5,$5,$4
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	lhu	$2,2($23)
	subu	$5,$5,$3
	lw	$3,36($16)
	addu	$5,$5,$2
	lhu	$2,0($17)
	subu	$5,$5,$3
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	bgez	$5,$L438
	andi	$2,$5,0xffff
	.set	macro
	.set	reorder

	subu	$5,$0,$5
	sra	$2,$5,16
	andi	$3,$5,0xffff
	addu	$5,$2,$3
	sra	$2,$5,16
	addu	$5,$5,$2
	nor	$2,$0,$5
	.set	noreorder
	.set	nomacro
	j	$L433
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L438:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,0($17)
$L433:
	lw	$2,28($16)
	sh	$2,0($23)
	lw	$2,36($16)
	sh	$2,2($23)
$L424:
	lw	$2,24($16)
	sw	$2,12($18)
$L486:
	lw	$2,32($16)
	sw	$2,16($18)
$L357:
	lw	$3,104($19)
	li	$2,-805371904			# 0xcfff0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	lw	$2,28($19)
	sw	$3,104($19)
	lw	$2,12($2)
	sw	$2,24($19)
	li	$2,1			# 0x1
	lbu	$3,2($16)
	bne	$3,$2,$L441
	lw	$2,152($19)
	lw	$3,32($16)
	lw	$2,16($2)
	j	$L493
$L441:
	lw	$3,16($18)
	lw	$2,24($16)
$L493:
	bne	$3,$2,$L447
	lw	$2,48($16)
	.set	noreorder
	.set	nomacro
	j	$L495
	sw	$2,140($19)
	.set	macro
	.set	reorder

$L447:
	lw	$2,52($16)
	sw	$2,140($19)
$L495:
	lui	$2,%hi(jiffies)
	lw	$2,%lo(jiffies)($2)
	lui	$3,%hi(fast_l2tp_fw)
	sw	$2,40($16)
	lw	$2,%lo(fast_l2tp_fw)($3)
	beq	$2,$0,$L449
	lw	$4,24($19)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L449
	li	$6,4			# 0x4
	.set	macro
	.set	reorder

	lui	$5,%hi($LC2)
	.set	noreorder
	.set	nomacro
	jal	memcmp
	addiu	$5,$5,%lo($LC2)
	.set	macro
	.set	reorder

	bne	$2,$0,$L449
	.set	noreorder
	.set	nomacro
	jal	fast_l2tp_to_wan
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L268
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L449:
	lw	$2,28($19)
	lw	$16,48($2)
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L451
	addiu	$5,$16,20
	.set	macro
	.set	reorder

	lw	$4,172($19)
	li	$6,16			# 0x10
	.set	noreorder
	.set	nomacro
	jal	memcpy
	addiu	$4,$4,-16
	.set	macro
	.set	reorder

	lhu	$5,10($16)
	.set	noreorder
	.set	nomacro
	jal	skb_push
	move	$4,$19
	.set	macro
	.set	reorder

	lui	$4,%hi(fast_l2tp_fw)
	lw	$2,%lo(fast_l2tp_fw)($4)
	beq	$2,$0,$L452
	.set	noreorder
	.set	nomacro
	jal	l2tp_tx_id
	move	$4,$19
	.set	macro
	.set	reorder

$L452:
	lw	$4,24($19)
	lw	$2,196($4)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L461
	lui	$2,%hi(gQosEnabled)
	.set	macro
	.set	reorder

	lw	$2,%lo(gQosEnabled)($2)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L454
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	dev_queue_xmit
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L268
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L454:
	lhu	$3,202($4)
	bne	$3,$2,$L457
	lw	$5,172($19)
	.set	noreorder
	.set	nomacro
	jal	__br_fdb_get
	addiu	$4,$4,704
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L457
	move	$5,$2
	.set	macro
	.set	reorder

	lw	$3,24($19)
	lw	$2,84($3)
	addiu	$2,$2,1
	sw	$2,84($3)
	lw	$4,24($19)
	lw	$3,84($19)
	lw	$2,92($4)
	addu	$2,$2,$3
	sw	$2,92($4)
	lw	$2,8($5)
	lw	$2,4($2)
	sw	$2,24($19)
$L457:
	lw	$5,24($19)
	lw	$2,184($5)
	lw	$2,16($2)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$19
	.set	macro
	.set	reorder

	bne	$2,$0,$L461
	.set	noreorder
	.set	nomacro
	j	$L268
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L451:
	lw	$2,44($2)
	beq	$2,$0,$L461
	lw	$2,76($2)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L268
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L461:
	.set	noreorder
	.set	nomacro
	jal	kfree_skb
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L268
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L325:
	lw	$16,64($16)
	j	$L480
$L473:
	lw	$2,24($19)
	move	$5,$0
	sw	$2,136($19)
$L268:
	lui	$3,%hi(fast_pptp_fw)
$L499:
	lw	$2,%lo(fast_pptp_fw)($3)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L259
	move	$16,$5
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	lw	$2,152($4)
	lbu	$3,9($2)
	li	$2,47			# 0x2f
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$2,84($4)
	sltu	$2,$2,21
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	lui	$2,%hi(pptp_tcp_finished)
	lw	$3,%lo(pptp_tcp_finished)($2)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	jal	Check_GRE_rx_net_device
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L494
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	jal	fast_pptp_sync_rx_seq
$L259:
	move	$2,$16
$L494:
	lw	$31,84($sp)
	lw	$fp,80($sp)
	lw	$23,76($sp)
	lw	$22,72($sp)
	lw	$21,68($sp)
	lw	$20,64($sp)
	lw	$19,60($sp)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,88
	.set	macro
	.set	reorder

	.end	FastPath_Enter
	.rdata
	.align	2
$LC3:
	.ascii	"%d\n\000"
	.section	.text.read_proc,"ax",@progbits
	.align	2
	.ent	read_proc
	.type	read_proc, @function
read_proc:
	.set	nomips16
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	lui	$2,%hi(fast_nat_fw)
	sw	$19,28($sp)
	move	$19,$5
	sw	$18,24($sp)
	lui	$5,%hi($LC3)
	sw	$17,20($sp)
	addiu	$5,$5,%lo($LC3)
	sw	$16,16($sp)
	move	$17,$6
	sw	$31,32($sp)
	move	$16,$7
	lw	$2,%lo(fast_nat_fw)($2)
	move	$18,$4
	addu	$18,$18,$17
	jal	sprintf
	addiu	$6,$2,10

	move	$4,$2
	addu	$2,$17,$16
	slt	$2,$2,$4
	subu	$4,$4,$17
	slt	$3,$16,$4
	movn	$4,$16,$3		#conditional move
	bne	$2,$0,$L501
	slt	$5,$4,0

	lw	$2,56($sp)
	li	$3,1			# 0x1
	sw	$3,0($2)
$L501:
	sw	$18,0($19)
	move	$2,$0
	lw	$31,32($sp)
	movz	$2,$4,$5		#conditional move  
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	read_proc
	.rdata
	.align	2
$LC4:
	.ascii	"%d\000"
	.section	.text.write_proc,"ax",@progbits
	.align	2
	.ent	write_proc
	.type	write_proc, @function
write_proc:
	.set	nomips16
	.frame	$sp,112,$31		# vars= 80, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-112
	sltu	$2,$6,2
	sw	$18,104($sp)
	li	$3,-14			# 0xfffffff2
	sw	$31,108($sp)
	move	$18,$6
	sw	$17,100($sp)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L504
	sw	$16,96($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L504
	addiu	$2,$5,80
	.set	macro
	.set	reorder

	lw	$3,24($28)
	or	$2,$5,$2
	and	$3,$3,$2
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L506
	addiu	$7,$sp,16
	.set	macro
	.set	reorder

	move	$4,$7
	li	$6,80			# 0x50
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$6,$0,$L504
	li	$3,-14			# 0xfffffff2
	.set	macro
	.set	reorder

	lbu	$3,16($sp)
	li	$2,50			# 0x32
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L514
	lui	$5,%hi($LC4)
	.set	macro
	.set	reorder

	lui	$17,%hi(net_namespace_list)
	lw	$2,%lo(net_namespace_list)($17)
	addiu	$3,$17,%lo(net_namespace_list)
$L522:
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L519
	addiu	$16,$2,-4
	.set	macro
	.set	reorder

	move	$4,$16
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	nf_conntrack_flush
	move	$6,$0
	.set	macro
	.set	reorder

	lw	$2,4($16)
	.set	noreorder
	.set	nomacro
	j	$L522
	addiu	$3,$17,%lo(net_namespace_list)
	.set	macro
	.set	reorder

$L514:
	lui	$6,%hi(fast_nat_fw)
	move	$4,$7
	addiu	$5,$5,%lo($LC4)
	.set	noreorder
	.set	nomacro
	jal	sscanf
	addiu	$6,$6,%lo(fast_nat_fw)
	.set	macro
	.set	reorder

$L519:
	.set	noreorder
	.set	nomacro
	j	$L504
	move	$3,$18
	.set	macro
	.set	reorder

$L506:
	li	$3,-14			# 0xfffffff2
$L504:
	lw	$31,108($sp)
	move	$2,$3
	lw	$18,104($sp)
	lw	$17,100($sp)
	lw	$16,96($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,112
	.set	macro
	.set	reorder

	.end	write_proc
	.rdata
	.align	2
$LC5:
	.ascii	"fast_nat\000"
	.section	.init.text,"ax",@progbits
	.align	2
	.ent	fastpath_init
	.type	fastpath_init, @function
fastpath_init:
	.set	nomips16
	.frame	$sp,72,$31		# vars= 32, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
$L528:
$L569:
	addiu	$sp,$sp,-72
	li	$5,32			# 0x20
	sw	$19,60($sp)
	lui	$19,%hi(malloc_sizes)
	sw	$16,48($sp)
	addiu	$2,$19,%lo(malloc_sizes)
	sw	$31,64($sp)
	sw	$18,56($sp)
	sw	$17,52($sp)
	lw	$4,92($2)
	jal	kmem_cache_alloc
	lui	$16,%hi(table_napt)

	move	$6,$16
	sw	$2,%lo(table_napt)($16)
	beq	$2,$0,$L523
	li	$3,-1			# 0xffffffff

	lui	$2,%hi(napt_list_inuse)
	lui	$17,%hi(napt_list_free)
	addiu	$3,$2,%lo(napt_list_inuse)
	addiu	$4,$17,%lo(napt_list_free)
	sw	$0,%lo(napt_list_inuse)($2)
	move	$5,$0
	sw	$3,4($3)
	li	$16,1023			# 0x3ff
	sw	$4,4($4)
	sw	$0,8($3)
	sw	$0,8($4)
	sw	$0,%lo(napt_list_free)($17)
$L579:
	lw	$2,%lo(table_napt)($6)
	addiu	$16,$16,-1
	addu	$2,$5,$2
	sw	$0,8($2)
	lw	$2,%lo(table_napt)($6)
	addu	$2,$5,$2
	sw	$0,0($2)
	lw	$2,%lo(table_napt)($6)
	addu	$2,$5,$2
	addiu	$5,$5,12
	bgez	$16,$L579
	sw	$2,4($2)

	move	$16,$0
$L633:
$L587:
$L628:
	addiu	$18,$19,%lo(malloc_sizes)
	li	$5,32			# 0x20
	lw	$4,12($18)
	jal	kmem_cache_alloc
	addiu	$16,$16,1

	addiu	$4,$17,%lo(napt_list_free)
	move	$3,$2
	addiu	$5,$2,44
	beq	$2,$0,$L869
	slt	$6,$16,1024

	sw	$0,44($2)
	lw	$2,4($4)
	sw	$2,48($3)
	lw	$2,4($4)
	sw	$3,0($2)
	lw	$2,8($4)
	sw	$5,4($4)
	addiu	$2,$2,1
	bne	$6,$0,$L633
	sw	$2,8($4)

$L638:
$L679:
	lw	$4,92($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	lui	$16,%hi(table_path)

	move	$6,$16
	sw	$2,%lo(table_path)($16)
	beq	$2,$0,$L523
	li	$3,-1			# 0xffffffff

	lui	$2,%hi(path_list_inuse)
	lui	$17,%hi(path_list_free)
	addiu	$3,$2,%lo(path_list_inuse)
	addiu	$4,$17,%lo(path_list_free)
	sw	$0,%lo(path_list_inuse)($2)
	move	$5,$0
	sw	$3,4($3)
	li	$16,1023			# 0x3ff
	sw	$4,4($4)
	sw	$0,8($3)
	sw	$0,8($4)
	sw	$0,%lo(path_list_free)($17)
$L689:
	lw	$2,%lo(table_path)($6)
	addiu	$16,$16,-1
	addu	$2,$5,$2
	sw	$0,8($2)
	lw	$2,%lo(table_path)($6)
	addu	$2,$5,$2
	sw	$0,0($2)
	lw	$2,%lo(table_path)($6)
	addu	$2,$5,$2
	addiu	$5,$5,12
	bgez	$16,$L689
	sw	$2,4($2)

	move	$16,$0
$L743:
$L697:
$L738:
	addiu	$18,$19,%lo(malloc_sizes)
	li	$5,32			# 0x20
	lw	$4,20($18)
	jal	kmem_cache_alloc
	addiu	$16,$16,1

	addiu	$4,$17,%lo(path_list_free)
	move	$3,$2
	addiu	$5,$2,72
	beq	$2,$0,$L869
	slt	$6,$16,2048

	sw	$0,72($2)
	lw	$2,4($4)
	sw	$2,76($3)
	lw	$2,4($4)
	sw	$3,0($2)
	lw	$2,8($4)
	sw	$5,4($4)
	addiu	$2,$2,1
	bne	$6,$0,$L743
	sw	$2,8($4)

$L749:
$L790:
	lw	$4,60($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	lui	$16,%hi(udp_cache_table)

	move	$4,$16
	beq	$2,$0,$L871
	sw	$2,%lo(udp_cache_table)($16)

	lui	$18,%hi(udp_cache_list_free)
	move	$3,$0
	addiu	$2,$18,%lo(udp_cache_list_free)
	li	$17,63			# 0x3f
	sw	$2,4($2)
	sw	$0,8($2)
	sw	$0,%lo(udp_cache_list_free)($18)
$L800:
	lw	$2,%lo(udp_cache_table)($4)
	addiu	$17,$17,-1
	addu	$2,$3,$2
	sw	$0,8($2)
	lw	$2,%lo(udp_cache_table)($4)
	addu	$2,$3,$2
	sw	$0,0($2)
	lw	$2,%lo(udp_cache_table)($4)
	addu	$2,$3,$2
	addiu	$3,$3,12
	bgez	$17,$L800
	sw	$2,4($2)

	move	$17,$0
$L854:
$L808:
$L849:
	addiu	$2,$19,%lo(malloc_sizes)
	li	$5,32			# 0x20
	lw	$4,12($2)
	jal	kmem_cache_alloc
	addiu	$17,$17,1

	move	$5,$0
	move	$16,$2
	addiu	$4,$2,16
	beq	$2,$0,$L871
	move	$6,$0

	jal	init_timer_key
	nop

	lui	$2,%hi(cache_timeout)
	addiu	$2,$2,%lo(cache_timeout)
	addiu	$3,$18,%lo(udp_cache_list_free)
	sw	$2,28($16)
	addiu	$4,$16,48
	sw	$16,32($16)
	slt	$5,$17,64
	sw	$0,48($16)
	lw	$2,4($3)
	sw	$2,52($16)
	lw	$2,4($3)
	sw	$16,0($2)
	lw	$2,8($3)
	sw	$4,4($3)
	addiu	$2,$2,1
	bne	$5,$0,$L854
	sw	$2,8($3)

	j	$L872
	nop

$L871:
	j	$L523
	li	$3,-1			# 0xffffffff

$L869:
	j	$L523
	li	$3,-2			# 0xfffffffe

$L872:
	jal	filter_init
	nop

	jal	fast_pptp_init
	nop

	jal	fast_l2tp_init
	nop

	lui	$4,%hi($LC5)
	addiu	$4,$4,%lo($LC5)
	move	$5,$0
	jal	create_proc_entry
	move	$6,$0

	lui	$4,%hi(res1)
	move	$3,$2
	beq	$2,$0,$L855
	sw	$2,%lo(res1)($4)

	lui	$2,%hi(read_proc)
	addiu	$2,$2,%lo(read_proc)
	sw	$2,64($3)
	lui	$2,%hi(write_proc)
	lw	$3,%lo(res1)($4)
	addiu	$2,$2,%lo(write_proc)
	sw	$2,68($3)
$L855:
	move	$3,$0
$L523:
	lw	$31,64($sp)
	move	$2,$3
	lw	$19,60($sp)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	j	$31
	addiu	$sp,$sp,72

	.set	macro
	.set	reorder
	.end	fastpath_init
	.section	.exit.text,"ax",@progbits
	.align	2
	.ent	fastpath_exit
	.type	fastpath_exit, @function
fastpath_exit:
	.set	nomips16
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,20($sp)
	sw	$16,16($sp)
	jal	filter_exit
	lui	$16,%hi(res1)

	jal	fast_pptp_exit
	nop

	lui	$4,%hi($LC5)
	lw	$2,%lo(res1)($16)
	addiu	$4,$4,%lo($LC5)
	beq	$2,$0,$L873
	move	$5,$2

	jal	remove_proc_entry
	nop

	sw	$0,%lo(res1)($16)
$L873:
	lw	$31,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	fastpath_exit
	.globl	route_list_inuse
	.section	.bss
	.align	2
	.type	route_list_inuse, @object
	.size	route_list_inuse, 12
route_list_inuse:
	.space	12
	.globl	route_list_free
	.align	2
	.type	route_list_free, @object
	.size	route_list_free, 12
route_list_free:
	.space	12
	.globl	napt_list_inuse
	.align	2
	.type	napt_list_inuse, @object
	.size	napt_list_inuse, 12
napt_list_inuse:
	.space	12
	.globl	napt_list_free
	.align	2
	.type	napt_list_free, @object
	.size	napt_list_free, 12
napt_list_free:
	.space	12
	.globl	table_napt
	.align	2
	.type	table_napt, @object
	.size	table_napt, 4
table_napt:
	.space	4
	.globl	path_list_inuse
	.align	2
	.type	path_list_inuse, @object
	.size	path_list_inuse, 12
path_list_inuse:
	.space	12
	.globl	path_list_free
	.align	2
	.type	path_list_free, @object
	.size	path_list_free, 12
path_list_free:
	.space	12
	.globl	table_path
	.align	2
	.type	table_path, @object
	.size	table_path, 4
table_path:
	.space	4
	.globl	udp_cache_list_free
	.align	2
	.type	udp_cache_list_free, @object
	.size	udp_cache_list_free, 12
udp_cache_list_free:
	.space	12
	.globl	udp_cache_table
	.align	2
	.type	udp_cache_table, @object
	.size	udp_cache_table, 4
udp_cache_table:
	.space	4
	.ident	"GCC: (GNU) 3.4.6-1.3.6"
