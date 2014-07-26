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
	.frame	$sp,40,$31		# vars= 8, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sw	$17,28($sp)
	sw	$4,16($sp)
	move	$17,$5
	lui	$4,%hi(arp_tbl)
	sw	$18,32($sp)
	addiu	$4,$4,%lo(arp_tbl)
	move	$18,$6
	addiu	$5,$sp,16
	sw	$16,24($sp)
	sw	$31,36($sp)
	.set	noreorder
	.set	nomacro
	jal	neigh_lookup
	move	$6,$17
	.set	macro
	.set	reorder

	move	$16,$2
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L2
	li	$2,-6			# 0xfffffffffffffffa
	.set	macro
	.set	reorder

	jal	local_bh_disable
	lbu	$6,256($17)
	move	$4,$18
	.set	noreorder
	.set	nomacro
	jal	memcpy
	addiu	$5,$16,36
	.set	macro
	.set	reorder

	jal	local_bh_enable
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,72($16)
	#nop
	addiu	$2,$2,-1
	sw	$2,72($16)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L11
	move	$4,$16
	.set	macro
	.set	reorder

	jal	neigh_destroy
$L11:
	move	$2,$0
$L2:
	lw	$31,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
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
	nop
	beq	$2,$0,$L20
	move	$7,$4

	lw	$2,8($4)
	lw	$3,4($4)
	lhu	$4,2($4)
	lbu	$5,1($7)
	xor	$3,$3,$2
	srl	$2,$3,16
	xor	$2,$2,$4
	xor	$3,$3,$2
	srl	$2,$3,8
	xor	$2,$2,$5
	xor	$3,$3,$2
	andi	$4,$3,0x3f
	lw	$6,40($7)
	sll	$2,$4,1
	addu	$2,$2,$4
	sb	$0,0($7)
	lw	$3,44($7)
	beq	$6,$0,$L16
	sll	$5,$2,2

	j	$L17
	sw	$3,44($6)

$L16:
	lui	$2,%hi(udp_cache_table)
	lw	$2,%lo(udp_cache_table)($2)
	nop
	addu	$2,$5,$2
	sw	$3,4($2)
$L17:
	lw	$2,40($7)
	lw	$5,44($7)
	sll	$3,$4,1
	addu	$3,$3,$4
	sw	$2,0($5)
	lui	$2,%hi(udp_cache_table)
	lw	$2,%lo(udp_cache_table)($2)
	sll	$3,$3,2
	lui	$4,%hi(udp_cache_list_free)
	addu	$3,$3,$2
	lw	$2,8($3)
	addiu	$4,$4,%lo(udp_cache_list_free)
	addiu	$6,$7,48
	addiu	$2,$2,-1
	sw	$2,8($3)
	sw	$0,48($7)
	lw	$2,4($4)
	nop
	sw	$2,52($7)
	lw	$2,4($4)
	nop
	sw	$7,0($2)
	lw	$2,8($4)
	sw	$6,4($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L20:
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
	lhu	$3,18($sp)
	xor	$2,$2,$5
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
	li	$2,-4			# 0xfffffffffffffffc

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
	li	$2,-4			# 0xfffffffffffffffc

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
	lw	$3,%lo(route_list_inuse)($2)
	move	$8,$0
	move	$7,$0
$L38:
	beq	$3,$0,$L37
	nop

	lw	$5,8($3)
	nop
	sltu	$2,$5,$7
	bne	$2,$0,$L33
	and	$6,$4,$5

	lw	$2,4($3)
	nop
	bne	$6,$2,$L33
	nop

	move	$7,$5
	addiu	$8,$3,16
$L33:
	lw	$3,44($3)
	j	$L38
	nop

$L37:
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
	sw	$fp,192($sp)
	lw	$fp,220($sp)
	sw	$7,212($sp)
	lw	$7,224($sp)
	andi	$2,$4,0xffff
	sw	$18,168($sp)
	lw	$18,228($sp)
	sw	$4,200($sp)
	sw	$5,204($sp)
	sw	$6,208($sp)
	move	$4,$5
	sw	$2,16($sp)
	move	$5,$6
	move	$6,$fp
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
	beq	$18,$0,$L39
	li	$2,-1			# 0xffffffffffffffff

	lw	$20,156($18)
	li	$2,6			# 0x6
	sw	$2,128($sp)
	lbu	$3,0($20)
	lw	$4,200($sp)
	li	$2,17			# 0x11
	andi	$3,$3,0xf
	xori	$5,$4,0x2
	li	$6,6			# 0x6
	movn	$6,$2,$5		#RLX4181/RLX4281:conditional move  
	sll	$3,$3,2
	move	$4,$fp
	sw	$6,128($sp)
	jal	filter_addconnect
	addu	$21,$20,$3

	lui	$9,%hi(table_napt)
	lw	$3,%lo(table_napt)($9)
	sll	$6,$16,1
	addu	$2,$6,$16
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$3,0($2)
	nop
$L172:
	beq	$3,$0,$L170
	lui	$4,%hi(napt_list_free)

	lw	$2,4($3)
	lw	$7,200($sp)
	nop
	bne	$2,$7,$L47
	nop

	lw	$2,8($3)
	lw	$10,204($sp)
	nop
	bne	$2,$10,$L47
	nop

	lw	$2,12($3)
	lw	$4,208($sp)
	nop
	bne	$2,$4,$L47
	nop

	lw	$2,16($3)
	lw	$5,212($sp)
	nop
	bne	$2,$5,$L47
	nop

	lw	$2,20($3)
	lw	$7,216($sp)
	nop
	bne	$2,$7,$L47
	nop

	lw	$2,24($3)
	nop
	bne	$2,$fp,$L47
	nop

	lw	$2,28($3)
	lw	$10,224($sp)
	nop
	beq	$2,$10,$L39
	move	$2,$0

$L47:
	lw	$3,36($3)
	j	$L172
	nop

$L170:
	lw	$8,%lo(napt_list_free)($4)
	nop
	beq	$8,$0,$L39
	li	$2,-1			# 0xffffffffffffffff

	lw	$2,236($sp)
	lw	$5,44($8)
	sw	$2,32($8)
	li	$2,-1
	sb	$2,0($8)
	lw	$2,200($sp)
	nop
	sw	$2,4($8)
	lw	$3,204($sp)
	nop
	sw	$3,8($8)
	lw	$7,208($sp)
	nop
	sw	$7,12($8)
	lw	$10,212($sp)
	nop
	sw	$10,16($8)
	lw	$2,216($sp)
	sw	$fp,24($8)
	sw	$2,20($8)
	lw	$3,224($sp)
	nop
	sw	$3,28($8)
	lw	$3,48($8)
	beq	$5,$0,$L52
	addiu	$2,$4,%lo(napt_list_free)

	j	$L53
	sw	$3,48($5)

$L52:
	sw	$3,4($2)
$L53:
	lw	$3,48($8)
	lw	$2,44($8)
	addiu	$4,$4,%lo(napt_list_free)
	addiu	$5,$8,44
	sw	$2,0($3)
	lw	$2,8($4)
	lui	$3,%hi(napt_list_inuse)
	addiu	$3,$3,%lo(napt_list_inuse)
	addiu	$2,$2,-1
	sw	$2,8($4)
	sw	$0,44($8)
	lw	$2,4($3)
	addu	$6,$6,$16
	sll	$6,$6,2
	sw	$2,48($8)
	lw	$2,4($3)
	lw	$10,204($sp)
	addiu	$7,$8,36
	sw	$8,0($2)
	lw	$2,8($3)
	sw	$5,4($3)
	srl	$4,$10,8
	addiu	$2,$2,1
	sw	$2,8($3)
	sw	$0,36($8)
	lw	$2,%lo(table_napt)($9)
	srl	$5,$fp,16
	xor	$4,$4,$10
	addu	$2,$6,$2
	lw	$2,4($2)
	xor	$5,$5,$fp
	xor	$4,$4,$5
	lw	$5,208($sp)
	sw	$2,40($8)
	lw	$2,%lo(table_napt)($9)
	srl	$3,$5,4
	lw	$10,224($sp)
	addu	$2,$6,$2
	lw	$2,4($2)
	xor	$4,$4,$3
	lw	$3,128($sp)
	sw	$8,0($2)
	lw	$2,%lo(table_napt)($9)
	xor	$4,$4,$10
	xor	$4,$4,$3
	addu	$2,$6,$2
	sw	$7,4($2)
	lw	$2,%lo(table_napt)($9)
	srl	$3,$4,12
	xor	$4,$4,$3
	andi	$4,$4,0x3ff
	sw	$4,132($sp)
	addu	$6,$6,$2
	lw	$2,8($6)
	lui	$4,%hi(path_list_free)
	addiu	$2,$2,1
	sw	$2,8($6)
	lw	$17,%lo(path_list_free)($4)
	nop
	beq	$17,$0,$L57
	move	$4,$fp

	lw	$5,200($sp)
	nop
	sw	$5,4($17)
	lw	$6,204($sp)
	nop
	sw	$6,8($17)
	lw	$7,208($sp)
	sw	$fp,16($17)
	sw	$10,20($17)
	sw	$7,12($17)
	lw	$10,212($sp)
	nop
	sw	$10,24($17)
	lw	$2,216($sp)
	sw	$fp,32($17)
	sw	$2,28($17)
	lw	$3,224($sp)
	jal	FastPath_Route
	sw	$3,36($17)

	lw	$4,8($17)
	lw	$3,24($17)
	sw	$2,44($17)
	li	$2,1
	sb	$2,2($17)
	li	$2,-1
	sb	$2,0($17)
	beq	$4,$3,$L58
	sb	$0,1($17)

	li	$2,1			# 0x1
	sb	$2,1($17)
$L58:
	lw	$3,12($17)
	lw	$2,28($17)
	nop
	beq	$3,$2,$L59
	nop

	lbu	$2,1($17)
	nop
	ori	$2,$2,0x2
	sb	$2,1($17)
$L59:
	sw	$0,48($17)
	sw	$0,52($17)
	lhu	$4,106($18)
	li	$2,33
	sb	$2,65($sp)
	li	$2,8
	sb	$2,72($sp)
	sw	$4,136($sp)
	sb	$0,64($sp)
	sb	$0,73($sp)
	lw	$5,144($18)
	lw	$6,204($sp)
	li	$2,2048			# 0x800
	sw	$5,144($sp)
	lw	$16,12($20)
	lhu	$22,0($21)
	lhu	$23,2($21)
	sw	$6,12($20)
	lw	$7,208($sp)
	lw	$19,16($20)
	sh	$7,0($21)
	sw	$fp,16($20)
	lw	$10,224($sp)
	nop
	sh	$10,2($21)
	bne	$4,$2,$L60
	sw	$0,144($18)

	lui	$2,%hi(nf_hooks+128)
	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L60
	lui	$2,%hi(init_net+236)

	lw	$6,140($18)
	lw	$7,24($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	move	$5,$0
	jal	ipt_do_table
	sw	$2,16($sp)

$L60:
	lw	$2,144($18)
	nop
	sw	$2,48($17)
	sw	$fp,12($20)
	lw	$2,224($sp)
	nop
	sh	$2,0($21)
	lw	$3,204($sp)
	li	$2,2048			# 0x800
	sw	$3,16($20)
	lw	$4,208($sp)
	nop
	sh	$4,2($21)
	sw	$0,144($18)
	lw	$5,136($sp)
	nop
	bne	$5,$2,$L65
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L65
	lui	$2,%hi(init_net+236)

	lw	$6,24($18)
	lw	$7,140($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	li	$5,4			# 0x4
	jal	ipt_do_table
	sw	$2,16($sp)

$L65:
	lw	$2,144($18)
	nop
	sw	$2,52($17)
	sw	$16,12($20)
	sh	$22,0($21)
	sw	$19,16($20)
	sh	$23,2($21)
	lw	$2,48($17)
	nop
	beq	$2,$0,$L177
	addiu	$16,$sp,48

	lw	$2,52($17)
	nop
	bne	$2,$0,$L70
	nop

$L177:
	move	$4,$16
	move	$5,$0
	jal	memset
	li	$6,14			# 0xe

	lui	$19,%hi(init_net)
	lui	$5,%hi($LC0)
	addiu	$5,$5,%lo($LC0)
	jal	__dev_get_by_name
	addiu	$4,$19,%lo(init_net)

	beq	$2,$0,$L70
	move	$5,$2

	lw	$4,204($sp)
	jal	arp_req_get_ha
	move	$6,$16

	bne	$2,$0,$L70
	addiu	$5,$sp,64

	lw	$4,176($18)
	li	$6,2			# 0x2
	jal	memcmp
	addiu	$4,$4,-2

	bne	$2,$0,$L73
	nop

	lw	$3,160($18)
	nop
	beq	$3,$0,$L73
	nop

	lbu	$2,12($3)
	lbu	$3,13($3)
	sll	$2,$2,8
	or	$3,$3,$2
	li	$2,2048			# 0x800
	beq	$3,$2,$L73
	nop

	lw	$2,176($18)
	nop
	addiu	$2,$2,-22
	sw	$2,160($18)
$L73:
	lw	$5,160($18)
	addiu	$4,$sp,24
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$5,$5,6

	lw	$5,160($18)
	addiu	$23,$sp,32
	move	$4,$23
	jal	memcpy
	li	$6,6			# 0x6

	lw	$2,48($17)
	nop
	bne	$2,$0,$L82
	li	$6,6			# 0x6

	lw	$4,160($18)
	move	$5,$16
	jal	memcpy
	addiu	$4,$4,6

	sw	$0,144($18)
	lw	$6,136($sp)
	li	$2,2048			# 0x800
	bne	$6,$2,$L85
	lui	$2,%hi(nf_hooks+128)

	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L85
	addiu	$2,$19,%lo(init_net)

	lw	$6,140($18)
	lw	$7,24($18)
	lw	$2,236($2)
	move	$4,$18
	move	$5,$0
	jal	ipt_do_table
	sw	$2,16($sp)

$L85:
	lw	$2,144($18)
	addiu	$5,$sp,24
	li	$6,6			# 0x6
	sw	$2,48($17)
	lw	$4,160($18)
	jal	memcpy
	addiu	$4,$4,6

$L82:
	lw	$2,52($17)
	nop
	bne	$2,$0,$L70
	addiu	$22,$sp,48

	lw	$4,160($18)
	move	$5,$22
	jal	memcpy
	li	$6,6			# 0x6

	lw	$19,28($18)
	nop
	beq	$19,$0,$L95
	nop

	lw	$3,48($19)
	nop
	beq	$3,$0,$L95
	li	$2,-20			# 0xffffffffffffffec

	beq	$3,$2,$L95
	addiu	$16,$3,22

	addiu	$4,$sp,40
	move	$5,$16
	li	$6,6			# 0x6
	jal	memcpy
	sw	$3,140($sp)

	move	$4,$16
	move	$5,$22
	jal	memcpy
	li	$6,6			# 0x6

$L95:
	sw	$0,144($18)
	lw	$7,136($sp)
	li	$2,2048			# 0x800
	bne	$7,$2,$L96
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L96
	lui	$2,%hi(init_net+236)

	lw	$6,24($18)
	lw	$7,140($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	li	$5,4			# 0x4
	jal	ipt_do_table
	sw	$2,16($sp)

$L96:
	lw	$2,144($18)
	beq	$19,$0,$L101
	sw	$2,52($17)

	lw	$3,48($19)
	nop
	beq	$3,$0,$L101
	li	$2,-20			# 0xffffffffffffffec

	beq	$3,$2,$L101
	addiu	$5,$sp,40

	lw	$10,140($sp)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$10,22

$L101:
	lw	$4,160($18)
	move	$5,$23
	jal	memcpy
	li	$6,6			# 0x6

$L70:
	lw	$2,144($sp)
	nop
	sw	$2,144($18)
	lw	$3,200($sp)
	li	$2,2			# 0x2
	bne	$3,$2,$L105
	lui	$2,%hi(nf_ct_udp_timeout_stream)

	lw	$5,232($sp)
	nop
	lbu	$4,184($5)
	jal	tcp_get_timeouts_by_state
	nop

	j	$L175
	sw	$2,60($17)

$L105:
	lw	$2,%lo(nf_ct_udp_timeout_stream)($2)
	nop
	sw	$2,60($17)
$L175:
	lw	$6,232($sp)
	lui	$2,%hi(jiffies)
	lw	$3,72($17)
	sw	$6,56($17)
	lw	$2,%lo(jiffies)($2)
	lw	$4,76($17)
	beq	$3,$0,$L108
	sw	$2,40($17)

	j	$L109
	sw	$4,76($3)

$L108:
	lui	$7,%hi(path_list_free)
	addiu	$2,$7,%lo(path_list_free)
	sw	$4,4($2)
$L109:
	lw	$4,76($17)
	lw	$2,72($17)
	lui	$3,%hi(path_list_free)
	addiu	$3,$3,%lo(path_list_free)
	sw	$2,0($4)
	lw	$2,8($3)
	lui	$4,%hi(path_list_inuse)
	addiu	$4,$4,%lo(path_list_inuse)
	addiu	$2,$2,-1
	sw	$2,8($3)
	sw	$0,72($17)
	lw	$2,4($4)
	addiu	$6,$17,72
	lui	$5,%hi(table_path)
	sw	$2,76($17)
	lw	$2,4($4)
	lw	$10,132($sp)
	sw	$17,0($2)
	lw	$2,8($4)
	sw	$6,4($4)
	sll	$3,$10,1
	addiu	$2,$2,1
	sw	$2,8($4)
	sw	$0,64($17)
	lw	$2,%lo(table_path)($5)
	addu	$3,$3,$10
	sll	$3,$3,2
	addu	$2,$3,$2
	lw	$2,4($2)
	addiu	$4,$17,64
	sw	$2,68($17)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	lw	$2,4($2)
	nop
	sw	$17,0($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	sw	$4,4($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$3,$3,$2
	lw	$2,8($3)
	nop
	addiu	$2,$2,1
	sw	$2,8($3)
$L57:
	lw	$4,212($sp)
	lw	$5,224($sp)
	srl	$2,$fp,8
	srl	$3,$4,16
	xor	$3,$3,$4
	xor	$2,$2,$fp
	lw	$6,216($sp)
	xor	$2,$2,$3
	lw	$7,128($sp)
	srl	$3,$5,4
	xor	$2,$2,$3
	xor	$2,$2,$6
	xor	$2,$2,$7
	lui	$10,%hi(path_list_free)
	srl	$3,$2,12
	lw	$17,%lo(path_list_free)($10)
	xor	$2,$2,$3
	andi	$2,$2,0x3ff
	beq	$17,$0,$L168
	sw	$2,132($sp)

	sw	$4,16($17)
	sw	$6,20($17)
	lw	$2,200($sp)
	sw	$fp,8($17)
	sw	$5,12($17)
	sw	$2,4($17)
	sw	$fp,24($17)
	sw	$5,28($17)
	lw	$3,204($sp)
	nop
	sw	$3,32($17)
	lw	$4,208($sp)
	nop
	sw	$4,36($17)
	lw	$4,204($sp)
	jal	FastPath_Route
	nop

	lw	$4,16($17)
	lw	$3,32($17)
	sw	$2,44($17)
	li	$2,2
	sb	$2,2($17)
	li	$2,-1
	sb	$2,0($17)
	beq	$4,$3,$L114
	sb	$0,1($17)

	li	$2,4			# 0x4
	sb	$2,1($17)
$L114:
	lw	$3,20($17)
	lw	$2,36($17)
	nop
	beq	$3,$2,$L115
	nop

	lbu	$2,1($17)
	nop
	ori	$2,$2,0x8
	sb	$2,1($17)
$L115:
	sw	$0,48($17)
	sw	$0,52($17)
	lhu	$5,106($18)
	li	$2,33
	sb	$2,73($sp)
	li	$2,8
	sb	$2,120($sp)
	sw	$5,148($sp)
	sb	$0,72($sp)
	sb	$0,121($sp)
	lw	$6,144($18)
	lw	$7,204($sp)
	sw	$6,156($sp)
	lw	$16,12($20)
	lhu	$22,0($21)
	lhu	$23,2($21)
	sw	$7,12($20)
	lw	$10,208($sp)
	lw	$19,16($20)
	sh	$10,0($21)
	sw	$fp,16($20)
	lw	$2,224($sp)
	nop
	sh	$2,2($21)
	li	$2,2048			# 0x800
	bne	$5,$2,$L116
	sw	$0,144($18)

	lui	$2,%hi(nf_hooks+128)
	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L116
	lui	$2,%hi(init_net+236)

	lw	$6,140($18)
	lw	$7,24($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	move	$5,$0
	jal	ipt_do_table
	sw	$2,16($sp)

$L116:
	lw	$2,144($18)
	nop
	sw	$2,48($17)
	sw	$fp,12($20)
	lw	$3,224($sp)
	li	$2,2048			# 0x800
	sh	$3,0($21)
	lw	$4,204($sp)
	nop
	sw	$4,16($20)
	lw	$5,208($sp)
	nop
	sh	$5,2($21)
	sw	$0,144($18)
	lw	$6,148($sp)
	nop
	bne	$6,$2,$L121
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L121
	lui	$2,%hi(init_net+236)

	lw	$6,24($18)
	lw	$7,140($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	li	$5,4			# 0x4
	jal	ipt_do_table
	sw	$2,16($sp)

$L121:
	lw	$2,144($18)
	nop
	sw	$2,52($17)
	sw	$16,12($20)
	sh	$22,0($21)
	sw	$19,16($20)
	sh	$23,2($21)
	lw	$2,48($17)
	nop
	beq	$2,$0,$L178
	addiu	$16,$sp,104

	lw	$2,52($17)
	nop
	bne	$2,$0,$L126
	nop

$L178:
	move	$4,$16
	move	$5,$0
	jal	memset
	li	$6,14			# 0xe

	lui	$20,%hi(init_net)
	lui	$5,%hi($LC0)
	addiu	$5,$5,%lo($LC0)
	jal	__dev_get_by_name
	addiu	$4,$20,%lo(init_net)

	beq	$2,$0,$L126
	move	$5,$2

	lw	$4,204($sp)
	jal	arp_req_get_ha
	move	$6,$16

	bne	$2,$0,$L126
	addiu	$5,$sp,72

	lw	$4,176($18)
	li	$6,2			# 0x2
	jal	memcmp
	addiu	$4,$4,-2

	bne	$2,$0,$L129
	nop

	lw	$3,160($18)
	nop
	beq	$3,$0,$L129
	nop

	lbu	$2,12($3)
	lbu	$3,13($3)
	sll	$2,$2,8
	or	$3,$3,$2
	li	$2,2048			# 0x800
	beq	$3,$2,$L129
	nop

	lw	$2,176($18)
	nop
	addiu	$2,$2,-22
	sw	$2,160($18)
$L129:
	lw	$5,160($18)
	addiu	$19,$sp,80
	move	$4,$19
	addiu	$5,$5,6
	jal	memcpy
	li	$6,6			# 0x6

	lw	$5,160($18)
	addiu	$21,$sp,88
	move	$4,$21
	jal	memcpy
	li	$6,6			# 0x6

	lw	$2,48($17)
	nop
	bne	$2,$0,$L138
	move	$5,$16

	lw	$4,160($18)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$4,6

	sw	$0,144($18)
	lw	$7,148($sp)
	li	$2,2048			# 0x800
	bne	$7,$2,$L141
	lui	$2,%hi(nf_hooks+128)

	lw	$3,%lo(nf_hooks+128)($2)
	addiu	$2,$2,%lo(nf_hooks+128)
	beq	$3,$2,$L141
	addiu	$2,$20,%lo(init_net)

	lw	$6,140($18)
	lw	$7,24($18)
	lw	$2,236($2)
	move	$4,$18
	move	$5,$0
	jal	ipt_do_table
	sw	$2,16($sp)

$L141:
	lw	$2,144($18)
	move	$5,$19
	li	$6,6			# 0x6
	sw	$2,48($17)
	lw	$4,160($18)
	jal	memcpy
	addiu	$4,$4,6

$L138:
	lw	$2,52($17)
	nop
	bne	$2,$0,$L126
	addiu	$20,$sp,104

	lw	$4,160($18)
	move	$5,$20
	jal	memcpy
	li	$6,6			# 0x6

	lw	$19,28($18)
	nop
	beq	$19,$0,$L151
	nop

	lw	$3,48($19)
	nop
	beq	$3,$0,$L151
	li	$2,-20			# 0xffffffffffffffec

	beq	$3,$2,$L151
	addiu	$16,$3,22

	addiu	$4,$sp,96
	move	$5,$16
	li	$6,6			# 0x6
	jal	memcpy
	sw	$3,152($sp)

	move	$4,$16
	move	$5,$20
	jal	memcpy
	li	$6,6			# 0x6

$L151:
	sw	$0,144($18)
	lw	$10,148($sp)
	li	$2,2048			# 0x800
	bne	$10,$2,$L152
	lui	$2,%hi(nf_hooks+160)

	lw	$3,%lo(nf_hooks+160)($2)
	addiu	$2,$2,%lo(nf_hooks+160)
	beq	$3,$2,$L152
	lui	$2,%hi(init_net+236)

	lw	$6,24($18)
	lw	$7,140($18)
	lw	$2,%lo(init_net+236)($2)
	move	$4,$18
	li	$5,4			# 0x4
	jal	ipt_do_table
	sw	$2,16($sp)

$L152:
	lw	$2,144($18)
	beq	$19,$0,$L157
	sw	$2,52($17)

	lw	$3,48($19)
	nop
	beq	$3,$0,$L157
	li	$2,-20			# 0xffffffffffffffec

	beq	$3,$2,$L157
	addiu	$5,$sp,96

	lw	$2,152($sp)
	li	$6,6			# 0x6
	jal	memcpy
	addiu	$4,$2,22

$L157:
	lw	$4,160($18)
	move	$5,$21
	jal	memcpy
	li	$6,6			# 0x6

$L126:
	lw	$3,156($sp)
	li	$2,2			# 0x2
	sw	$3,144($18)
	lw	$4,200($sp)
	nop
	bne	$4,$2,$L161
	lui	$2,%hi(nf_ct_udp_timeout_stream)

	lw	$5,232($sp)
	nop
	lbu	$4,184($5)
	jal	tcp_get_timeouts_by_state
	nop

	j	$L176
	sw	$2,60($17)

$L161:
	lw	$2,%lo(nf_ct_udp_timeout_stream)($2)
	nop
	sw	$2,60($17)
$L176:
	lw	$6,232($sp)
	lui	$2,%hi(jiffies)
	lw	$3,72($17)
	sw	$6,56($17)
	lw	$2,%lo(jiffies)($2)
	lw	$4,76($17)
	beq	$3,$0,$L164
	sw	$2,40($17)

	j	$L165
	sw	$4,76($3)

$L164:
	lui	$7,%hi(path_list_free)
	addiu	$2,$7,%lo(path_list_free)
	sw	$4,4($2)
$L165:
	lw	$4,76($17)
	lw	$2,72($17)
	lui	$3,%hi(path_list_free)
	addiu	$3,$3,%lo(path_list_free)
	sw	$2,0($4)
	lw	$2,8($3)
	lui	$4,%hi(path_list_inuse)
	addiu	$4,$4,%lo(path_list_inuse)
	addiu	$2,$2,-1
	sw	$2,8($3)
	sw	$0,72($17)
	lw	$2,4($4)
	addiu	$6,$17,72
	lui	$5,%hi(table_path)
	sw	$2,76($17)
	lw	$2,4($4)
	lw	$10,132($sp)
	sw	$17,0($2)
	lw	$2,8($4)
	sw	$6,4($4)
	sll	$3,$10,1
	addiu	$2,$2,1
	sw	$2,8($4)
	sw	$0,64($17)
	lw	$2,%lo(table_path)($5)
	addu	$3,$3,$10
	sll	$3,$3,2
	addu	$2,$3,$2
	lw	$2,4($2)
	addiu	$4,$17,64
	sw	$2,68($17)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	lw	$2,4($2)
	nop
	sw	$17,0($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	sw	$4,4($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$3,$3,$2
	lw	$2,8($3)
	nop
	addiu	$2,$2,1
	sw	$2,8($3)
$L168:
	move	$2,$0
$L39:
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
	sw	$19,36($sp)
	sw	$17,28($sp)
	lw	$19,88($sp)
	lw	$17,84($sp)
	andi	$2,$4,0xffff
	sw	$23,52($sp)
	sw	$22,48($sp)
	sw	$21,44($sp)
	sw	$18,32($sp)
	move	$23,$4
	move	$18,$5
	move	$4,$5
	move	$22,$6
	move	$5,$6
	sw	$2,16($sp)
	move	$6,$17
	move	$21,$7
	move	$7,$19
	sw	$31,60($sp)
	sw	$fp,56($sp)
	sw	$20,40($sp)
	jal	FastPath_Hash_NAPT_Entry
	sw	$16,24($sp)

	move	$16,$2
	xori	$3,$23,0x2
	li	$2,17			# 0x11
	li	$20,6			# 0x6
	move	$4,$17
	lw	$fp,80($sp)
	jal	filter_delconnect
	movn	$20,$2,$3		#RLX4181/RLX4281:conditional move  

	lui	$10,%hi(table_napt)
	lw	$3,%lo(table_napt)($10)
	sll	$2,$16,1
	addu	$2,$2,$16
	sll	$2,$2,2
	addu	$3,$2,$3
	lw	$5,0($3)
	nop
	beq	$5,$0,$L221
	lui	$3,%hi(napt_list_inuse)

	move	$4,$2
	addiu	$6,$3,%lo(napt_list_inuse)
	srl	$2,$17,16
	lui	$3,%hi(napt_list_free)
	addiu	$7,$3,%lo(napt_list_free)
	xor	$9,$2,$17
	move	$8,$4
	lui	$12,%hi(path_list_inuse)
	lui	$13,%hi(path_list_free)
$L219:
	lw	$2,4($5)
	nop
	bne	$2,$23,$L184
	nop

	lw	$2,8($5)
	nop
	bne	$2,$18,$L184
	nop

	lw	$2,12($5)
	nop
	bne	$2,$22,$L184
	nop

	lw	$2,16($5)
	nop
	bne	$2,$21,$L184
	nop

	lw	$2,20($5)
	nop
	bne	$2,$fp,$L184
	nop

	lw	$2,24($5)
	nop
	bne	$2,$17,$L184
	nop

	lw	$2,28($5)
	nop
	bne	$2,$19,$L184
	nop

	lw	$2,36($5)
	sb	$0,0($5)
	lw	$3,40($5)
	beq	$2,$0,$L187
	nop

	j	$L188
	sw	$3,40($2)

$L187:
	lw	$2,%lo(table_napt)($10)
	nop
	addu	$2,$4,$2
	sw	$3,4($2)
$L188:
	lw	$3,40($5)
	lw	$2,36($5)
	nop
	sw	$2,0($3)
	lui	$2,%hi(table_napt)
	lw	$3,%lo(table_napt)($2)
	nop
	addu	$3,$8,$3
	lw	$2,8($3)
	nop
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$2,44($5)
	lw	$3,48($5)
	beq	$2,$0,$L190
	nop

	j	$L191
	sw	$3,48($2)

$L190:
	sw	$3,4($6)
$L191:
	lw	$4,48($5)
	lw	$3,44($5)
	srl	$2,$18,8
	xor	$2,$2,$18
	sw	$3,0($4)
	lw	$3,8($6)
	srl	$4,$22,4
	xor	$2,$2,$9
	addiu	$3,$3,-1
	sw	$3,8($6)
	sw	$0,44($5)
	lw	$3,4($7)
	xor	$2,$2,$4
	xor	$2,$2,$19
	sw	$3,48($5)
	lw	$4,4($7)
	xor	$2,$2,$20
	srl	$3,$2,12
	sw	$5,0($4)
	xor	$2,$2,$3
	andi	$6,$2,0x3ff
	lw	$3,8($7)
	lui	$8,%hi(table_path)
	lw	$4,%lo(table_path)($8)
	sll	$2,$6,1
	addu	$2,$2,$6
	addiu	$5,$5,44
	addiu	$3,$3,1
	sll	$2,$2,2
	sw	$3,8($7)
	sw	$5,4($7)
	addu	$4,$2,$4
	lw	$5,0($4)
	nop
	beq	$5,$0,$L195
	move	$4,$2

	move	$10,$2
	addiu	$9,$12,%lo(path_list_inuse)
	addiu	$7,$13,%lo(path_list_free)
	li	$3,1			# 0x1
	move	$11,$8
$L205:
	lw	$2,4($5)
	nop
	bne	$2,$23,$L196
	nop

	lbu	$2,2($5)
	nop
	bne	$2,$3,$L196
	nop

	lw	$2,8($5)
	nop
	bne	$2,$18,$L196
	nop

	lw	$2,12($5)
	nop
	bne	$2,$22,$L196
	nop

	lw	$2,24($5)
	nop
	bne	$2,$21,$L196
	nop

	lw	$2,28($5)
	nop
	bne	$2,$fp,$L196
	nop

	lw	$2,16($5)
	nop
	bne	$2,$17,$L196
	nop

	lw	$2,20($5)
	nop
	bne	$2,$19,$L196
	nop

	lw	$2,64($5)
	sb	$0,0($5)
	lw	$6,68($5)
	beq	$2,$0,$L199
	nop

	j	$L200
	sw	$6,68($2)

$L199:
	lw	$2,%lo(table_path)($8)
	nop
	addu	$2,$4,$2
	sw	$6,4($2)
$L200:
	lw	$3,68($5)
	lw	$2,64($5)
	nop
	sw	$2,0($3)
	lw	$3,%lo(table_path)($11)
	nop
	addu	$3,$10,$3
	lw	$2,8($3)
	nop
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$3,72($5)
	lw	$2,76($5)
	beq	$3,$0,$L202
	nop

	j	$L203
	sw	$2,76($3)

$L202:
	sw	$2,4($9)
$L203:
	lw	$2,72($5)
	lw	$3,76($5)
	addiu	$4,$5,72
	sw	$2,0($3)
	lw	$2,8($9)
	nop
	addiu	$2,$2,-1
	sw	$2,8($9)
	sw	$0,72($5)
	lw	$2,4($7)
	nop
	sw	$2,76($5)
	lw	$2,4($7)
	nop
	sw	$5,0($2)
	lw	$2,8($7)
	sw	$4,4($7)
	addiu	$2,$2,1
	j	$L195
	sw	$2,8($7)

$L196:
	lw	$5,64($5)
	nop
	bne	$5,$0,$L205
	nop

$L195:
	srl	$2,$17,8
	srl	$3,$21,16
	xor	$3,$3,$21
	xor	$2,$2,$17
	xor	$2,$2,$3
	srl	$3,$19,4
	xor	$2,$2,$3
	xor	$2,$2,$fp
	xor	$2,$2,$20
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$6,$2,0x3ff
	lui	$4,%hi(table_path)
	lw	$3,%lo(table_path)($4)
	sll	$2,$6,1
	addu	$2,$2,$6
	sll	$2,$2,2
	addu	$3,$2,$3
	lw	$5,0($3)
	nop
	beq	$5,$0,$L208
	nop

	move	$3,$2
	addiu	$8,$12,%lo(path_list_inuse)
	addiu	$7,$13,%lo(path_list_free)
	move	$9,$2
	li	$6,2			# 0x2
	move	$10,$4
$L218:
	lw	$2,4($5)
	nop
	bne	$2,$23,$L209
	nop

	lbu	$2,2($5)
	nop
	bne	$2,$6,$L209
	nop

	lw	$2,16($5)
	nop
	bne	$2,$21,$L209
	nop

	lw	$2,20($5)
	nop
	bne	$2,$fp,$L209
	nop

	lw	$2,24($5)
	nop
	bne	$2,$17,$L209
	nop

	lw	$2,28($5)
	nop
	bne	$2,$19,$L209
	nop

	lw	$2,32($5)
	nop
	bne	$2,$18,$L209
	nop

	lw	$2,36($5)
	nop
	bne	$2,$22,$L209
	nop

	lw	$2,64($5)
	sb	$0,0($5)
	lw	$6,68($5)
	beq	$2,$0,$L212
	nop

	j	$L213
	sw	$6,68($2)

$L212:
	lw	$2,%lo(table_path)($4)
	nop
	addu	$2,$3,$2
	sw	$6,4($2)
$L213:
	lw	$3,68($5)
	lw	$2,64($5)
	nop
	sw	$2,0($3)
	lw	$3,%lo(table_path)($10)
	nop
	addu	$3,$9,$3
	lw	$2,8($3)
	nop
	addiu	$2,$2,-1
	sw	$2,8($3)
	lw	$3,72($5)
	lw	$2,76($5)
	beq	$3,$0,$L215
	nop

	j	$L216
	sw	$2,76($3)

$L215:
	sw	$2,4($8)
$L216:
	lw	$2,72($5)
	lw	$3,76($5)
	addiu	$4,$5,72
	sw	$2,0($3)
	lw	$2,8($8)
	nop
	addiu	$2,$2,-1
	sw	$2,8($8)
	sw	$0,72($5)
	lw	$2,4($7)
	nop
	sw	$2,76($5)
	lw	$2,4($7)
	nop
	sw	$5,0($2)
	lw	$2,8($7)
	sw	$4,4($7)
	addiu	$2,$2,1
	j	$L208
	sw	$2,8($7)

$L209:
	lw	$5,64($5)
	nop
	bne	$5,$0,$L218
	nop

$L208:
	j	$L179
	move	$2,$0

$L184:
	lw	$5,36($5)
	nop
	bne	$5,$0,$L219
	nop

$L221:
	li	$2,-4			# 0xfffffffffffffffc
$L179:
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
	lw	$9,52($sp)
	srl	$2,$5,8
	xor	$2,$2,$5
	srl	$3,$9,16
	xor	$3,$3,$9
	lw	$11,56($sp)
	xor	$2,$2,$3
	srl	$3,$6,4
	xor	$2,$2,$3
	move	$12,$4
	li	$3,17			# 0x11
	xori	$4,$4,0x2
	li	$8,6			# 0x6
	movn	$8,$3,$4		#RLX4181/RLX4281:conditional move  
	xor	$2,$2,$11
	xor	$2,$2,$8
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$4,$2,0x3ff
	lui	$14,%hi(table_path)
	lw	$3,%lo(table_path)($14)
	sll	$2,$4,1
	addu	$2,$2,$4
	sll	$2,$2,2
	sw	$18,24($sp)
	sw	$31,28($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	addu	$2,$2,$3
	lw	$16,0($2)
	lui	$2,%hi(jiffies)
	lw	$13,%lo(jiffies)($2)
	lw	$10,48($sp)
	lw	$18,60($sp)
$L254:
	beq	$16,$0,$L257
	srl	$2,$9,8

	lw	$2,4($16)
	nop
	bne	$2,$12,$L230
	li	$2,1			# 0x1

	lbu	$3,2($16)
	nop
	bne	$3,$2,$L230
	nop

	lw	$2,8($16)
	nop
	bne	$2,$5,$L230
	nop

	lw	$2,12($16)
	nop
	bne	$2,$6,$L230
	nop

	lw	$2,24($16)
	nop
	bne	$2,$7,$L230
	nop

	lw	$2,28($16)
	nop
	bne	$2,$10,$L230
	nop

	lw	$2,16($16)
	nop
	bne	$2,$9,$L230
	nop

	lw	$2,20($16)
	nop
	bne	$2,$11,$L230
	subu	$2,$13,$18

	lw	$17,40($16)
	nop
	subu	$2,$2,$17
	bgez	$2,$L229
	nop

	j	$L256
	nop

$L230:
	lw	$16,64($16)
	j	$L254
	nop

$L229:
	srl	$2,$9,8
$L257:
	srl	$3,$7,16
	xor	$3,$3,$7
	xor	$2,$2,$9
	xor	$2,$2,$3
	srl	$3,$11,4
	xor	$2,$2,$3
	xor	$2,$2,$10
	xor	$2,$2,$8
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$4,$2,0x3ff
	lw	$3,%lo(table_path)($14)
	sll	$2,$4,1
	addu	$2,$2,$4
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$16,0($2)
	nop
$L255:
	beq	$16,$0,$L224
	move	$2,$0

	lw	$2,4($16)
	nop
	bne	$2,$12,$L242
	li	$2,2			# 0x2

	lbu	$3,2($16)
	nop
	bne	$3,$2,$L242
	nop

	lw	$2,16($16)
	nop
	bne	$2,$7,$L242
	nop

	lw	$2,20($16)
	nop
	bne	$2,$10,$L242
	nop

	lw	$2,24($16)
	nop
	bne	$2,$9,$L242
	nop

	lw	$2,28($16)
	nop
	bne	$2,$11,$L242
	nop

	lw	$2,32($16)
	nop
	bne	$2,$5,$L242
	nop

	lw	$2,36($16)
	nop
	bne	$2,$6,$L242
	subu	$2,$13,$18

	lw	$17,40($16)
	nop
	subu	$2,$2,$17
	bgez	$2,$L241
	nop

$L256:
	jal	local_bh_disable
	nop

	lw	$2,56($16)
	addu	$3,$17,$18
	sw	$3,124($2)
	lw	$4,56($16)
	jal	add_timer
	addiu	$4,$4,116

	jal	local_bh_enable
	nop

	j	$L224
	li	$2,-1			# 0xffffffffffffffff

$L242:
	lw	$16,64($16)
	j	$L255
	nop

$L241:
	move	$2,$0
$L224:
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
	move	$17,$4
	sw	$2,24($sp)
	lw	$3,176($2)
	#nop
	sw	$3,152($2)
	lw	$3,24($sp)
	#nop
	lw	$2,176($3)
	#nop
	sw	$2,156($3)
	lw	$4,24($sp)
	jal	filter_enter
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L259
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
	j	$L496
	move	$2,$16
	.set	macro
	.set	reorder

$L259:
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$16,$2,$L260
	move	$16,$0
	.set	macro
	.set	reorder

	lui	$2,%hi(fast_nat_fw)
	lw	$2,%lo(fast_nat_fw)($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L260
	lui	$3,%hi(fast_pptp_fw)
	.set	macro
	.set	reorder

	lw	$2,%lo(fast_pptp_fw)($3)
	#nop
	beq	$2,$0,$L263
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
	bltz	$2,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$2,24($sp)
	#nop
	sw	$2,0($17)
$L263:
	lui	$4,%hi(fast_l2tp_fw)
	lw	$2,%lo(fast_l2tp_fw)($4)
	#nop
	beq	$2,$0,$L265
	lw	$4,24($sp)
	jal	fast_l2tp_rx
$L265:
	lw	$19,24($sp)
	li	$2,1			# 0x1
	sw	$2,28($sp)
	lw	$18,156($19)
	sw	$0,32($sp)
	sw	$0,36($sp)
	lbu	$22,9($18)
	li	$2,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$22,$2,$L268
	move	$fp,$0
	.set	macro
	.set	reorder

	li	$2,17			# 0x11
	.set	noreorder
	.set	nomacro
	bne	$22,$2,$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L268:
	lui	$3,%hi(fast_l2tp_fw)
	lw	$2,%lo(fast_l2tp_fw)($3)
	#nop
	beq	$2,$0,$L270
	lw	$5,24($19)
	#nop
	lw	$3,292($5)
	#nop
	bne	$3,$0,$L270
	lui	$4,%hi(init_net)
	.set	noreorder
	.set	nomacro
	jal	__dev_get_by_name
	addiu	$4,$4,%lo(init_net)
	.set	macro
	.set	reorder

	beq	$2,$0,$L270
	lw	$3,292($2)
	#nop
	beq	$3,$0,$L270
	lw	$2,24($19)
	#nop
	sw	$3,292($2)
$L270:
	lbu	$2,0($18)
	lw	$21,12($18)
	lw	$20,16($18)
	andi	$2,$2,0xf
	sll	$2,$2,2
	addu	$23,$18,$2
	li	$2,6			# 0x6
	lhu	$11,0($23)
	lhu	$10,2($23)
	.set	noreorder
	.set	nomacro
	beq	$22,$2,$L275
	li	$2,17			# 0x11
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$22,$2,$L304
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L275:
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
	nop
	move	$4,$1
2:	subu	$4,$1
3:	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	lhu	$3,6($18)
	#nop
	andi	$2,$3,0x3fff
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L281
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	xori	$2,$3,0x2000
	.set	noreorder
	.set	nomacro
	j	$L281
	sltu	$4,$2,1
	.set	macro
	.set	reorder

$L475:
	lw	$5,24($4)
	lhu	$6,30($4)
	j	$L286
$L281:
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$4,$2,$L274
	li	$2,65536			# 0x10000
	.set	macro
	.set	reorder

	lw	$3,12($23)
	#nop
	and	$2,$3,$2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L283
	li	$2,458752			# 0x70000
	.set	macro
	.set	reorder

	srl	$2,$21,8
	srl	$3,$20,16
	xor	$3,$3,$20
	xor	$2,$2,$21
	xor	$2,$2,$3
	srl	$3,$11,4
	xor	$2,$2,$3
	xor	$2,$2,$10
	xor	$2,$2,$22
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$4,$2,0x3ff
	lui	$7,%hi(table_path)
	sll	$2,$4,1
	lw	$3,%lo(table_path)($7)
	addu	$2,$2,$4
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$4,0($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	li	$3,255			# 0xff
$L291:
	lw	$2,12($4)
	#nop
	bne	$2,$11,$L287
	lw	$2,20($4)
	#nop
	bne	$2,$10,$L287
	lw	$2,8($4)
	#nop
	bne	$2,$21,$L287
	lw	$2,16($4)
	#nop
	bne	$2,$20,$L287
	lbu	$2,0($4)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L287
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lbu	$3,2($4)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L475
	sb	$0,0($4)
	.set	macro
	.set	reorder

	lw	$5,32($4)
	lhu	$6,38($4)
	j	$L286
$L287:
	lw	$4,64($4)
	#nop
	bne	$4,$0,$L291
	.set	noreorder
	.set	nomacro
	j	$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L286:
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	lbu	$3,2($4)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L294
	srl	$3,$21,16
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
	j	$L480
	xor	$2,$2,$6
	.set	macro
	.set	reorder

$L294:
	srl	$2,$5,8
	xor	$3,$3,$21
	xor	$2,$2,$5
	xor	$2,$2,$3
	srl	$3,$6,4
	xor	$2,$2,$3
	xor	$2,$2,$11
$L480:
	xor	$2,$2,$22
	srl	$3,$2,12
	xor	$2,$2,$3
	andi	$4,$2,0x3ff
	sll	$2,$4,1
	lw	$3,%lo(table_path)($7)
	addu	$2,$2,$4
	sll	$2,$2,2
	addu	$2,$2,$3
	lw	$4,0($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	li	$3,255			# 0xff
$L302:
	lw	$2,24($4)
	#nop
	bne	$2,$20,$L300
	lw	$2,28($4)
	#nop
	bne	$2,$10,$L300
	lw	$2,32($4)
	#nop
	bne	$2,$21,$L300
	lw	$2,36($4)
	#nop
	bne	$2,$11,$L300
	lbu	$2,0($4)
	#nop
	bne	$2,$3,$L300
	sb	$0,0($4)
$L300:
	lw	$4,64($4)
	#nop
	bne	$4,$0,$L302
	.set	noreorder
	.set	nomacro
	j	$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L283:
	and	$2,$3,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	j	$L274
$L304:
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
	nop
	move	$4,$1
2:	subu	$4,$1
3:	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L274:
	lhu	$3,6($18)
	#nop
	andi	$2,$3,0x3fff
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L308
	li	$2,8192			# 0x2000
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L309
	andi	$2,$3,0x2000
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$L310
	sw	$4,32($sp)
	.set	macro
	.set	reorder

$L309:
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L310
	andi	$3,$3,0x1fff
	.set	macro
	.set	reorder

	lw	$4,36($sp)
	li	$2,1			# 0x1
	movn	$4,$2,$3		#RLX4181/RLX4281:conditional move
	sw	$4,36($sp)
$L310:
	lhu	$6,4($18)
	xor	$3,$21,$20
	srl	$2,$3,16
	xor	$2,$2,$6
	xor	$3,$3,$2
	srl	$2,$3,8
	andi	$5,$22,0x00ff
	xor	$2,$2,$5
	xor	$3,$3,$2
	andi	$3,$3,0x3f
	lui	$2,%hi(udp_cache_table)
	lw	$4,%lo(udp_cache_table)($2)
	sll	$2,$3,1
	addu	$2,$2,$3
	sll	$2,$2,2
	addu	$2,$2,$4
	lw	$3,0($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L472
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

$L318:
	lhu	$2,2($3)
	#nop
	bne	$2,$6,$L315
	lw	$2,4($3)
	#nop
	bne	$2,$21,$L315
	lw	$2,8($3)
	#nop
	bne	$2,$20,$L315
	lbu	$2,1($3)
	#nop
	bne	$2,$5,$L315
	lbu	$2,0($3)
	#nop
	beq	$2,$4,$L476
$L315:
	lw	$3,40($3)
	#nop
	bne	$3,$0,$L318
$L472:
	.set	noreorder
	.set	nomacro
	j	$L319
	move	$fp,$0
	.set	macro
	.set	reorder

$L476:
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L319
	move	$fp,$3
	.set	macro
	.set	reorder

	lw	$2,32($sp)
	lhu	$11,12($3)
	lhu	$10,14($3)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L498
	srl	$3,$21,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L498
	sw	$0,28($sp)
	.set	macro
	.set	reorder

$L319:
	lw	$4,32($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

$L308:
	srl	$3,$21,8
$L498:
	srl	$2,$20,16
	xor	$2,$2,$20
	xor	$3,$3,$21
	xor	$3,$3,$2
	srl	$2,$11,4
	xor	$3,$3,$2
	xor	$3,$3,$10
	xor	$3,$3,$22
	srl	$2,$3,12
	xor	$3,$3,$2
	andi	$3,$3,0x3ff
	lui	$2,%hi(table_path)
	lw	$4,%lo(table_path)($2)
	sll	$2,$3,1
	addu	$2,$2,$3
	sll	$2,$2,2
	addu	$2,$2,$4
	lw	$16,0($2)
	#nop
$L481:
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L474
	move	$3,$0
	.set	macro
	.set	reorder

	lw	$2,12($16)
	#nop
	bne	$2,$11,$L326
	lw	$2,20($16)
	#nop
	bne	$2,$10,$L326
	lw	$2,8($16)
	#nop
	bne	$2,$21,$L326
	lw	$2,16($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$2,$20,$L326
	li	$2,255			# 0xff
	.set	macro
	.set	reorder

	lbu	$3,0($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L326
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L499
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	li	$2,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$22,$2,$L328
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

$L499:
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L326
	li	$2,17			# 0x11
	.set	macro
	.set	reorder

	bne	$22,$2,$L326
$L328:
	lw	$5,32($16)
	lw	$6,12($18)
	lbu	$7,1($18)
	lw	$2,24($19)
	move	$4,$19
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
	bne	$2,$0,$L269
	move	$3,$0
	.set	macro
	.set	reorder

	lw	$3,28($19)
	#nop
	lw	$2,48($3)
	#nop
	bne	$2,$0,$L333
	lw	$2,44($3)
	#nop
	beq	$2,$0,$L489
$L333:
	lw	$2,72($3)
	lw	$3,84($19)
	#nop
	sltu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L489
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L337
	addiu	$17,$23,16
	.set	macro
	.set	reorder

	lhu	$3,6($23)
	addiu	$2,$23,6
	move	$17,$0
	movn	$17,$2,$3		#RLX4181/RLX4281:conditional move  
$L337:
	lw	$2,32($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L340
	xor	$2,$21,$20
	.set	macro
	.set	reorder

	lhu	$8,4($18)
	srl	$3,$2,16
	xor	$3,$3,$8
	xor	$2,$2,$3
	lui	$4,%hi(udp_cache_list_free)
	srl	$3,$2,8
	andi	$6,$22,0x00ff
	lw	$7,%lo(udp_cache_list_free)($4)
	xor	$3,$3,$6
	xor	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$7,$0,$L343
	andi	$9,$2,0x3f
	.set	macro
	.set	reorder

$L489:
	lw	$4,28($19)
	jal	dst_release
	move	$3,$0
	.set	noreorder
	.set	nomacro
	j	$L269
	sw	$0,28($19)
	.set	macro
	.set	reorder

$L343:
	lw	$5,48($7)
	li	$2,1
	sh	$8,2($7)
	sw	$21,4($7)
	sw	$20,8($7)
	sb	$6,1($7)
	sh	$11,12($7)
	sh	$10,14($7)
	sb	$2,0($7)
	lw	$3,52($7)
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L346
	addiu	$2,$4,%lo(udp_cache_list_free)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L347
	sw	$3,52($5)
	.set	macro
	.set	reorder

$L346:
	sw	$3,4($2)
$L347:
	lw	$3,52($7)
	lw	$2,48($7)
	addiu	$4,$4,%lo(udp_cache_list_free)
	lui	$5,%hi(udp_cache_table)
	sw	$2,0($3)
	lw	$2,8($4)
	sll	$3,$9,1
	addu	$3,$3,$9
	addiu	$2,$2,-1
	sw	$2,8($4)
	sw	$0,40($7)
	lw	$2,%lo(udp_cache_table)($5)
	sll	$3,$3,2
	addiu	$6,$7,40
	addu	$2,$3,$2
	lw	$2,4($2)
	addiu	$4,$7,16
	sw	$2,44($7)
	lw	$2,%lo(udp_cache_table)($5)
	#nop
	addu	$2,$3,$2
	lw	$2,4($2)
	#nop
	sw	$7,0($2)
	lw	$2,%lo(udp_cache_table)($5)
	#nop
	addu	$2,$3,$2
	sw	$6,4($2)
	lw	$2,%lo(udp_cache_table)($5)
	#nop
	addu	$3,$3,$2
	lw	$2,8($3)
	#nop
	addiu	$2,$2,1
	sw	$2,8($3)
	lui	$2,%hi(jiffies)
	lw	$2,%lo(jiffies)($2)
	#nop
	addiu	$2,$2,1000
	.set	noreorder
	.set	nomacro
	jal	add_timer
	sw	$2,24($7)
	.set	macro
	.set	reorder

	j	$L349
$L340:
	lw	$3,36($sp)
	#nop
	beq	$3,$0,$L349
	.set	noreorder
	.set	nomacro
	jal	del_timer
	addiu	$4,$fp,16
	.set	macro
	.set	reorder

	lw	$2,8($fp)
	lw	$3,4($fp)
	lhu	$4,2($fp)
	lbu	$5,1($fp)
	xor	$3,$3,$2
	srl	$2,$3,16
	xor	$2,$2,$4
	xor	$3,$3,$2
	srl	$2,$3,8
	lw	$4,40($fp)
	xor	$2,$2,$5
	xor	$3,$3,$2
	sb	$0,0($fp)
	lw	$6,44($fp)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L353
	andi	$5,$3,0x3f
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L354
	sw	$6,44($4)
	.set	macro
	.set	reorder

$L353:
	lui	$2,%hi(udp_cache_table)
	lw	$3,%lo(udp_cache_table)($2)
	sll	$2,$5,1
	addu	$2,$2,$5
	sll	$2,$2,2
	addu	$2,$2,$3
	sw	$6,4($2)
$L354:
	lw	$4,44($fp)
	lw	$3,40($fp)
	sll	$2,$5,1
	addu	$2,$2,$5
	sw	$3,0($4)
	lui	$3,%hi(udp_cache_table)
	lw	$3,%lo(udp_cache_table)($3)
	sll	$2,$2,2
	lui	$4,%hi(udp_cache_list_free)
	addu	$2,$2,$3
	lw	$3,8($2)
	addiu	$4,$4,%lo(udp_cache_list_free)
	addiu	$3,$3,-1
	sw	$3,8($2)
	sw	$0,48($fp)
	lw	$2,4($4)
	addiu	$3,$fp,48
	sw	$2,52($fp)
	lw	$2,4($4)
	#nop
	sw	$fp,0($2)
	lw	$2,8($4)
	sw	$3,4($4)
	addiu	$2,$2,1
	sw	$2,8($4)
$L349:
	lbu	$3,1($16)
	#nop
	sltu	$2,$3,13
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L418
	sll	$2,$3,2
	.set	macro
	.set	reorder

	lui	$3,%hi($L441)
	addiu	$3,$3,%lo($L441)
	addu	$2,$2,$3
	lw	$2,0($2)
	#nop
	j	$2
	.rdata
	.align	2
$L441:
	.word	$L358
	.word	$L360
	.word	$L375
	.word	$L375
	.word	$L389
	.word	$L418
	.word	$L418
	.word	$L418
	.word	$L404
	.word	$L418
	.word	$L418
	.word	$L418
	.word	$L404
	.section	.text.FastPath_Enter
$L360:
	lw	$6,12($18)
	lw	$3,24($16)
	lhu	$4,10($18)
	srl	$2,$6,16
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	subu	$5,$5,$3
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L362
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
	j	$L361
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L362:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L361:
	lw	$4,28($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L379
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L365
	andi	$5,$6,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L379
	lhu	$5,0($17)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L379
	srl	$3,$6,16
	.set	macro
	.set	reorder

	lw	$2,24($16)
	andi	$4,$6,0xffff
	addu	$4,$4,$3
	andi	$3,$2,0xffff
	subu	$4,$4,$3
	srl	$2,$2,16
	subu	$4,$4,$2
	addu	$4,$4,$5
	.set	noreorder
	.set	nomacro
	bgez	$4,$L368
	sra	$3,$4,16
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L482
	nor	$2,$0,$4
	.set	macro
	.set	reorder

$L368:
	andi	$2,$4,0xffff
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L379
	sh	$4,0($17)
	.set	macro
	.set	reorder

$L365:
	lw	$2,24($16)
	srl	$3,$6,16
	addu	$5,$5,$3
	lhu	$4,0($17)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	subu	$5,$5,$2
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L372
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
$L482:
	.set	noreorder
	.set	nomacro
	j	$L379
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L372:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L379
	sh	$5,0($17)
	.set	macro
	.set	reorder

$L375:
	lw	$6,12($18)
	lw	$3,24($16)
	lhu	$4,10($18)
	srl	$2,$6,16
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	subu	$5,$5,$3
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L377
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
	j	$L376
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L377:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L376:
	lw	$2,28($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L379
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L380
	andi	$5,$6,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L385
	lhu	$7,0($17)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$7,$0,$L385
	srl	$3,$6,16
	.set	macro
	.set	reorder

	lw	$2,24($16)
	andi	$5,$6,0xffff
	addu	$5,$5,$3
	lhu	$4,0($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,28($16)
	subu	$5,$5,$2
	addu	$5,$5,$4
	subu	$5,$5,$3
	.set	noreorder
	.set	nomacro
	j	$L490
	addu	$5,$5,$7
	.set	macro
	.set	reorder

$L380:
	lw	$2,24($16)
	srl	$3,$6,16
	addu	$5,$5,$3
	lhu	$4,0($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,28($16)
	subu	$5,$5,$2
	lhu	$2,0($17)
	addu	$5,$5,$4
	subu	$5,$5,$3
	addu	$5,$5,$2
$L490:
	.set	noreorder
	.set	nomacro
	bgez	$5,$L387
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
	j	$L385
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L387:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,0($17)
$L385:
	lw	$2,28($16)
	#nop
	sh	$2,0($23)
$L379:
	lw	$2,24($16)
	.set	noreorder
	.set	nomacro
	j	$L358
	sw	$2,12($18)
	.set	macro
	.set	reorder

$L389:
	lw	$6,16($18)
	lw	$3,32($16)
	lhu	$4,10($18)
	srl	$2,$6,16
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	subu	$5,$5,$3
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L391
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
	j	$L390
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L391:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L390:
	lw	$3,28($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L487
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L394
	andi	$5,$6,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L487
	lhu	$5,0($17)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L487
	srl	$3,$6,16
	.set	macro
	.set	reorder

	lw	$2,32($16)
	andi	$4,$6,0xffff
	addu	$4,$4,$3
	andi	$3,$2,0xffff
	subu	$4,$4,$3
	srl	$2,$2,16
	subu	$4,$4,$2
	addu	$4,$4,$5
	.set	noreorder
	.set	nomacro
	bgez	$4,$L397
	sra	$3,$4,16
	.set	macro
	.set	reorder

	subu	$4,$0,$4
	sra	$2,$4,16
	andi	$3,$4,0xffff
	addu	$4,$2,$3
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L484
	nor	$2,$0,$4
	.set	macro
	.set	reorder

$L397:
	andi	$2,$4,0xffff
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	.set	noreorder
	.set	nomacro
	j	$L487
	sh	$4,0($17)
	.set	macro
	.set	reorder

$L394:
	lw	$2,32($16)
	srl	$3,$6,16
	addu	$5,$5,$3
	lhu	$4,0($17)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	subu	$5,$5,$2
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L401
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
$L484:
	.set	noreorder
	.set	nomacro
	j	$L487
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L401:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	.set	noreorder
	.set	nomacro
	j	$L487
	sh	$5,0($17)
	.set	macro
	.set	reorder

$L404:
	lw	$6,16($18)
	lw	$3,32($16)
	lhu	$4,10($18)
	srl	$2,$6,16
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	subu	$5,$5,$3
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L406
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
	j	$L405
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L406:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L405:
	lw	$4,28($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L487
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L409
	andi	$5,$6,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L414
	lhu	$7,0($17)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$7,$0,$L414
	srl	$3,$6,16
	.set	macro
	.set	reorder

	lw	$2,32($16)
	andi	$5,$6,0xffff
	addu	$5,$5,$3
	lhu	$4,2($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,36($16)
	subu	$5,$5,$2
	addu	$5,$5,$4
	subu	$5,$5,$3
	.set	noreorder
	.set	nomacro
	j	$L491
	addu	$5,$5,$7
	.set	macro
	.set	reorder

$L409:
	lw	$2,32($16)
	srl	$3,$6,16
	addu	$5,$5,$3
	lhu	$4,2($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,36($16)
	subu	$5,$5,$2
	lhu	$2,0($17)
	addu	$5,$5,$4
	subu	$5,$5,$3
	addu	$5,$5,$2
$L491:
	.set	noreorder
	.set	nomacro
	bgez	$5,$L416
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
	j	$L414
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L416:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,0($17)
$L414:
	lw	$2,36($16)
	.set	noreorder
	.set	nomacro
	j	$L487
	sh	$2,2($23)
	.set	macro
	.set	reorder

$L418:
	lw	$6,12($18)
	lw	$3,24($16)
	lhu	$4,10($18)
	srl	$2,$6,16
	andi	$5,$6,0xffff
	addu	$5,$5,$2
	andi	$2,$3,0xffff
	subu	$5,$5,$2
	srl	$3,$3,16
	subu	$5,$5,$3
	addu	$5,$5,$4
	.set	noreorder
	.set	nomacro
	bgez	$5,$L420
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
	j	$L419
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L420:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,10($18)
$L419:
	lw	$4,16($18)
	lw	$3,32($16)
	lhu	$5,10($18)
	srl	$2,$4,16
	andi	$4,$4,0xffff
	addu	$4,$4,$2
	andi	$2,$3,0xffff
	subu	$4,$4,$2
	srl	$3,$3,16
	subu	$4,$4,$3
	addu	$4,$4,$5
	.set	noreorder
	.set	nomacro
	bgez	$4,$L423
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
	j	$L422
	sh	$2,10($18)
	.set	macro
	.set	reorder

$L423:
	sra	$3,$4,16
	addu	$4,$3,$2
	sra	$2,$4,16
	addu	$4,$4,$2
	sh	$4,10($18)
$L422:
	lw	$2,28($sp)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L425
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	lw	$3,4($16)
	#nop
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L426
	andi	$5,$6,0xffff
	.set	macro
	.set	reorder

	beq	$17,$0,$L434
	lhu	$7,0($17)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$7,$0,$L434
	srl	$3,$6,16
	.set	macro
	.set	reorder

	lw	$2,24($16)
	andi	$5,$6,0xffff
	addu	$5,$5,$3
	lhu	$4,0($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,28($16)
	subu	$5,$5,$2
	addu	$5,$5,$4
	subu	$5,$5,$3
	.set	noreorder
	.set	nomacro
	j	$L495
	addu	$5,$5,$7
	.set	macro
	.set	reorder

$L426:
	lw	$2,24($16)
	srl	$3,$6,16
	addu	$5,$5,$3
	lhu	$4,0($23)
	andi	$3,$2,0xffff
	subu	$5,$5,$3
	srl	$2,$2,16
	lw	$3,28($16)
	subu	$5,$5,$2
	lhu	$2,0($17)
	addu	$5,$5,$4
	subu	$5,$5,$3
	addu	$5,$5,$2
$L495:
	.set	noreorder
	.set	nomacro
	bgez	$5,$L436
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
	j	$L435
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L436:
	sra	$3,$5,16
	addu	$5,$3,$2
	sra	$2,$5,16
	addu	$5,$5,$2
	sh	$5,0($17)
$L435:
	lw	$4,16($18)
	lw	$3,32($16)
	lhu	$5,2($23)
	srl	$2,$4,16
	andi	$6,$4,0xffff
	addu	$6,$6,$2
	andi	$2,$3,0xffff
	subu	$6,$6,$2
	srl	$3,$3,16
	lw	$4,36($16)
	subu	$6,$6,$3
	lhu	$2,0($17)
	addu	$6,$6,$5
	subu	$6,$6,$4
	addu	$6,$6,$2
	.set	noreorder
	.set	nomacro
	bgez	$6,$L439
	andi	$2,$6,0xffff
	.set	macro
	.set	reorder

	subu	$6,$0,$6
	sra	$2,$6,16
	andi	$3,$6,0xffff
	addu	$6,$2,$3
	sra	$2,$6,16
	addu	$6,$6,$2
	nor	$2,$0,$6
	.set	noreorder
	.set	nomacro
	j	$L434
	sh	$2,0($17)
	.set	macro
	.set	reorder

$L439:
	sra	$3,$6,16
	addu	$6,$3,$2
	sra	$2,$6,16
	addu	$6,$6,$2
	sh	$6,0($17)
$L434:
	lw	$2,28($16)
	#nop
	sh	$2,0($23)
	lw	$2,36($16)
	#nop
	sh	$2,2($23)
$L425:
	lw	$2,24($16)
	#nop
	sw	$2,12($18)
$L487:
	lw	$2,32($16)
	#nop
	sw	$2,16($18)
$L358:
	lw	$3,104($19)
	li	$2,-805371904			# 0xffffffffcfff0000
	ori	$2,$2,0xffff
	lw	$4,28($19)
	and	$3,$3,$2
	sw	$3,104($19)
	lw	$2,12($4)
	#nop
	sw	$2,24($19)
	lbu	$3,2($16)
	li	$2,1			# 0x1
	bne	$3,$2,$L442
	lw	$2,156($19)
	lw	$3,32($16)
	lw	$2,16($2)
	j	$L494
$L442:
	lw	$3,16($18)
	lw	$2,24($16)
	#nop
$L494:
	bne	$3,$2,$L448
	lw	$2,48($16)
	.set	noreorder
	.set	nomacro
	j	$L497
	sw	$2,144($19)
	.set	macro
	.set	reorder

$L448:
	lw	$2,52($16)
	#nop
	sw	$2,144($19)
$L497:
	lui	$2,%hi(jiffies)
	lw	$2,%lo(jiffies)($2)
	lui	$3,%hi(fast_l2tp_fw)
	sw	$2,40($16)
	lw	$2,%lo(fast_l2tp_fw)($3)
	#nop
	beq	$2,$0,$L450
	lw	$4,24($19)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L450
	lui	$5,%hi($LC2)
	.set	macro
	.set	reorder

	addiu	$5,$5,%lo($LC2)
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,4			# 0x4
	.set	macro
	.set	reorder

	bne	$2,$0,$L450
	.set	noreorder
	.set	nomacro
	jal	fast_l2tp_to_wan
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L269
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L450:
	lw	$2,28($19)
	#nop
	lw	$16,48($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L452
	addiu	$5,$16,20
	.set	macro
	.set	reorder

	lw	$4,176($19)
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
	#nop
	beq	$2,$0,$L453
	.set	noreorder
	.set	nomacro
	jal	l2tp_tx_id
	move	$4,$19
	.set	macro
	.set	reorder

$L453:
	lw	$4,24($19)
	#nop
	lw	$2,196($4)
	#nop
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L462
	lui	$2,%hi(gQosEnabled)
	.set	macro
	.set	reorder

	lw	$2,%lo(gQosEnabled)($2)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L455
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
	j	$L269
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L455:
	lhu	$3,202($4)
	#nop
	bne	$3,$2,$L458
	lw	$5,176($19)
	.set	noreorder
	.set	nomacro
	jal	__br_fdb_get
	addiu	$4,$4,704
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L458
	move	$5,$2
	.set	macro
	.set	reorder

	lw	$3,24($19)
	#nop
	lw	$2,84($3)
	#nop
	addiu	$2,$2,1
	sw	$2,84($3)
	lw	$4,24($19)
	lw	$3,84($19)
	lw	$2,92($4)
	#nop
	addu	$2,$2,$3
	sw	$2,92($4)
	lw	$2,8($5)
	#nop
	lw	$2,4($2)
	#nop
	sw	$2,24($19)
$L458:
	lw	$5,24($19)
	#nop
	lw	$2,184($5)
	#nop
	lw	$2,16($2)
	#nop
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$19
	.set	macro
	.set	reorder

	bne	$2,$0,$L462
	.set	noreorder
	.set	nomacro
	j	$L269
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L452:
	lw	$2,44($2)
	#nop
	beq	$2,$0,$L462
	lw	$2,76($2)
	#nop
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L269
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L462:
	.set	noreorder
	.set	nomacro
	jal	kfree_skb
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L269
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L326:
	lw	$16,64($16)
	j	$L481
$L474:
	lw	$2,24($19)
	#nop
	sw	$2,140($19)
$L269:
	lui	$4,%hi(fast_pptp_fw)
	lw	$2,%lo(fast_pptp_fw)($4)
	#nop
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L260
	move	$16,$3
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	#nop
	lw	$2,156($4)
	#nop
	lbu	$3,9($2)
	li	$2,47			# 0x2f
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$2,84($4)
	#nop
	sltu	$2,$2,21
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	lui	$2,%hi(pptp_tcp_finished)
	lw	$3,%lo(pptp_tcp_finished)($2)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	jal	Check_GRE_rx_net_device
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L496
	move	$2,$16
	.set	macro
	.set	reorder

	lw	$4,24($sp)
	jal	fast_pptp_sync_rx_seq
$L260:
	move	$2,$16
$L496:
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
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	sw	$31,32($sp)
	lui	$2,%hi(fast_nat_fw)
	lw	$2,%lo(fast_nat_fw)($2)
	move	$19,$5
	lui	$5,%hi($LC3)
	move	$17,$6
	addiu	$5,$5,%lo($LC3)
	addiu	$6,$2,10
	move	$16,$7
	jal	sprintf
	move	$18,$4

	subu	$4,$2,$17
	addu	$3,$17,$16
	slt	$3,$3,$2
	slt	$2,$16,$4
	movn	$4,$16,$2		#RLX4181/RLX4281:conditional move
	addu	$18,$18,$17
	bne	$3,$0,$L501
	slt	$5,$4,0

	lw	$2,56($sp)
	li	$3,1			# 0x1
	sw	$3,0($2)
$L501:
	sw	$18,0($19)
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	movz	$2,$4,$5		#RLX4181/RLX4281:conditional move  
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
	sw	$31,108($sp)
	sw	$17,100($sp)
	sw	$16,96($sp)
	move	$18,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L504
	li	$3,-14			# 0xfffffffffffffff2
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
	li	$3,-14			# 0xfffffffffffffff2
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
$L523:
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
	j	$L523
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
	li	$3,-14			# 0xfffffffffffffff2
$L504:
	lw	$31,108($sp)
	lw	$18,104($sp)
	lw	$17,100($sp)
	lw	$16,96($sp)
	move	$2,$3
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
	
$L529:
$L570:
	addiu	$sp,$sp,-72
	sw	$19,60($sp)
	lui	$19,%hi(malloc_sizes)
	sw	$16,48($sp)
	sw	$31,64($sp)
	sw	$18,56($sp)
	sw	$17,52($sp)
	addiu	$2,$19,%lo(malloc_sizes)
	lw	$4,92($2)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	lui	$16,%hi(table_napt)

	sw	$2,%lo(table_napt)($16)
	move	$5,$16
	beq	$2,$0,$L524
	li	$3,-1			# 0xffffffffffffffff

	lui	$2,%hi(napt_list_inuse)
	lui	$17,%hi(napt_list_free)
	addiu	$3,$2,%lo(napt_list_inuse)
	addiu	$4,$17,%lo(napt_list_free)
	sw	$3,4($3)
	sw	$0,8($3)
	sw	$0,%lo(napt_list_inuse)($2)
	sw	$4,4($4)
	sw	$0,8($4)
	sw	$0,%lo(napt_list_free)($17)
	move	$3,$0
	li	$16,1023			# 0x3ff
$L580:
	lw	$2,%lo(table_napt)($5)
	addiu	$16,$16,-1
	addu	$2,$3,$2
	sw	$0,8($2)
	lw	$2,%lo(table_napt)($5)
	nop
	addu	$2,$3,$2
	sw	$0,0($2)
	lw	$2,%lo(table_napt)($5)
	nop
	addu	$2,$3,$2
	sw	$2,4($2)
	bgez	$16,$L580
	addiu	$3,$3,12

	move	$16,$0
$L634:
$L588:
$L629:
	addiu	$18,$19,%lo(malloc_sizes)
	lw	$4,12($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	addiu	$16,$16,1

	move	$3,$2
	addiu	$4,$17,%lo(napt_list_free)
	addiu	$5,$2,44
	beq	$2,$0,$L870
	slt	$6,$16,1024

	sw	$0,44($2)
	lw	$2,4($4)
	nop
	sw	$2,48($3)
	lw	$2,4($4)
	nop
	sw	$3,0($2)
	lw	$2,8($4)
	sw	$5,4($4)
	addiu	$2,$2,1
	bne	$6,$0,$L634
	sw	$2,8($4)

$L639:
$L680:
	lw	$4,92($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	lui	$16,%hi(table_path)

	sw	$2,%lo(table_path)($16)
	move	$5,$16
	beq	$2,$0,$L524
	li	$3,-1			# 0xffffffffffffffff

	lui	$2,%hi(path_list_inuse)
	lui	$17,%hi(path_list_free)
	addiu	$3,$2,%lo(path_list_inuse)
	addiu	$4,$17,%lo(path_list_free)
	sw	$3,4($3)
	sw	$0,8($3)
	sw	$0,%lo(path_list_inuse)($2)
	sw	$4,4($4)
	sw	$0,8($4)
	sw	$0,%lo(path_list_free)($17)
	move	$3,$0
	li	$16,1023			# 0x3ff
$L690:
	lw	$2,%lo(table_path)($5)
	addiu	$16,$16,-1
	addu	$2,$3,$2
	sw	$0,8($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	sw	$0,0($2)
	lw	$2,%lo(table_path)($5)
	nop
	addu	$2,$3,$2
	sw	$2,4($2)
	bgez	$16,$L690
	addiu	$3,$3,12

	move	$16,$0
$L744:
$L698:
$L739:
	addiu	$18,$19,%lo(malloc_sizes)
	lw	$4,20($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	addiu	$16,$16,1

	move	$3,$2
	addiu	$4,$17,%lo(path_list_free)
	addiu	$5,$2,72
	beq	$2,$0,$L870
	slt	$6,$16,2048

	sw	$0,72($2)
	lw	$2,4($4)
	nop
	sw	$2,76($3)
	lw	$2,4($4)
	nop
	sw	$3,0($2)
	lw	$2,8($4)
	sw	$5,4($4)
	addiu	$2,$2,1
	bne	$6,$0,$L744
	sw	$2,8($4)

$L750:
$L791:
	lw	$4,60($18)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	lui	$16,%hi(udp_cache_table)

	beq	$2,$0,$L872
	sw	$2,%lo(udp_cache_table)($16)

	lui	$18,%hi(udp_cache_list_free)
	addiu	$2,$18,%lo(udp_cache_list_free)
	sw	$2,4($2)
	sw	$0,8($2)
	sw	$0,%lo(udp_cache_list_free)($18)
	move	$3,$0
	li	$17,63			# 0x3f
$L801:
	lw	$2,%lo(udp_cache_table)($16)
	addiu	$17,$17,-1
	addu	$2,$3,$2
	sw	$0,8($2)
	lw	$2,%lo(udp_cache_table)($16)
	nop
	addu	$2,$3,$2
	sw	$0,0($2)
	lw	$2,%lo(udp_cache_table)($16)
	nop
	addu	$2,$3,$2
	sw	$2,4($2)
	bgez	$17,$L801
	addiu	$3,$3,12

	move	$17,$0
$L855:
$L809:
$L850:
	addiu	$2,$19,%lo(malloc_sizes)
	lw	$4,12($2)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	addiu	$17,$17,1

	move	$16,$2
	addiu	$4,$2,16
	move	$5,$0
	beq	$2,$0,$L872
	move	$6,$0

	jal	init_timer_key
	nop

	lui	$2,%hi(cache_timeout)
	addiu	$2,$2,%lo(cache_timeout)
	sw	$2,28($16)
	sw	$16,32($16)
	sw	$0,48($16)
	addiu	$3,$18,%lo(udp_cache_list_free)
	lw	$2,4($3)
	addiu	$4,$16,48
	slt	$5,$17,64
	sw	$2,52($16)
	lw	$2,4($3)
	nop
	sw	$16,0($2)
	lw	$2,8($3)
	sw	$4,4($3)
	addiu	$2,$2,1
	bne	$5,$0,$L855
	sw	$2,8($3)

	j	$L873
	nop

$L872:
	j	$L524
	li	$3,-1			# 0xffffffffffffffff

$L870:
	j	$L524
	li	$3,-2			# 0xfffffffffffffffe

$L873:
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
	beq	$2,$0,$L856
	sw	$2,%lo(res1)($4)

	lui	$2,%hi(read_proc)
	addiu	$2,$2,%lo(read_proc)
	sw	$2,64($3)
	lw	$3,%lo(res1)($4)
	lui	$2,%hi(write_proc)
	addiu	$2,$2,%lo(write_proc)
	sw	$2,68($3)
$L856:
	move	$3,$0
$L524:
	lw	$31,64($sp)
	lw	$19,60($sp)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	move	$2,$3
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
	jal	filter_exit
	sw	$16,16($sp)

	jal	fast_pptp_exit
	lui	$16,%hi(res1)

	lw	$2,%lo(res1)($16)
	lui	$4,%hi($LC5)
	addiu	$4,$4,%lo($LC5)
	beq	$2,$0,$L874
	move	$5,$2

	jal	remove_proc_entry
	nop

	sw	$0,%lo(res1)($16)
$L874:
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
