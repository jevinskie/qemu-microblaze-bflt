#ifndef LINUX_USER_MICROBLAZE_TARGET_FLAT_H
#define LINUX_USER_MICROBLAZE_TARGET_FLAT_H

#define MICROBLAZE_REL_MASK 0x7FFFFFFF

#define flat_argvp_envp_on_stack()                           1
#define flat_reloc_valid(reloc, size)                        ((reloc) <= (size))
#define flat_old_ram_flag(flag)                              (flag)
// #define flat_get_relocate_addr(relval)                       ((relval) & MICROBLAZE_REL_MASK)
#define flat_get_relocate_addr(relval)                       (ntohl((relval)))
#define flat_get_addr_from_rp(rp, relval, flags, persistent) (rp)
#define flat_set_persistent(relval, persistent)              (*persistent)
// #define flat_put_addr_at_rp(rp, addr, relval)                put_user_ual(addr, rp)

static int flat_put_addr_at_rp(abi_ulong rp, abi_ulong addr, abi_ulong relval) {
	if (ntohl(relval) & 0x80000000) {
		abi_ulong inst_hi, inst_lo;
        if (get_user_ual(inst_hi, rp)) {
            printf("64 bit reloc write bad get inst_hi rp\n");
            return -EFAULT;
        }
        if (get_user_ual(inst_lo, rp + 4)) {
            printf("64 bit reloc write bad get inst_lo rp + 4\n");
            return -EFAULT;
        }
        printf("origs inst_hi: 0x%08x inst_lo: 0x%08x\n", inst_hi, inst_lo);
        inst_hi = (inst_hi & 0xFFFF0000) | (addr >> 16);
        inst_lo = (inst_lo & 0xFFFF0000) | (addr & 0xFFFF);
        printf("news inst_hi: 0x%08x inst_lo: 0x%08x\n", inst_hi, inst_lo);
        if (put_user_ual(inst_hi, rp)) {
            printf("64 bit reloc write bad put inst_hi rp\n");
            return -EFAULT;
        }
        if (put_user_ual(inst_hi, rp)) {
            printf("64 bit reloc write bad put inst_hi rp\n");
            return -EFAULT;
        }
	} else {
		abi_ulong orig_addr;
		if (get_user_ual(orig_addr, rp)) {
            printf("32 bit reloc write bad get orig_addr rp\n");
            return -EFAULT;
        }
        printf("32 bit reloc write orig_addr: 0x%08x new_addr: 0x%08x\n", orig_addr, addr);
        if (put_user_ual(addr, rp)) {
            printf("32 bit reloc write bad put addr rp\n");
            return -EFAULT;
        }
	}
	return 0;
}

#endif
