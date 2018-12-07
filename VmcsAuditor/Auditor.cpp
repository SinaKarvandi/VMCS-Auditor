

// This file is forked from Bochs implementation of VMX as part of 
// checking for Hypervisor From Scratch
// You can use it in your hypervisor driver to check the states
// before executing VMLAUNCH
#include "pch.h"
#include <iostream>
#include <sstream>
#include <string>
///
/// Global Variables
///

UINT32 vmx_pin_vmexec_ctrl_supported_bits;
UINT32 vmx_proc_vmexec_ctrl_supported_bits;
UINT32 vmx_vmexec_ctrl2_supported_bits;
UINT32 vmx_vmexit_ctrl_supported_bits;
UINT32 vmx_vmentry_ctrl_supported_bits;
UINT64 vmx_ept_vpid_cap_supported_bits;
UINT64 vmx_vmfunc_supported_bits;
UINT32 cr0_suppmask_0;
UINT32 cr0_suppmask_1;
UINT32 cr4_suppmask_0;
UINT32 cr4_suppmask_1;
UINT32 vmx_extensions_bitmask;


Bit64u efer_suppmask = 0;


BxExceptionInfo exceptions_info[32] = {
	/* DE */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 0 },
	/* DB */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 02 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* BP */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
	/* OF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
	/* BR */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* UD */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* NM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* DF */ { BX_ET_DOUBLE_FAULT, BX_EXCEPTION_CLASS_FAULT, 1 },
	/* 09 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* TS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
	/* NP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
	/* SS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
	/* GP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
	/* PF */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 1 },
	/* 15 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* MF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* AC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 1 },
	/* MC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_ABORT, 0 },
	/* XM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* VE */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 21 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 22 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 23 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 24 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 25 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 26 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 27 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 28 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 29 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 30 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
	/* 31 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }
};

////////////////////////////////////////////////////////////





uint64_t ReadInputAuditor(const char* Message, int64_t DefaultValue){
	std::cout << Message << " [ Default : 0x" << DefaultValue << " ]" << endl;

	string numberstr = std::to_string(DefaultValue);
	int64_t number = DefaultValue;
	std::string input;
	std::getline(std::cin, input);
	if (!input.empty()) {
		std::istringstream stream(input);

		stream >> numberstr;
	}

	std::stringstream ss;
	ss << std::hex << numberstr;
	ss >> number;

	cout << endl << "  =======>  " << Message << " Set to : " << std::hex << number << endl;
	return number;

}


void VMexit(Bit32u reason, Bit64u qualification) {

	printf("\n\n[*] The following configuration will cause VM-Exit with reason (0x%x) and Exit-Qualification (%lx).\n", reason, qualification);
}

void VMfail(Bit32u error_code)
{
	printf("\n\n[*] VMFail called with code (0x%x).\n", error_code);
}

bx_bool IsValidPhyAddr(bx_phy_address addr)
{
	return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

bx_bool CheckPDPTR(Bit64u *pdptr)
{
	for (unsigned n = 0; n < 4; n++) {
		if (pdptr[n] & 0x1) {
			if (pdptr[n] & PAGING_PAE_PDPTE_RESERVED_BITS) return 0;
		}
	}

	return 1; /* PDPTRs are fine */
}

bx_bool long_mode()
{
#if BX_SUPPORT_X86_64
	//We're definitely in long-mode when we reach here in our driver
	return 1;
#else
	return 0;
#endif
}

void init_vmx_extensions_bitmask()
{
	Bit32u features_bitmask = 0;

	features_bitmask |= BX_VMX_VIRTUAL_NMI;

#if BX_SUPPORT_X86_64
	static bx_bool x86_64_enabled = TRUE;
	if (x86_64_enabled) {
		features_bitmask |= BX_VMX_TPR_SHADOW |
			BX_VMX_APIC_VIRTUALIZATION |
			BX_VMX_WBINVD_VMEXIT;

#if BX_SUPPORT_VMX >= 2
		features_bitmask |= BX_VMX_PREEMPTION_TIMER |
			BX_VMX_PAT |
			BX_VMX_EFER |
			BX_VMX_EPT |
			BX_VMX_VPID |
			BX_VMX_UNRESTRICTED_GUEST |
			BX_VMX_DESCRIPTOR_TABLE_EXIT |
			BX_VMX_X2APIC_VIRTUALIZATION |
			BX_VMX_PAUSE_LOOP_EXITING |
			BX_VMX_EPT_ACCESS_DIRTY |
			BX_VMX_VINTR_DELIVERY |
			BX_VMX_VMCS_SHADOWING |
			BX_VMX_EPTP_SWITCHING | BX_VMX_EPT_EXCEPTION;

		features_bitmask |= BX_VMX_SAVE_DEBUGCTL_DISABLE |
			/* BX_VMX_MONITOR_TRAP_FLAG | */ // not implemented yet
			BX_VMX_PERF_GLOBAL_CTRL;
#endif
	}
#endif
	vmx_extensions_bitmask = features_bitmask;

}




void parse_selector(Bit16u raw_selector, bx_selector_t *selector)
{
	selector->value = raw_selector;
	selector->index = raw_selector >> 3;
	selector->ti = (raw_selector >> 2) & 0x01;
	selector->rpl = raw_selector & 0x03;
}

bx_bool set_segment_ar_data(bx_segment_reg_t *seg, bx_bool valid,
	Bit16u raw_selector, bx_address base, Bit32u limit_scaled, Bit16u ar_data)
{
	parse_selector(raw_selector, &seg->selector);

	bx_descriptor_t *d = &seg->cache;

	d->p = (ar_data >> 7) & 0x1;
	d->dpl = (ar_data >> 5) & 0x3;
	d->segment = (ar_data >> 4) & 0x1;
	d->type = (ar_data & 0x0f);

	d->valid = valid;

	if (d->segment || !valid) { /* data/code segment descriptors */
		d->u.segment.g = (ar_data >> 15) & 0x1;
		d->u.segment.d_b = (ar_data >> 14) & 0x1;
#if BX_SUPPORT_X86_64
		d->u.segment.l = (ar_data >> 13) & 0x1;
#endif
		d->u.segment.avl = (ar_data >> 12) & 0x1;

		d->u.segment.base = base;
		d->u.segment.limit_scaled = limit_scaled;
	}
	else {
		switch (d->type) {
		case BX_SYS_SEGMENT_LDT:
		case BX_SYS_SEGMENT_AVAIL_286_TSS:
		case BX_SYS_SEGMENT_BUSY_286_TSS:
		case BX_SYS_SEGMENT_AVAIL_386_TSS:
		case BX_SYS_SEGMENT_BUSY_386_TSS:
			d->u.segment.avl = (ar_data >> 12) & 0x1;
			d->u.segment.d_b = (ar_data >> 14) & 0x1;
			d->u.segment.g = (ar_data >> 15) & 0x1;
			d->u.segment.base = base;
			d->u.segment.limit_scaled = limit_scaled;
			break;

		default:
			printf("\nset_segment_ar_data(): case %u unsupported, valid=%d", (unsigned)d->type, d->valid);
		}
	}

	return d->valid;
}
bx_bool is_eptptr_valid(Bit64u eptptr)
{
	// [2:0] EPT paging-structure memory type
	//       0 = Uncacheable (UC)
	//       6 = Write-back (WB)
	Bit32u memtype = eptptr & 7;
	if (memtype != BX_MEMTYPE_UC && memtype != BX_MEMTYPE_WB) return 0;

	// [5:3] This value is 1 less than the EPT page-walk length
	Bit32u walk_length = (eptptr >> 3) & 7;
	if (walk_length != 3) return 0;

	// [6]   EPT A/D Enable
	if (!BX_SUPPORT_VMX_EXTENSION(BX_VMX_EPT_ACCESS_DIRTY)) {
		if (eptptr & 0x40) {
			printf(("\nis_eptptr_valid: EPTPTR A/D enabled when not supported by CPU"));
			return 0;
		}
	}
}

bx_bool IsLimitAccessRightsConsistent(Bit32u limit, Bit32u ar)
{
	bx_bool g = (ar >> 15) & 1;

	// access rights reserved bits set
	if (ar & 0xfffe0f00) return 0;

	if (g) {
		// if any of the bits in limit[11:00] are '0 <=> G must be '0
		if ((limit & 0xfff) != 0xfff)
			return 0;
	}
	else {
		// if any of the bits in limit[31:20] are '1 <=> G must be '1
		if ((limit & 0xfff00000) != 0)
			return 0;
	}

	return 1;
}

#if BX_SUPPORT_X86_64
bx_bool IsCanonical(bx_address offset)
{
	return ((Bit64u)((((Bit64s)(offset)) >> (BX_LIN_ADDRESS_WIDTH - 1)) + 1) < 2);
}
#endif

BOOLEAN IsValidPageAlignedPhyAddr(bx_phy_address addr)
{
	return ((addr & (BX_PHY_ADDRESS_RESERVED_BITS | 0xfff)) == 0);
}


Bit32u rotate_r(Bit32u val_32)
{
	return (val_32 >> 8) | (val_32 << 24);
}

Bit32u vmx_from_ar_byte_rd(Bit32u ar_byte)
{
	return rotate_r(ar_byte);
}

bx_bool isMemTypeValidMTRR(unsigned memtype)
{
	switch (memtype) {
	case BX_MEMTYPE_UC:
	case BX_MEMTYPE_WC:
	case BX_MEMTYPE_WT:
	case BX_MEMTYPE_WP:
	case BX_MEMTYPE_WB:
		return BX_TRUE;
	default:
		return BX_FALSE;
	}
}

bx_bool isMemTypeValidPAT(unsigned memtype)
{
	return (memtype == 0x07) /* UC- */ || isMemTypeValidMTRR(memtype);
}

bx_bool isValidMSR_PAT(Bit64u pat_val)
{
	// use packed register as 64-bit value with convinient accessors
	BxPackedRegister pat_msr = pat_val;
	for (unsigned i = 0; i < 8; i++)
		if (!isMemTypeValidPAT(pat_msr.ubyte(i))) return BX_FALSE;

	return BX_TRUE;
}


VMX_error_code VMenterLoadCheckVmControls(VMCS_CACHE *vm)
{
	//VMCS_CACHE *vm = ExAllocatePoolWithTag(NonPagedPool, sizeof(VMCS_CACHE), POOLTAG);

   //
   // Load VM-execution control fields to VMCS Cache
   //

	//# vm->vmexec_ctrls1 = VMread32(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS);
	//# vm->vmexec_ctrls2 = VMread32(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS);

	vm->vmexec_ctrls1 = ReadInputAuditor("VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS", 0x0);
	vm->vmexec_ctrls2 = ReadInputAuditor("VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS", 0x0);


	//* if (VMEXIT(VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS)) {

	if (vm->vmexec_ctrls2 & (VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS)) {
		//# vm->vmexec_ctrls3 = VMread32(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS);
		vm->vmexec_ctrls3 = ReadInputAuditor("VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS ", 0x0);

	}
	else
		vm->vmexec_ctrls3 = 0;

	//# vm->vm_exceptions_bitmap = VMread32(VMCS_32BIT_CONTROL_EXECUTION_BITMAP);
	//# vm->vm_pf_mask = VMread32(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MASK);
	//# vm->vm_pf_match = VMread32(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MATCH);
	//# vm->vm_cr0_mask = VMread_natural(VMCS_CONTROL_CR0_GUEST_HOST_MASK);
	//# vm->vm_cr4_mask = VMread_natural(VMCS_CONTROL_CR4_GUEST_HOST_MASK);
	//# vm->vm_cr0_read_shadow = VMread_natural(VMCS_CONTROL_CR0_READ_SHADOW);
	//# vm->vm_cr4_read_shadow = VMread_natural(VMCS_CONTROL_CR4_READ_SHADOW);
	//# vm->vm_cr3_target_cnt = VMread32(VMCS_32BIT_CONTROL_CR3_TARGET_COUNT);

	vm->vm_exceptions_bitmap = ReadInputAuditor("VMCS_32BIT_CONTROL_EXECUTION_BITMAP ", 0x0);
	vm->vm_pf_mask = ReadInputAuditor("VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MASK ", 0x0);
	vm->vm_pf_match = ReadInputAuditor("VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MATCH ", 0x0);
	vm->vm_cr0_mask = ReadInputAuditor("VMCS_CONTROL_CR0_GUEST_HOST_MASK ", 0x0);
	vm->vm_cr4_mask = ReadInputAuditor("VMCS_CONTROL_CR4_GUEST_HOST_MASK ", 0x0);
	vm->vm_cr0_read_shadow = ReadInputAuditor("VMCS_CONTROL_CR0_READ_SHADOW ", 0x0);
	vm->vm_cr4_read_shadow = ReadInputAuditor("VMCS_CONTROL_CR4_READ_SHADOW ", 0x0);
	vm->vm_cr3_target_cnt = ReadInputAuditor("VMCS_32BIT_CONTROL_CR3_TARGET_COUNT ", 0x0);


	for (int n = 0; n < VMX_CR3_TARGET_MAX_CNT; n++) {

		if (n == 0)
		{
			//* vm->vm_cr3_target_value[n] = VMread_natural(VMCS_CR3_TARGET0 + 2 * n);
			vm->vm_cr3_target_value[n] = ReadInputAuditor("VMCS_CR3_TARGET0 ", 0x0);
		}
		if (n == 1)
		{
			//* vm->vm_cr3_target_value[n] = VMread_natural(VMCS_CR3_TARGET0 + 2 * n);
			vm->vm_cr3_target_value[n] = ReadInputAuditor("VMCS_CR3_TARGET1 ", 0x0);
		}
		if (n == 2)
		{
			//* vm->vm_cr3_target_value[n] = VMread_natural(VMCS_CR3_TARGET0 + 2 * n);
			vm->vm_cr3_target_value[n] = ReadInputAuditor("VMCS_CR3_TARGET2 ", 0x0);
		}
		if (n == 3)
		{
			//* vm->vm_cr3_target_value[n] = VMread_natural(VMCS_CR3_TARGET0 + 2 * n);
			vm->vm_cr3_target_value[n] = ReadInputAuditor("VMCS_CR3_TARGET3 ", 0x0);
		}

	}

	//
	// Check VM-execution control fields
	//

	if (~vm->vmexec_ctrls1 & VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed 0-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
	if (vm->vmexec_ctrls1 & ~VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed 1-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (~vm->vmexec_ctrls2 & VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed 0-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
	if (vm->vmexec_ctrls2 & ~VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed 1-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (~vm->vmexec_ctrls3 & VMX_MSR_VMX_PROCBASED_CTRLS2_LO) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX secondary proc-based controls allowed 0-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
	if (vm->vmexec_ctrls3 & ~VMX_MSR_VMX_PROCBASED_CTRLS2_HI) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX secondary proc-based controls allowed 1-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (vm->vm_cr3_target_cnt > VMX_CR3_TARGET_MAX_CNT) {
		printf("\nVMFAIL: VMCS EXEC CTRL: too may CR3 targets %d", vm->vm_cr3_target_cnt);
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_IO_BITMAPS) {
		//# vm->io_bitmap_addr[0] = VMread64(VMCS_64BIT_CONTROL_IO_BITMAP_A);
		//# vm->io_bitmap_addr[1] = VMread64(VMCS_64BIT_CONTROL_IO_BITMAP_B);

		vm->io_bitmap_addr[0] = ReadInputAuditor("VMCS_64BIT_CONTROL_IO_BITMAP_A ", 0x0);
		vm->io_bitmap_addr[1] = ReadInputAuditor("VMCS_64BIT_CONTROL_IO_BITMAP_B ", 0x0);

		// I/O bitmaps control enabled
		for (int bitmap = 0; bitmap < 2; bitmap++) {
			if (!IsValidPageAlignedPhyAddr(vm->io_bitmap_addr[bitmap])) {
				printf("\nVMFAIL: VMCS EXEC CTRL: I/O bitmap %c phy addr malformed", 'A' + bitmap);
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}
		}
	}

	if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_MSR_BITMAPS) {
		// MSR bitmaps control enabled
		//# vm->msr_bitmap_addr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_MSR_BITMAPS);
		vm->msr_bitmap_addr = ReadInputAuditor("VMCS_64BIT_CONTROL_MSR_BITMAPS ", 0x0);
		if (!IsValidPageAlignedPhyAddr(vm->msr_bitmap_addr)) {
			printf("\nVMFAIL: VMCS EXEC CTRL: MSR bitmap phy addr malformed");
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (!(vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_NMI_EXITING)) {
		if (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: misconfigured virtual NMI control"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (!(vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI)) {
		if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_NMI_WINDOW_EXITING) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: misconfigured virtual NMI control"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

#if BX_SUPPORT_VMX >= 2
	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
		//# vm->vmread_bitmap_addr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR);
		vm->vmread_bitmap_addr = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR ", 0x0);

		if (!IsValidPageAlignedPhyAddr(vm->vmread_bitmap_addr)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: VMREAD bitmap phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
		//# vm->vmwrite_bitmap_addr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR);
		vm->vmwrite_bitmap_addr = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR ", 0x0);

		if (!IsValidPageAlignedPhyAddr(vm->vmwrite_bitmap_addr)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: VMWRITE bitmap phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_VIOLATION_EXCEPTION) {
		//# vm->ve_info_addr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR);
		vm->ve_info_addr = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR ", 0x0);

		if (!IsValidPageAlignedPhyAddr(vm->ve_info_addr)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: broken #VE information address"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}
#endif

#if BX_SUPPORT_X86_64
	if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_TPR_SHADOW) {
		//# vm->virtual_apic_page_addr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR);

		vm->virtual_apic_page_addr = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR ", 0x0);

		if (!IsValidPageAlignedPhyAddr(vm->virtual_apic_page_addr)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: virtual apic phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

#if BX_SUPPORT_VMX >= 2
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY) {

			// #define PIN_VMEXIT(ctrl) (BX_CPU_THIS_PTR vmcs.vmexec_ctrls1 & (ctrl))
			// #define     VMEXIT(ctrl) (BX_CPU_THIS_PTR vmcs.vmexec_ctrls2 & (ctrl))

			//if (!PIN_VMEXIT(VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT)) {
			if (!(vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT)) {

				printf(("\nVMFAIL: VMCS EXEC CTRL: virtual interrupt delivery must be set together with external interrupt exiting"));
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}

			for (int reg = 0; reg < 8; reg++) {

				if (reg == 0)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 ", 0x0);
				}
				if (reg == 1)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0_HI ", 0x0);
				}
				if (reg == 2)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP1 ", 0x0);
				}
				if (reg == 3)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP1_HI ", 0x0);
				}
				if (reg == 4)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP2 ", 0x0);
				}
				if (reg == 5)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP2_HI ", 0x0);
				}
				if (reg == 6)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP3 ", 0x0);
				}
				if (reg == 7)
				{
					//* vm->eoi_exit_bitmap[reg] = VMread32(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
					vm->eoi_exit_bitmap[reg] = ReadInputAuditor("VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP3_HI ", 0x0);
				}

			}

			//# Bit16u guest_interrupt_status = VMread16(VMCS_16BIT_GUEST_INTERRUPT_STATUS);
			Bit16u guest_interrupt_status = ReadInputAuditor("VMCS_16BIT_GUEST_INTERRUPT_STATUS ", 0x0);

			vm->rvi = guest_interrupt_status & 0xff;
			vm->svi = guest_interrupt_status >> 8;
		}
		else
#endif
		{
			//# vm->vm_tpr_threshold = VMread32(VMCS_32BIT_CONTROL_TPR_THRESHOLD);
			vm->vm_tpr_threshold = ReadInputAuditor("VMCS_32BIT_CONTROL_TPR_THRESHOLD ", 0x0);

			if (vm->vm_tpr_threshold & 0xfffffff0) {
				printf(("\nVMFAIL: VMCS EXEC CTRL: TPR threshold too big"));
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}

			if (!(vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES)) {

				// ToDo : uncomment these lines
				printf("\n\n[*] Make sure you have a correct VMX Virtual APIC Address");
				/*
				Bit8u tpr_shadow = (VMX_Read_Virtual_APIC(BX_LAPIC_TPR) >> 4) & 0xf;
				if (vm->vm_tpr_threshold > tpr_shadow) {
					printf(("\nVMFAIL: VMCS EXEC CTRL: TPR threshold > TPR shadow"));
					return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
				}
				*/

			}
		}
	}
#if BX_SUPPORT_VMX >= 2
	else { // TPR shadow is disabled
		if (vm->vmexec_ctrls3 & (VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE |
			VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS |
			VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY))
		{
			printf(("\nVMFAIL: VMCS EXEC CTRL: apic virtualization is enabled without TPR shadow"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}
#endif // BX_SUPPORT_VMX >= 2

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES) {
		//* vm->apic_access_page = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR);
		vm->apic_access_page = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR", 0x0);
		if (!IsValidPageAlignedPhyAddr(vm->apic_access_page)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: apic access page phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

#if BX_SUPPORT_VMX >= 2
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: virtualize X2APIC mode enabled together with APIC access virtualization"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
#endif
	}

#if BX_SUPPORT_VMX >= 2
	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) {
		//* vm->eptptr = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_EPTPTR);
		vm->eptptr = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_EPTPTR ", 0x0);

		if (!is_eptptr_valid(vm->eptptr)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: invalid EPTPTR value"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}
	else {
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: unrestricted guest without EPT"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VPID_ENABLE) {
		//* vm->vpid = VMread16(VMCS_16BIT_CONTROL_VPID);
		vm->vpid = ReadInputAuditor("VMCS_16BIT_CONTROL_VPID ", 0x0);

		if (vm->vpid == 0) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: guest VPID == 0"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PAUSE_LOOP_VMEXIT) {
		//* vm->ple.pause_loop_exiting_gap = VMread32(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_GAP);
		vm->ple.pause_loop_exiting_gap = ReadInputAuditor("VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_GAP ", 0x0);
		//* vm->ple.pause_loop_exiting_window = VMread32(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_WINDOW);
		vm->ple.pause_loop_exiting_window = ReadInputAuditor("VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_WINDOW ", 0x0);
	}

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMFUNC_ENABLE)
		//* vm->vmfunc_ctrls = VMread64(VMCS_64BIT_CONTROL_VMFUNC_CTRLS);
		vm->vmfunc_ctrls = ReadInputAuditor("VMCS_64BIT_CONTROL_VMFUNC_CTRLS ", 0x0);
	else
		vm->vmfunc_ctrls = 0;

	if (vm->vmfunc_ctrls & ~VMX_VMFUNC_CTRL1_SUPPORTED_BITS) {
		printf(("\nVMFAIL: VMCS VM Functions control reserved bits set"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (vm->vmfunc_ctrls & VMX_VMFUNC_EPTP_SWITCHING_MASK) {
		if ((vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
			printf(("\nVMFAIL: VMFUNC EPTP-SWITCHING: EPT disabled"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		//# vm->eptp_list_address = VMread64(VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS);
		vm->eptp_list_address = ReadInputAuditor("VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS ", 0x0);
		if (!IsValidPageAlignedPhyAddr(vm->eptp_list_address)) {
			printf(("\nVMFAIL: VMFUNC EPTP-SWITCHING: eptp list phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PML_ENABLE) {
		if ((vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: PML is enabled without EPT"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		//* vm->pml_address = (bx_phy_address)VMread64(VMCS_64BIT_CONTROL_PML_ADDRESS);
		vm->pml_address = (bx_phy_address)ReadInputAuditor("VMCS_64BIT_CONTROL_PML_ADDRESS ", 0x0);
		if (!IsValidPageAlignedPhyAddr(vm->pml_address)) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: PML base phy addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
		//* vm->pml_index = VMread16(VMCS_16BIT_GUEST_PML_INDEX);
		vm->pml_index = ReadInputAuditor("VMCS_16BIT_GUEST_PML_INDEX ", 0x0);
	}
#endif

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_XSAVES_XRSTORS)
		//* vm->xss_exiting_bitmap = VMread64(VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP);
		vm->xss_exiting_bitmap = ReadInputAuditor("VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP ", 0x0);
	else
		vm->xss_exiting_bitmap = 0;

#endif // BX_SUPPORT_X86_64

	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_TSC_SCALING) {
		//* if ((vm->tsc_multiplier = VMread64(VMCS_64BIT_CONTROL_TSC_MULTIPLIER)) == 0) {
		if ((vm->tsc_multiplier = ReadInputAuditor("VMCS_64BIT_CONTROL_TSC_MULTIPLIER ", 0x0)) == 0) {
			printf(("\nVMFAIL: VMCS EXEC CTRL: TSC multiplier should be non zero"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	//
	// Load VM-exit control fields to VMCS Cache
	//

	//* vm->vmexit_ctrls = VMread32(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS);
	//* vm->vmexit_msr_store_cnt = VMread32(VMCS_32BIT_CONTROL_VMEXIT_MSR_STORE_COUNT);
	//* vm->vmexit_msr_load_cnt = VMread32(VMCS_32BIT_CONTROL_VMEXIT_MSR_LOAD_COUNT);
	vm->vmexit_ctrls = ReadInputAuditor("VMCS_32BIT_CONTROL_VMEXIT_CONTROLS ", 0x0);
	vm->vmexit_msr_store_cnt = ReadInputAuditor("VMCS_32BIT_CONTROL_VMEXIT_MSR_STORE_COUNT ", 0x0);
	vm->vmexit_msr_load_cnt = ReadInputAuditor("VMCS_32BIT_CONTROL_VMEXIT_MSR_LOAD_COUNT ", 0x0);


	//
	// Check VM-exit control fields
	//

	if (~vm->vmexit_ctrls & VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 0-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
	if (vm->vmexit_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 1-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

#if BX_SUPPORT_VMX >= 2
	if ((~vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VMX_PREEMPTION_TIMER_VMEXIT) && (vm->vmexit_ctrls & VMX_VMEXIT_CTRL1_STORE_VMX_PREEMPTION_TIMER)) {
		printf(("\nVMFAIL: save_VMX_preemption_timer VMEXIT control is set but VMX_preemption_timer VMEXEC control is clear"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
#endif

	if (vm->vmexit_msr_store_cnt > 0) {
		//* vm->vmexit_msr_store_addr = VMread64(VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR);
		vm->vmexit_msr_store_addr = ReadInputAuditor("VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR ", 0x0);
		if ((vm->vmexit_msr_store_addr & 0xf) != 0 || !IsValidPhyAddr(vm->vmexit_msr_store_addr)) {
			printf(("\nVMFAIL: VMCS VMEXIT CTRL: msr store addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		Bit64u last_byte = vm->vmexit_msr_store_addr + (vm->vmexit_msr_store_cnt * 16) - 1;
		if (!IsValidPhyAddr(last_byte)) {
			printf(("\nVMFAIL: VMCS VMEXIT CTRL: msr store addr too high"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	if (vm->vmexit_msr_load_cnt > 0) {
		//* vm->vmexit_msr_load_addr = VMread64(VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR);
		vm->vmexit_msr_load_addr = ReadInputAuditor("VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR ", 0x0);
		if ((vm->vmexit_msr_load_addr & 0xf) != 0 || !IsValidPhyAddr(vm->vmexit_msr_load_addr)) {
			printf(("\nVMFAIL: VMCS VMEXIT CTRL: msr load addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		Bit64u last_byte = (Bit64u)vm->vmexit_msr_load_addr + (vm->vmexit_msr_load_cnt * 16) - 1;
		if (!IsValidPhyAddr(last_byte)) {
			printf(("\nVMFAIL: VMCS VMEXIT CTRL: msr load addr too high"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	//
	// Load VM-entry control fields to VMCS Cache
	//

	//* vm->vmentry_ctrls = VMread32(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS);
	vm->vmentry_ctrls = ReadInputAuditor("VMCS_32BIT_CONTROL_VMENTRY_CONTROLS ", 0x0);
	//* vm->vmentry_msr_load_cnt = VMread32(VMCS_32BIT_CONTROL_VMENTRY_MSR_LOAD_COUNT);
	vm->vmentry_msr_load_cnt = ReadInputAuditor("VMCS_32BIT_CONTROL_VMENTRY_MSR_LOAD_COUNT ", 0x0);

	//
	// Check VM-entry control fields
	//

	if (~vm->vmentry_ctrls & VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 0-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}
	if (vm->vmentry_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI) {
		printf(("\nVMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 1-settings"));
		return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
	}

	if (vm->vmentry_ctrls & VMX_VMENTRY_CTRL1_DEACTIVATE_DUAL_MONITOR_TREATMENT) {
		// Not in SMM so let's skip
		/*
		if (!BX_CPU_THIS_PTR in_smm) {
			printf(("\nVMFAIL: VMENTRY from outside SMM with dual-monitor treatment enabled"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
		*/
	}

	if (vm->vmentry_msr_load_cnt > 0) {

		//* vm->vmentry_msr_load_addr = VMread64(VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR);
		vm->vmentry_msr_load_addr = ReadInputAuditor("VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR ", 0x0);

		if ((vm->vmentry_msr_load_addr & 0xf) != 0 || !IsValidPhyAddr(vm->vmentry_msr_load_addr)) {
			printf(("\nVMFAIL: VMCS VMENTRY CTRL: msr load addr malformed"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		Bit64u last_byte = vm->vmentry_msr_load_addr + (vm->vmentry_msr_load_cnt * 16) - 1;
		if (!IsValidPhyAddr(last_byte)) {
			printf(("\nVMFAIL: VMCS VMENTRY CTRL: msr load addr too high"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}
	}

	//
	// Check VM-entry event injection info
	//

	//* vm->vmentry_interr_info = VMread32(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO);
	//* vm->vmentry_excep_err_code = VMread32(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE);
	//* vm->vmentry_instr_length = VMread32(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH);
	vm->vmentry_interr_info = ReadInputAuditor("VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO ", 0x0);
	vm->vmentry_excep_err_code = ReadInputAuditor("VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE ", 0x0);
	vm->vmentry_instr_length = ReadInputAuditor("VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH ", 0x0);


	if (VMENTRY_INJECTING_EVENT(vm->vmentry_interr_info)) {

		/* the VMENTRY injecting event to the guest */
		unsigned vector = vm->vmentry_interr_info & 0xff;
		unsigned event_type = (vm->vmentry_interr_info >> 8) & 7;
		unsigned push_error = (vm->vmentry_interr_info >> 11) & 1;
		unsigned error_code = push_error ? vm->vmentry_excep_err_code : 0;

		unsigned push_error_reference = 0;
		if (event_type == BX_HARDWARE_EXCEPTION && vector < BX_CPU_HANDLED_EXCEPTIONS)
			push_error_reference = exceptions_info[vector].push_error;

		if (vm->vmentry_interr_info & 0x7ffff000) {
			printf(("\nVMFAIL: VMENTRY broken interruption info field"));
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		switch (event_type) {
		case BX_EXTERNAL_INTERRUPT:
			break;

		case BX_NMI:
			if (vector != 2) {
				printf("\nVMFAIL: VMENTRY bad injected event vector %d", vector);
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}
			/*
					 // injecting NMI
					 if (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
					   if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED) {
						 printf(("\nVMFAIL: VMENTRY injected NMI vector when blocked by NMI in interruptibility state", vector));
						 return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
					   }
					 }
			*/
			break;

		case BX_HARDWARE_EXCEPTION:
			if (vector > 31) {
				printf("\nVMFAIL: VMENTRY bad injected event vector %d", vector);
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}
			break;

		case BX_SOFTWARE_INTERRUPT:
		case BX_PRIVILEGED_SOFTWARE_INTERRUPT:
		case BX_SOFTWARE_EXCEPTION:
			if (vm->vmentry_instr_length == 0 || vm->vmentry_instr_length > 15) {
				printf(("\nVMFAIL: VMENTRY bad injected event instr length"));
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}
			break;

		case 7: /* MTF */
			if (BX_SUPPORT_VMX_EXTENSION(BX_VMX_MONITOR_TRAP_FLAG)) {
				if (vector != 0) {
					printf("\nVMFAIL: VMENTRY bad MTF injection with vector=%d", vector);
					return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
				}
			}
			break;

		default:
			printf("\nVMFAIL: VMENTRY bad injected event type %d", event_type);
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

#if BX_SUPPORT_VMX >= 2
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
			//* unsigned protected_mode_guest = (Bit32u)VMread_natural(VMCS_GUEST_CR0) & BX_CR0_PE_MASK;
			unsigned protected_mode_guest = (Bit32u)ReadInputAuditor("VMCS_GUEST_CR0 ", 0x0)  & BX_CR0_PE_MASK;
			if (!protected_mode_guest) push_error_reference = 0;
		}
#endif

		if (push_error != push_error_reference) {
			printf("\nVMFAIL: VMENTRY injected event vector %d broken error code", vector);
			return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
		}

		if (push_error) {
			if (error_code & 0xffff0000) {
				printf("\nVMFAIL: VMENTRY bad error code 0x%08x for injected event %d", error_code, vector);
				return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
			}
		}
	}

	return VMXERR_NO_ERROR;
}

VMX_error_code VMenterLoadCheckHostState(VMCS_CACHE *vm)
{
	VMCS_HOST_STATE *host_state = &vm->host_state;
	bx_bool x86_64_host = 0, x86_64_guest = 0;

	//
	// VM Host State Checks Related to Address-Space Size
	//

	Bit32u vmexit_ctrls = vm->vmexit_ctrls;
	if (vmexit_ctrls & VMX_VMEXIT_CTRL1_HOST_ADDR_SPACE_SIZE) {
		x86_64_host = 1;
	}
	Bit32u vmentry_ctrls = vm->vmentry_ctrls;
	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
		x86_64_guest = 1;
	}

#if BX_SUPPORT_X86_64
	if (long_mode()) {
		if (!x86_64_host) {
			printf(("\nVMFAIL: VMCS x86-64 host control invalid on VMENTRY"));
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}
	else
#endif
	{
		if (x86_64_host || x86_64_guest) {
			printf("\nVMFAIL: VMCS x86-64 guest(%d)/host(%d) controls invalid on VMENTRY", x86_64_guest, x86_64_host);
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}

	//
	// Load and Check VM Host State to VMCS Cache
	//

	//# host_state->cr0 = (bx_address)VMread_natural(VMCS_HOST_CR0);
	if (~host_state->cr0 & VMX_MSR_CR0_FIXED0) {
		printf("\nVMFAIL: VMCS host state invalid CR0 0x%08x", (Bit32u)host_state->cr0);
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	if (host_state->cr0 & ~VMX_MSR_CR0_FIXED1) {
		printf("\nVMFAIL: VMCS host state invalid CR0 0x%08x", (Bit32u)host_state->cr0);
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	//# host_state->cr3 = (bx_address)VMread_natural(VMCS_HOST_CR3);
#if BX_SUPPORT_X86_64
	if (!IsValidPhyAddr(host_state->cr3)) {
		printf(("\nVMFAIL: VMCS host state invalid CR3"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
#endif

	//# host_state->cr4 = (bx_address)VMread_natural(VMCS_HOST_CR4);
	if (~host_state->cr4 & VMX_MSR_CR4_FIXED0) {
		printf("\nVMFAIL: VMCS host state invalid CR4 0x" FMT_ADDRX, host_state->cr4);
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
	if (host_state->cr4 & ~VMX_MSR_CR4_FIXED1) {
		printf("\nVMFAIL: VMCS host state invalid CR4 0x" FMT_ADDRX, host_state->cr4);
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	for (int n = 0; n < 6; n++) {


		if (n == 0)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_ES_SELECTOR ", 0x0);
		}
		if (n == 1)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_CS_SELECTOR ", 0x0);
		}
		if (n == 2)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_SS_SELECTOR ", 0x0);
		}
		if (n == 3)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_DS_SELECTOR ", 0x0);
		}
		if (n == 4)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_FS_SELECTOR ", 0x0);
		}
		if (n == 5)
		{
			//*host_state->segreg_selector[n] = VMread16(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
			host_state->segreg_selector[n] = ReadInputAuditor("VMCS_16BIT_HOST_GS_SELECTOR ", 0x0);
		}



		if (host_state->segreg_selector[n] & 7) {
			printf("\nVMFAIL: VMCS host segreg %d TI/RPL != 0", n);
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}

	if (host_state->segreg_selector[BX_SEG_REG_CS] == 0) {
		printf(("\nVMFAIL: VMCS host CS selector 0"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	if (!x86_64_host && host_state->segreg_selector[BX_SEG_REG_SS] == 0) {
		printf(("\nVMFAIL: VMCS host SS selector 0"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	//# host_state->tr_selector = VMread16(VMCS_16BIT_HOST_TR_SELECTOR);
	if (!host_state->tr_selector || (host_state->tr_selector & 7) != 0) {
		printf(("\nVMFAIL: VMCS invalid host TR selector"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	//# host_state->tr_base = (bx_address)VMread_natural(VMCS_HOST_TR_BASE);
#if BX_SUPPORT_X86_64
	if (!IsCanonical(host_state->tr_base)) {
		printf(("\nVMFAIL: VMCS host TR BASE non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
#endif

	//# host_state->fs_base = (bx_address)VMread_natural(VMCS_HOST_FS_BASE);
	//# host_state->gs_base = (bx_address)VMread_natural(VMCS_HOST_GS_BASE);
#if BX_SUPPORT_X86_64
	if (!IsCanonical(host_state->fs_base)) {
		printf(("\nVMFAIL: VMCS host FS BASE non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
	if (!IsCanonical(host_state->gs_base)) {
		printf(("\nVMFAIL: VMCS host GS BASE non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
#endif

	//# host_state->gdtr_base = (bx_address)VMread_natural(VMCS_HOST_GDTR_BASE);
	//# host_state->idtr_base = (bx_address)VMread_natural(VMCS_HOST_IDTR_BASE);
#if BX_SUPPORT_X86_64
	if (!IsCanonical(host_state->gdtr_base)) {
		printf(("\nVMFAIL: VMCS host GDTR BASE non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
	if (!IsCanonical(host_state->idtr_base)) {
		printf(("\nVMFAIL: VMCS host IDTR BASE non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
#endif

	//# host_state->sysenter_esp_msr = (bx_address)VMread_natural(VMCS_HOST_IA32_SYSENTER_ESP_MSR);
	//# host_state->sysenter_eip_msr = (bx_address)VMread_natural(VMCS_HOST_IA32_SYSENTER_EIP_MSR);
	//# host_state->sysenter_cs_msr = (Bit16u)VMread32(VMCS_32BIT_HOST_IA32_SYSENTER_CS_MSR);

#if BX_SUPPORT_X86_64
	if (!IsCanonical(host_state->sysenter_esp_msr)) {
		printf(("\nVMFAIL: VMCS host SYSENTER_ESP_MSR non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	if (!IsCanonical(host_state->sysenter_eip_msr)) {
		printf(("\nVMFAIL: VMCS host SYSENTER_EIP_MSR non canonical"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}
#endif

#if BX_SUPPORT_VMX >= 2
	if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_PAT_MSR) {
		//# host_state->pat_msr = VMread64(VMCS_64BIT_HOST_IA32_PAT);
		if (!isValidMSR_PAT(host_state->pat_msr)) {
			printf(("\nVMFAIL: invalid Memory Type in host MSR_PAT"));
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}
#endif

	//# host_state->rsp = (bx_address)VMread_natural(VMCS_HOST_RSP);
	//# host_state->rip = (bx_address)VMread_natural(VMCS_HOST_RIP);

#if BX_SUPPORT_X86_64

#if BX_SUPPORT_VMX >= 2
	if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_EFER_MSR) {
		//# host_state->efer_msr = VMread64(VMCS_64BIT_HOST_IA32_EFER);
		if (host_state->efer_msr & ~((Bit64u)efer_suppmask)) {
			printf(("\nVMFAIL: VMCS host EFER reserved bits set !"));
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
		bx_bool lme = (host_state->efer_msr >> 8) & 0x1;
		bx_bool lma = (host_state->efer_msr >> 10) & 0x1;
		if (lma != lme || lma != x86_64_host) {
			printf("\nVMFAIL: VMCS host EFER (0x%08x) inconsistent value !", (Bit32u)host_state->efer_msr);
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}
#endif

	if (x86_64_host) {
		if ((host_state->cr4 & BX_CR4_PAE_MASK) == 0) {
			printf("\nVMFAIL: VMCS host CR4.PAE=0 with x86-64 host");
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
		if (!IsCanonical(host_state->rip)) {
			printf("\nVMFAIL: VMCS host RIP non-canonical");
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}
	else {
		if (GET32H(host_state->rip) != 0) {
			printf(("\nVMFAIL: VMCS host RIP > 32 bit"));
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
		if (host_state->cr4 & BX_CR4_PCIDE_MASK) {
			printf(("\nVMFAIL: VMCS host CR4.PCIDE set"));
			return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
		}
	}
#endif

	return VMXERR_NO_ERROR;
}

Bit32u VMenterLoadCheckGuestState(VMCS_CACHE *vm, Bit64u *qualification, UINT64 VMXON_Pointer, INT32 RevisionID)
{
	static const char *segname[] = { "ES", "CS", "SS", "DS", "FS", "GS" };
	int n;

	VMCS_GUEST_STATE guest;
	// VMCS_CACHE *vm = &BX_CPU_THIS_PTR vmcs;

	*qualification = VMENTER_ERR_NO_ERROR;

	//
	// Load and Check Guest State from VMCS
	//

	//# guest.rflags = VMread_natural(VMCS_GUEST_RFLAGS);
	guest.rflags = ReadInputAuditor("VMCS_GUEST_RFLAGS ", 0x0);


	// RFLAGS reserved bits [63:22], bit 15, bit 5, bit 3 must be zero
	if (guest.rflags & BX_CONST64(0xFFFFFFFFFFC08028)) {
		printf(("\nVMENTER FAIL: RFLAGS reserved bits are set"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	// RFLAGS[1] must be always set
	if ((guest.rflags & 0x2) == 0) {
		printf(("\nVMENTER FAIL: RFLAGS[1] cleared"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	bx_bool v8086_guest = 0;
	if (guest.rflags & EFlagsVMMask)
		v8086_guest = 1;

	bx_bool x86_64_guest = 0; // can't be 1 if X86_64 is not supported (checked before)
	Bit32u vmentry_ctrls = vm->vmentry_ctrls;
#if BX_SUPPORT_X86_64
	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
		printf(("\nVMENTER to x86-64 guest"));
		x86_64_guest = 1;
	}
#endif

	if (x86_64_guest && v8086_guest) {
		printf(("\nVMENTER FAIL: Enter to x86-64 guest with RFLAGS.VM"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	//# guest.cr0 = VMread_natural(VMCS_GUEST_CR0);
	guest.cr0 = ReadInputAuditor("VMCS_GUEST_CR0 ", 0x0);

#if BX_SUPPORT_VMX >= 2
	if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
		if (~guest.cr0 & (VMX_MSR_CR0_FIXED0 & ~(BX_CR0_PE_MASK | BX_CR0_PG_MASK))) {
			printf(("\nVMENTER FAIL: VMCS guest invalid CR0"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		bx_bool pe = (guest.cr0 & BX_CR0_PE_MASK) != 0;
		bx_bool pg = (guest.cr0 & BX_CR0_PG_MASK) != 0;
		if (pg && !pe) {
			printf(("\nVMENTER FAIL: VMCS unrestricted guest CR0.PG without CR0.PE"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
	else
#endif
	{
		if (~guest.cr0 & VMX_MSR_CR0_FIXED0) {
			printf(("\nVMENTER FAIL: VMCS guest invalid CR0"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	if (guest.cr0 & ~VMX_MSR_CR0_FIXED1) {
		printf(("\nVMENTER FAIL: VMCS guest invalid CR0"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

#if BX_SUPPORT_VMX >= 2
	bx_bool real_mode_guest = 0;
	if (!(guest.cr0 & BX_CR0_PE_MASK))
		real_mode_guest = 1;
#endif

	//# guest.cr3 = VMread_natural(VMCS_GUEST_CR3);
	guest.cr3 = ReadInputAuditor("VMCS_GUEST_CR3 ", 0x0);

#if BX_SUPPORT_X86_64
	if (!IsValidPhyAddr(guest.cr3)) {
		printf(("\nVMENTER FAIL: VMCS guest invalid CR3"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
#endif

	//# guest.cr4 = VMread_natural(VMCS_GUEST_CR4);
	guest.cr4 = ReadInputAuditor("VMCS_GUEST_CR4 ", 0x0);;
	if (~guest.cr4 & VMX_MSR_CR4_FIXED0) {
		printf(("\nVMENTER FAIL: VMCS guest invalid CR4"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

	if (guest.cr4 & ~VMX_MSR_CR4_FIXED1) {
		printf(("\nVMENTER FAIL: VMCS guest invalid CR4"));
		return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
	}

#if BX_SUPPORT_X86_64
	if (x86_64_guest) {
		if ((guest.cr4 & BX_CR4_PAE_MASK) == 0) {
			printf(("\nVMENTER FAIL: VMCS guest CR4.PAE=0 in x86-64 mode"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
	else {
		if (guest.cr4 & BX_CR4_PCIDE_MASK) {
			printf(("\nVMENTER FAIL: VMCS CR4.PCIDE set in 32-bit guest"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
#endif

#if BX_SUPPORT_X86_64
	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_DBG_CTRLS) {
		//* guest.dr7 = VMread_natural(VMCS_GUEST_DR7);
		guest.dr7 = ReadInputAuditor("VMCS_GUEST_DR7 ", 0x0);
		if (GET32H(guest.dr7)) {
			printf(("\nVMENTER FAIL: VMCS guest invalid DR7"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
#endif

	//
	// Load and Check Guest State from VMCS - Segment Registers
	//

	for (n = 0; n < 6; n++) {

		Bit16u selector;
		bx_address base;
		Bit32u limit;
		Bit32u ar;

		/*
		Bit16u selector = VMread16(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * n);
		bx_address base = (bx_address)VMread_natural(VMCS_GUEST_ES_BASE + 2 * n);
		Bit32u limit = VMread32(VMCS_32BIT_GUEST_ES_LIMIT + 2 * n);
		Bit32u ar = VMread32(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n);
		*/

		if (n == 0)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_ES_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_ES_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_ES_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS ", 0x0);
		}
		if (n == 1)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_CS_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_CS_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_CS_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_CS_ACCESS_RIGHTS ", 0x0);
		}

		if (n == 2)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_SS_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_SS_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_SS_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_SS_ACCESS_RIGHTS ", 0x0);
		}

		if (n == 3)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_DS_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_DS_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_DS_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_DS_ACCESS_RIGHTS ", 0x0);
		}

		if (n == 4)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_FS_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_FS_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_FS_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_FS_ACCESS_RIGHTS ", 0x0);
		}

		if (n == 5)
		{
			selector = ReadInputAuditor("VMCS_16BIT_GUEST_GS_SELECTOR ", 0x0);
			base = (bx_address)ReadInputAuditor("VMCS_GUEST_GS_BASE ", 0x0);
			limit = ReadInputAuditor("VMCS_32BIT_GUEST_GS_LIMIT ", 0x0);
			ar = ReadInputAuditor("VMCS_32BIT_GUEST_GS_ACCESS_RIGHTS ", 0x0);
		}

		ar = vmx_from_ar_byte_rd(ar);
		bx_bool invalid = (ar >> 16) & 1;

		set_segment_ar_data(&guest.sregs[n], !invalid,
			(Bit16u)selector, base, limit, (Bit16u)ar);

		if (v8086_guest) {
			// guest in V8086 mode
			if (base != ((bx_address)(selector << 4))) {
				printf(("\nVMENTER FAIL: VMCS v8086 guest bad %s.BASE", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
			if (limit != 0xffff) {
				printf(("\nVMENTER FAIL: VMCS v8086 guest %s.LIMIT != 0xFFFF", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
			// present, expand-up read/write accessed, segment, DPL=3
			if (ar != 0xF3) {
				printf(("\nVMENTER FAIL: VMCS v8086 guest %s.AR != 0xF3", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}

			continue; // go to next segment register
		}

#if BX_SUPPORT_X86_64
		if (n >= BX_SEG_REG_FS) {
			if (!IsCanonical(base)) {
				printf(("\nVMENTER FAIL: VMCS guest %s.BASE non canonical", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
#endif

		if (n != BX_SEG_REG_CS && invalid)
			continue;

#if BX_SUPPORT_X86_64
		if (n == BX_SEG_REG_SS && (selector & BX_SELECTOR_RPL_MASK) == 0) {
			// SS is allowed to be NULL selector if going to 64-bit guest
			if (x86_64_guest && guest.sregs[BX_SEG_REG_CS].cache.u.segment.l)
				continue;
		}

		if (n < BX_SEG_REG_FS) {
			if (GET32H(base) != 0) {
				printf(("\nVMENTER FAIL: VMCS guest %s.BASE > 32 bit", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
#endif

		if (!guest.sregs[n].cache.segment) {
			printf(("\nVMENTER FAIL: VMCS guest %s not segment", segname[n]));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		if (!guest.sregs[n].cache.p) {
			printf(("\nVMENTER FAIL: VMCS guest %s not present", segname[n]));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		if (!IsLimitAccessRightsConsistent(limit, ar)) {
			printf(("\nVMENTER FAIL: VMCS guest %s.AR/LIMIT malformed", segname[n]));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		if (n == BX_SEG_REG_CS) {
			// CS checks
			switch (guest.sregs[BX_SEG_REG_CS].cache.type) {
			case BX_CODE_EXEC_ONLY_ACCESSED:
			case BX_CODE_EXEC_READ_ACCESSED:
				// non-conforming segment
				if (guest.sregs[BX_SEG_REG_CS].selector.rpl != guest.sregs[BX_SEG_REG_CS].cache.dpl) {
					printf(("\nVMENTER FAIL: VMCS guest non-conforming CS.RPL <> CS.DPL"));
					return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
				}
				break;
			case BX_CODE_EXEC_ONLY_CONFORMING_ACCESSED:
			case BX_CODE_EXEC_READ_CONFORMING_ACCESSED:
				// conforming segment
				if (guest.sregs[BX_SEG_REG_CS].selector.rpl < guest.sregs[BX_SEG_REG_CS].cache.dpl) {
					printf(("\nVMENTER FAIL: VMCS guest non-conforming CS.RPL < CS.DPL"));
					return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
				}
				break;
#if BX_SUPPORT_VMX >= 2
			case BX_DATA_READ_WRITE_ACCESSED:
				if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
					if (guest.sregs[BX_SEG_REG_CS].cache.dpl != 0) {
						printf(("\nVMENTER FAIL: VMCS unrestricted guest CS.DPL != 0"));
						return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
					}
					break;
				}
				// fall through
#endif
			default:
				printf(("\nVMENTER FAIL: VMCS guest CS.TYPE"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}

#if BX_SUPPORT_X86_64
			if (x86_64_guest) {
				if (guest.sregs[BX_SEG_REG_CS].cache.u.segment.d_b && guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
					printf(("\nVMENTER FAIL: VMCS x86_64 guest wrong CS.D_B/L"));
					return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
				}
			}
#endif
		}
		else if (n == BX_SEG_REG_SS) {
			// SS checks
			switch (guest.sregs[BX_SEG_REG_SS].cache.type) {
			case BX_DATA_READ_WRITE_ACCESSED:
			case BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED:
				break;
			default:
				printf(("\nVMENTER FAIL: VMCS guest SS.TYPE"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
		else {
			// DS, ES, FS, GS
			if ((guest.sregs[n].cache.type & 0x1) == 0) {
				printf(("\nVMENTER FAIL: VMCS guest %s not ACCESSED", segname[n]));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}

			if (guest.sregs[n].cache.type & 0x8) {
				if ((guest.sregs[n].cache.type & 0x2) == 0) {
					printf(("\nVMENTER FAIL: VMCS guest CODE segment %s not READABLE", segname[n]));
					return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
				}
			}

			if (!(vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
				if (guest.sregs[n].cache.type < 11) {
					// data segment or non-conforming code segment
					if (guest.sregs[n].selector.rpl > guest.sregs[n].cache.dpl) {
						printf(("\nVMENTER FAIL: VMCS guest non-conforming %s.RPL < %s.DPL", segname[n], segname[n]));
						return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
					}
				}
			}
		}
	}

	if (!v8086_guest) {
		if (!(vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
			if (guest.sregs[BX_SEG_REG_SS].selector.rpl != guest.sregs[BX_SEG_REG_CS].selector.rpl) {
				printf(("\nVMENTER FAIL: VMCS guest CS.RPL != SS.RPL"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
			if (guest.sregs[BX_SEG_REG_SS].selector.rpl != guest.sregs[BX_SEG_REG_SS].cache.dpl) {
				printf(("\nVMENTER FAIL: VMCS guest SS.RPL <> SS.DPL"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
#if BX_SUPPORT_VMX >= 2
		else { // unrestricted guest
			if (real_mode_guest || guest.sregs[BX_SEG_REG_CS].cache.type == BX_DATA_READ_WRITE_ACCESSED) {
				if (guest.sregs[BX_SEG_REG_SS].cache.dpl != 0) {
					printf(("\nVMENTER FAIL: VMCS unrestricted guest SS.DPL != 0"));
					return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
				}
			}
		}
#endif
	}

	//
	// Load and Check Guest State from VMCS - GDTR/IDTR
	//

	//* Bit64u gdtr_base = VMread_natural(VMCS_GUEST_GDTR_BASE);
	//* Bit32u gdtr_limit = VMread32(VMCS_32BIT_GUEST_GDTR_LIMIT);
	//* Bit64u idtr_base = VMread_natural(VMCS_GUEST_IDTR_BASE);
	//* Bit32u idtr_limit = VMread32(VMCS_32BIT_GUEST_IDTR_LIMIT);

	Bit64u gdtr_base = ReadInputAuditor("VMCS_GUEST_GDTR_BASE ", 0x0);
	Bit32u gdtr_limit = ReadInputAuditor("VMCS_32BIT_GUEST_GDTR_LIMIT ", 0x0);
	Bit64u idtr_base = ReadInputAuditor("VMCS_GUEST_IDTR_BASE ", 0x0);
	Bit32u idtr_limit = ReadInputAuditor("VMCS_32BIT_GUEST_IDTR_LIMIT ", 0x0);

#if BX_SUPPORT_X86_64
	if (!IsCanonical(gdtr_base) || !IsCanonical(idtr_base)) {
		printf(("\nVMENTER FAIL: VMCS guest IDTR/IDTR.BASE non canonical"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
#endif
	if (gdtr_limit > 0xffff || idtr_limit > 0xffff) {
		printf(("\nVMENTER FAIL: VMCS guest GDTR/IDTR limit > 0xFFFF"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	//
	// Load and Check Guest State from VMCS - LDTR
	//

	//* Bit16u ldtr_selector = VMread16(VMCS_16BIT_GUEST_LDTR_SELECTOR);
	Bit16u ldtr_selector = ReadInputAuditor("VMCS_16BIT_GUEST_LDTR_SELECTOR ", 0x0);
	//* Bit64u ldtr_base = VMread_natural(VMCS_GUEST_LDTR_BASE);
	Bit64u ldtr_base = ReadInputAuditor("VMCS_GUEST_LDTR_BASE ", 0x0);
	//* Bit32u ldtr_limit = VMread32(VMCS_32BIT_GUEST_LDTR_LIMIT);
	Bit32u ldtr_limit = ReadInputAuditor("VMCS_32BIT_GUEST_LDTR_LIMIT ", 0x0);
	//* Bit32u ldtr_ar = VMread32(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS);
	Bit32u ldtr_ar = ReadInputAuditor("VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS ", 0x0);




	ldtr_ar = vmx_from_ar_byte_rd(ldtr_ar);
	bx_bool ldtr_invalid = (ldtr_ar >> 16) & 1;
	if (set_segment_ar_data(&guest.ldtr, !ldtr_invalid,
		(Bit16u)ldtr_selector, ldtr_base, ldtr_limit, (Bit16u)(ldtr_ar)))
	{
		// ldtr is valid
		if (guest.ldtr.selector.ti) {
			printf(("\nVMENTER FAIL: VMCS guest LDTR.TI set"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (guest.ldtr.cache.type != BX_SYS_SEGMENT_LDT) {
			printf("\nVMENTER FAIL: VMCS guest incorrect LDTR type (%d)", guest.ldtr.cache.type);
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (guest.ldtr.cache.segment) {
			printf("\nVMENTER FAIL: VMCS guest LDTR is not system segment");
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (!guest.ldtr.cache.p) {
			printf("\nVMENTER FAIL: VMCS guest LDTR not present");
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (!IsLimitAccessRightsConsistent(ldtr_limit, ldtr_ar)) {
			printf("\nVMENTER FAIL: VMCS guest LDTR.AR/LIMIT malformed");
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
#if BX_SUPPORT_X86_64
		if (!IsCanonical(ldtr_base)) {
			printf(("\nVMENTER FAIL: VMCS guest LDTR.BASE non canonical"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
#endif
	}

	//
	// Load and Check Guest State from VMCS - TR
	//

	//* Bit16u tr_selector = VMread16(VMCS_16BIT_GUEST_TR_SELECTOR);
	Bit16u tr_selector = ReadInputAuditor("VMCS_16BIT_GUEST_TR_SELECTOR ", 0x0);
	//* Bit64u tr_base = VMread_natural(VMCS_GUEST_TR_BASE);
	Bit64u tr_base = ReadInputAuditor("VMCS_GUEST_TR_BASE ", 0x0);
	//* Bit32u tr_limit = VMread32(VMCS_32BIT_GUEST_TR_LIMIT);
	Bit32u tr_limit = ReadInputAuditor("VMCS_32BIT_GUEST_TR_LIMIT ", 0x0);
	//* Bit32u tr_ar = VMread32(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS);
	Bit32u tr_ar = ReadInputAuditor("VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS ", 0x0);


	tr_ar = vmx_from_ar_byte_rd(tr_ar);
	bx_bool tr_invalid = (tr_ar >> 16) & 1;

#if BX_SUPPORT_X86_64
	if (!IsCanonical(tr_base)) {
		printf(("\nVMENTER FAIL: VMCS guest TR.BASE non canonical"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
#endif

	set_segment_ar_data(&guest.tr, !tr_invalid,
		(Bit16u)tr_selector, tr_base, tr_limit, (Bit16u)(tr_ar));

	if (tr_invalid) {
		printf(("\nVMENTER FAIL: VMCS guest TR invalid"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	if (guest.tr.selector.ti) {
		printf(("\nVMENTER FAIL: VMCS guest TR.TI set"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	if (guest.tr.cache.segment) {
		printf(("\nVMENTER FAIL: VMCS guest TR is not system segment"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	if (!guest.tr.cache.p) {
		printf(("\nVMENTER FAIL: VMCS guest TR not present"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	if (!IsLimitAccessRightsConsistent(tr_limit, tr_ar)) {
		printf(("\nVMENTER FAIL: VMCS guest TR.AR/LIMIT malformed"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	switch (guest.tr.cache.type) {
	case BX_SYS_SEGMENT_BUSY_386_TSS:
		break;
	case BX_SYS_SEGMENT_BUSY_286_TSS:
		if (!x86_64_guest) break;
		// fall through
	default:
		printf(("\nVMENTER FAIL: VMCS guest incorrect TR type"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	//
	// Load and Check Guest State from VMCS - MSRS
	//

	//# guest.ia32_debugctl_msr = VMread64(VMCS_64BIT_GUEST_IA32_DEBUGCTL);
	guest.ia32_debugctl_msr = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_DEBUGCTL ", 0x0);
	//# guest.smbase = VMread32(VMCS_32BIT_GUEST_SMBASE);
	guest.smbase = ReadInputAuditor("VMCS_32BIT_GUEST_SMBASE ", 0x0);
	//# guest.sysenter_esp_msr = VMread_natural(VMCS_GUEST_IA32_SYSENTER_ESP_MSR);
	guest.sysenter_esp_msr = ReadInputAuditor("VMCS_GUEST_IA32_SYSENTER_ESP_MSR ", 0x0);
	//# guest.sysenter_eip_msr = VMread_natural(VMCS_GUEST_IA32_SYSENTER_EIP_MSR);
	guest.sysenter_eip_msr = ReadInputAuditor("VMCS_GUEST_IA32_SYSENTER_EIP_MSR ", 0x0);
	//# guest.sysenter_cs_msr = VMread32(VMCS_32BIT_GUEST_IA32_SYSENTER_CS_MSR);
	guest.sysenter_cs_msr = ReadInputAuditor("VMCS_32BIT_GUEST_IA32_SYSENTER_CS_MSR ", 0x0);

#if BX_SUPPORT_X86_64
	if (!IsCanonical(guest.sysenter_esp_msr)) {
		printf(("\nVMENTER FAIL: VMCS guest SYSENTER_ESP_MSR non canonical"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
	if (!IsCanonical(guest.sysenter_eip_msr)) {
		printf(("\nVMENTER FAIL: VMCS guest SYSENTER_EIP_MSR non canonical"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}
#endif

#if BX_SUPPORT_VMX >= 2
	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_PAT_MSR) {
		//* guest.pat_msr = VMread64(VMCS_64BIT_GUEST_IA32_PAT);
		guest.pat_msr = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_PAT ", 0x0);

		if (!isValidMSR_PAT(guest.pat_msr)) {
			printf(("\nVMENTER FAIL: invalid Memory Type in guest MSR_PAT"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
#endif

	//* guest.rip = VMread_natural(VMCS_GUEST_RIP);
	guest.rip = ReadInputAuditor("VMCS_GUEST_RIP ", 0x0);
	//* guest.rsp = VMread_natural(VMCS_GUEST_RSP);
	guest.rsp = ReadInputAuditor("VMCS_GUEST_RSP ", 0x0);

#if BX_SUPPORT_VMX >= 2 && BX_SUPPORT_X86_64
	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_EFER_MSR) {
		//* guest.efer_msr = VMread64(VMCS_64BIT_GUEST_IA32_EFER);
		guest.efer_msr = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_EFER ", 0x0);


		if (guest.efer_msr & ~((Bit64u)efer_suppmask)) {
			printf(("\nVMENTER FAIL: VMCS guest EFER reserved bits set !"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		bx_bool lme = (guest.efer_msr >> 8) & 0x1;
		bx_bool lma = (guest.efer_msr >> 10) & 0x1;
		if (lma != x86_64_guest) {
			printf(("\nVMENTER FAIL: VMCS guest EFER.LMA doesn't match x86_64_guest !"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (lma != lme && (guest.cr0 & BX_CR0_PG_MASK) != 0) {
			printf("\nVMENTER FAIL: VMCS guest EFER (0x%08x) inconsistent value !", (Bit32u)guest.efer_msr);
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	if (!x86_64_guest || !guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
		if (GET32H(guest.rip) != 0) {
			printf(("\nVMENTER FAIL: VMCS guest RIP > 32 bit"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}
#endif

	//
	// Load and Check Guest Non-Registers State from VMCS
	//

	//* vm->vmcs_linkptr = VMread64(VMCS_64BIT_GUEST_LINK_POINTER);
	vm->vmcs_linkptr = ReadInputAuditor("VMCS_64BIT_GUEST_LINK_POINTER ", 0x0);

	if (vm->vmcs_linkptr != BX_INVALID_VMCSPTR) {
		if (!IsValidPageAlignedPhyAddr(vm->vmcs_linkptr)) {
			*qualification = (Bit64u)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
			printf(("\nVMFAIL: VMCS link pointer malformed"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		Bit32u revision = RevisionID;
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
			if ((revision & BX_VMCS_SHADOW_BIT_MASK) == 0) {
				*qualification = (Bit64u)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
				printf("\nVMFAIL: VMCS link pointer must indicate shadow VMCS revision ID = %d", revision);
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
			revision &= ~BX_VMCS_SHADOW_BIT_MASK;
		}
		// If revision ID is not true then we can't load our VMCS so skip this check
		//if (revision != BX_CPU_THIS_PTR vmcs_map->get_vmcs_revision_id()) {
		//	*qualification = (Bit64u)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
		//	printf(("\nVMFAIL: VMCS link pointer incorrect revision ID %d != %d", revision, BX_CPU_THIS_PTR vmcs_map->get_vmcs_revision_id()));
		//	return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		//}


		// We're not in SMM
		if ( /*!BX_CPU_THIS_PTR in_smm || */ (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) != 0) {
			if (vm->vmcs_linkptr == VMXON_Pointer) {
				*qualification = (Bit64u)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
				printf(("\nVMFAIL: VMCS link pointer equal to current VMCS pointer"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
		else {
			// Change it for real-world example
			//if (vm->vmcs_linkptr == BX_CPU_THIS_PTR vmxonptr) {
			if (vm->vmcs_linkptr == VMXON_Pointer) {
				*qualification = (Bit64u)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
				printf(("\nVMFAIL: VMCS link pointer equal to VMXON pointer"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
	}

	//* guest.tmpDR6 = (Bit32u)VMread_natural(VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
	guest.tmpDR6 = (Bit32u)ReadInputAuditor("VMCS_GUEST_PENDING_DBG_EXCEPTIONS ", 0x0);
	if (guest.tmpDR6 & BX_CONST64(0xFFFFFFFFFFFFAFF0)) {
		printf("\nVMENTER FAIL: VMCS guest tmpDR6 reserved bits");
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	//* guest.activity_state = VMread32(VMCS_32BIT_GUEST_ACTIVITY_STATE);
	guest.activity_state = ReadInputAuditor("VMCS_32BIT_GUEST_ACTIVITY_STATE ", 0x0);

	if (guest.activity_state > BX_VMX_LAST_ACTIVITY_STATE) {
		printf("\nVMENTER FAIL: VMCS guest activity state %d", guest.activity_state);
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	if (guest.activity_state == BX_ACTIVITY_STATE_HLT) {
		if (guest.sregs[BX_SEG_REG_SS].cache.dpl != 0) {
			printf("\nVMENTER FAIL: VMCS guest HLT state with SS.DPL=%d", guest.sregs[BX_SEG_REG_SS].cache.dpl);
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	//* guest.interruptibility_state = VMread32(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE);
	guest.interruptibility_state = ReadInputAuditor("VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE ", 0x0);
	if (guest.interruptibility_state & ~BX_VMX_INTERRUPTIBILITY_STATE_MASK) {
		printf(("\nVMENTER FAIL: VMCS guest interruptibility state broken"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	if (guest.interruptibility_state & 0x3) {
		if (guest.activity_state != BX_ACTIVITY_STATE_ACTIVE) {
			printf("\nVMENTER FAIL: VMCS guest interruptibility state broken when entering non active CPU state %d", guest.activity_state);
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	if ((guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) &&
		(guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS))
	{
		printf(("\nVMENTER FAIL: VMCS guest interruptibility state broken"));
		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	}

	if ((guest.rflags & EFlagsIFMask) == 0) {
		if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) {
			printf(("\nVMENTER FAIL: VMCS guest interrupts can't be blocked by STI when EFLAGS.IF = 0"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	if (VMENTRY_INJECTING_EVENT(vm->vmentry_interr_info)) {
		unsigned event_type = (vm->vmentry_interr_info >> 8) & 7;
		unsigned vector = vm->vmentry_interr_info & 0xff;
		if (event_type == BX_EXTERNAL_INTERRUPT) {
			if ((guest.interruptibility_state & 0x3) != 0 || (guest.rflags & EFlagsIFMask) == 0) {
				printf(("\nVMENTER FAIL: VMCS guest interrupts blocked when injecting external interrupt"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
		if (event_type == BX_NMI) {
			if ((guest.interruptibility_state & 0x3) != 0) {
				printf(("\nVMENTER FAIL: VMCS guest interrupts blocked when injecting NMI"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
		if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
			printf(("\nVMENTER FAIL: No guest interruptions are allowed when entering Wait-For-Sipi state"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
		if (guest.activity_state == BX_ACTIVITY_STATE_SHUTDOWN && event_type != BX_NMI && vector != BX_MC_EXCEPTION) {
			printf(("\nVMENTER FAIL: Only NMI or #MC guest interruption is allowed when entering shutdown state"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	if (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) {
		if (!(guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED)) {
			printf(("\nVMENTER FAIL: VMCS SMM guest should block SMI"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}

		if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
			printf(("\nVMENTER FAIL: The activity state must not indicate the wait-for-SIPI state if entering to SMM guest"));
			return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
		}
	}

	// We're not in SMM so let's skip this check
	// if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED) {
	//	if (!BX_CPU_THIS_PTR in_smm) {
	//		printf(("\nVMENTER FAIL: VMCS SMI blocked when not in SMM mode"));
	//		return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
	//	}
	//}

	if (!x86_64_guest && (guest.cr4 & BX_CR4_PAE_MASK) != 0 && (guest.cr0 & BX_CR0_PG_MASK) != 0) {
#if BX_SUPPORT_VMX >= 2
		if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) {
			for (n = 0; n < 4; n++) {


				if (n == 0)
				{

					//* guest.pdptr[n] = VMread64(VMCS_64BIT_GUEST_IA32_PDPTE0 + 2 * n);
					guest.pdptr[n] = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_PDPTE0 ", 0x0);

				}
				if (n == 1)
				{

					//* guest.pdptr[n] = VMread64(VMCS_64BIT_GUEST_IA32_PDPTE0 + 2 * n);
					guest.pdptr[n] = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_PDPTE1 ", 0x0);

				}
				if (n == 2)
				{

					//* guest.pdptr[n] = VMread64(VMCS_64BIT_GUEST_IA32_PDPTE0 + 2 * n);
					guest.pdptr[n] = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_PDPTE2 ", 0x0);

				}
				if (n == 3)
				{

					//* guest.pdptr[n] = VMread64(VMCS_64BIT_GUEST_IA32_PDPTE0 + 2 * n);
					guest.pdptr[n] = ReadInputAuditor("VMCS_64BIT_GUEST_IA32_PDPTE3 ", 0x0);

				}

			}

			if (!CheckPDPTR(guest.pdptr)) {
				*qualification = VMENTER_ERR_GUEST_STATE_PDPTR_LOADING;
				printf(("\nVMENTER: EPT Guest State PDPTRs Checks Failed"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
		else
#endif
		{
			if (!CheckPDPTR((Bit64u*)guest.cr3)) {
				*qualification = VMENTER_ERR_GUEST_STATE_PDPTR_LOADING;
				printf(("\nVMENTER: Guest State PDPTRs Checks Failed"));
				return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
			}
		}
	}

	//
	// Load Guest State -> VMENTER
	//


	// We're not interested to continue any more, because all the checks are performed.
	printf("\nAll the guest-state checks are performed successfully.");

	return VMXERR_NO_ERROR;
}


BOOLEAN CheckVMXState(VMCS_CACHE *pVm, BOOLEAN IsVMResume, UINT64 VMXON_Pointer, INT32 RevisionID,
	UINT32 _vmx_pin_vmexec_ctrl_supported_bits, UINT32 _vmx_proc_vmexec_ctrl_supported_bits,
	UINT32 _vmx_vmexec_ctrl2_supported_bits, UINT32 _vmx_vmexit_ctrl_supported_bits,
	UINT32 _vmx_vmentry_ctrl_supported_bits, UINT64 _vmx_ept_vpid_cap_supported_bits,
	UINT64 _vmx_vmfunc_supported_bits, UINT32 _cr0_suppmask_0, UINT32 _cr0_suppmask_1,
	UINT32 _cr4_suppmask_0, UINT32 _cr4_suppmask_1)
{
	// Set VMX-Capabilities


	/*
	Bit32u vmx_pin_vmexec_ctrl_supported_bits;
	Bit32u vmx_proc_vmexec_ctrl_supported_bits;
	Bit32u vmx_vmexec_ctrl2_supported_bits;
	Bit32u vmx_vmexit_ctrl_supported_bits;
	Bit32u vmx_vmentry_ctrl_supported_bits;
	Bit64u vmx_ept_vpid_cap_supported_bits;
	Bit64u vmx_vmfunc_supported_bits;
	*/

	vmx_pin_vmexec_ctrl_supported_bits = _vmx_pin_vmexec_ctrl_supported_bits;
	vmx_proc_vmexec_ctrl_supported_bits = _vmx_proc_vmexec_ctrl_supported_bits;
	vmx_vmexec_ctrl2_supported_bits = _vmx_vmexec_ctrl2_supported_bits;
	vmx_vmexit_ctrl_supported_bits = _vmx_vmexit_ctrl_supported_bits;
	vmx_vmentry_ctrl_supported_bits = _vmx_vmentry_ctrl_supported_bits;
	vmx_ept_vpid_cap_supported_bits = _vmx_ept_vpid_cap_supported_bits;
	vmx_vmfunc_supported_bits = _vmx_ept_vpid_cap_supported_bits;

	// If bit in X_FIXED0 is 1 then it should be also fixed 1
	// If bit in X_FIXED1 is 0 then it should be also fixed to 0
	// So FIXED0 and FIXED1 cannot have different values
	// X_FIXED1 is almost 0xffffffff means that all of the are allowed to be 1

	/*
	The restrictions on CR0.PE and CR0.PG imply that VMX operation is supported only in paged protected mode.
	Therefore, guest software cannot be run in unpaged protected mode or in real-address mode.

	Later processors support a VM-execution control called “unrestricted guest”.
	If this control is 1, CR0.PE and CR0.PG may be 0 in VMX non-root
	operation (even if the capability MSR IA32_VMX_CR0_FIXED0 reports otherwise).
	Such processors allow guest software to run in unpaged protected mode or in real-address mode.


	*/

	cr4_suppmask_0 = _cr4_suppmask_0;
	cr4_suppmask_1 = _cr4_suppmask_1;
	cr0_suppmask_0 = _cr0_suppmask_0;
	cr0_suppmask_1 = _cr0_suppmask_1;

	efer_suppmask = ReadInputAuditor("\n[*] Please insert IA32_EFER Reserved bit mask , if don't know what it is then let it to default value (0xFFFFFFFF)", 0xffffffff);

	init_vmx_extensions_bitmask();

	// If we're here then we're definitely in protected-mode and long-mode and we're not in vmx so let's skip the checks
	//if (!BX_CPU_THIS_PTR in_vmx || !protected_mode() || BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_COMPAT)
	//	exception(BX_UD_EXCEPTION, 0);

	unsigned vmlaunch = 0;

	if (IsVMResume) {
		printf(("\n\n[*] VMLAUNCH VMCS CALLED ON CURRENT PROCESSOR VMCS PTR."));
		vmlaunch = 1;
	}
	else {
		printf(("\n\n[*] VMRESUME VMCS CALLED ON CURRENT PROCESSOR VMCS PTR."));
	}

	// We're not in guest state so let's skip this check.
	//if (BX_CPU_THIS_PTR in_vmx_guest) {
	//	VMexit(vmlaunch ? VMX_VMEXIT_VMLAUNCH : VMX_VMEXIT_VMRESUME, 0);
	//}

	// Our test case is a driver with CPL = 0, skip this step
	//if (CPL != 0) {
	//	printf(("\n%s: with CPL!=0 cause #GP(0)", i->getIaOpcodeNameShort()));
	//	exception(BX_GP_EXCEPTION, 0);
	//}

	// This test is also not valid as long as VMCS PTR should be loaded successfully, previously.
	//if (BX_CPU_THIS_PTR vmcsptr == BX_INVALID_VMCSPTR) {
	//	printf(("\nVMFAIL: VMLAUNCH with invalid VMCS ptr !"));
	//	VMfailInvalid();	
	//}

	printf("\n\n[*] Make sure interrupts are not blocked by MOV_SS \n");
	/*if (interrupts_inhibited(BX_INHIBIT_INTERRUPTS_BY_MOVSS)) {
		printf(("\nVMFAIL: VMLAUNCH with interrupts blocked by MOV_SS !"));
		VMfail(VMXERR_VMENTRY_MOV_SS_BLOCKING);

	}*/

	//# Bit32u launch_state = VMread32(VMCS_LAUNCH_STATE_FIELD_ENCODING);
	Bit32u launch_state = ReadInputAuditor("VMCS_LAUNCH_STATE_FIELD_ENCODING ", 0x0);


	if (vmlaunch) {
		if (launch_state != VMCS_STATE_CLEAR) {
			printf(("\nVMFAIL: VMLAUNCH with non-clear VMCS!"));
			VMfail(VMXERR_VMLAUNCH_NON_CLEAR_VMCS);

		}
	}
	else {
		if (launch_state != VMCS_STATE_LAUNCHED) {
			printf(("\nVMFAIL: VMRESUME with non-launched VMCS!"));
			VMfail(VMXERR_VMRESUME_NON_LAUNCHED_VMCS);

		}
	}

	///////////////////////////////////////////////////////
	// STEP 1: Load and Check VM-Execution Control Fields
	// STEP 2: Load and Check VM-Exit Control Fields
	// STEP 3: Load and Check VM-Entry Control Fields
	///////////////////////////////////////////////////////

	VMX_error_code error = VMenterLoadCheckVmControls(pVm);
	if (error != VMXERR_NO_ERROR) {
		VMfail(error);

	}

	///////////////////////////////////////////////////////
	// STEP 4: Load and Check Host State
	///////////////////////////////////////////////////////

	error = VMenterLoadCheckHostState(pVm);
	if (error != VMXERR_NO_ERROR) {
		VMfail(error);

	}

	///////////////////////////////////////////////////////
	// STEP 5: Load and Check Guest State
	///////////////////////////////////////////////////////

	Bit64u qualification = VMENTER_ERR_NO_ERROR;
	Bit32u state_load_error = VMenterLoadCheckGuestState(pVm, &qualification, VMXON_Pointer, RevisionID);
	if (state_load_error) {
		printf(("\nVMEXIT: Guest State Checks Failed"));
		VMexit(VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE | (1 << 31), qualification);
	}
	pVm->vmentry_msr_load_addr = ReadInputAuditor("vmentry_msr_load_addr ", 0x0);
	pVm->vmentry_msr_load_cnt = ReadInputAuditor("vmentry_msr_load_cnt ", 0x0);

	// Not needed :)
	/*
	Bit32u msr = LoadMSRs(pVm->vmentry_msr_load_cnt, pVm->vmentry_msr_load_addr);
	if (msr) {
		printf("\nVMEXIT: Error when loading guest MSR 0x%08x", msr);
		VMexit(VMX_VMEXIT_VMENTRY_FAILURE_MSR | (1 << 31), msr);
	}
	*/

	///////////////////////////////////////////////////////
	// STEP 6: Update VMCS 'launched' state
	///////////////////////////////////////////////////////

	// We're not intersted to emulating after these code, which means the VMCS configuration successfully checked.
	goto ReturnTrue;

	//if (vmlaunch) VMwrite32(VMCS_LAUNCH_STATE_FIELD_ENCODING, VMCS_STATE_LAUNCHED);

	/*
	   Check settings of VMX controls and host-state area;
	   if invalid settings
	   THEN VMfailValid(VM entry with invalid VMX-control field(s)) or
			VMfailValid(VM entry with invalid host-state field(s)) or
			VMfailValid(VM entry with invalid executive-VMCS pointer)) or
			VMfailValid(VM entry with non-launched executive VMCS) or
			VMfailValid(VM entry with executive-VMCS pointer not VMXON pointer)
			VMfailValid(VM entry with invalid VM-execution control fields in executive VMCS)
	   (as appropriate);
	   else
			Attempt to load guest state and PDPTRs as appropriate;
			clear address-range monitoring;
			if failure in checking guest state or PDPTRs
				THEN VM entry fails (see Section 22.7, in the IntelR 64 and IA-32 Architectures Software Developer's Manual, Volume 3B);
			else
					Attempt to load MSRs from VM-entry MSR-load area;
					if failure
						THEN VM entry fails (see Section 22.7, in the IntelR 64 and IA-32 Architectures Software Developer's Manual, Volume 3B);
					else {
							if VMLAUNCH
								THEN launch state of VMCS <== "launched";
									if in SMM and "entry to SMM" VM-entry control is 0
									THEN
										if "deactivate dual-monitor treatment" VM-entry control is 0
												THEN SMM-transfer VMCS pointer <== current-VMCS pointer;
											FI;
											if executive-VMCS pointer is VMX pointer
												THEN current-VMCS pointer <== VMCS-link pointer;
											else current-VMCS pointer <== executive-VMCS pointer;
									FI;
									leave SMM;
							FI;
							VMsucceed();
					}
			 FI;
	   FI;
	*/

ReturnTrue:
	printf("\n\n[*] All the states checked successfully, now if there wasn't any problem you can execute VMLAUNCH");
	return TRUE;

ReturnFalse:
	printf("\n\n[*] The was problem in your configuration, please to solve the error before executing VMLAUNCH.");
	return FALSE;
}