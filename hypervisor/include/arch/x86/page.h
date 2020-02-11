/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PAGE_H
#define PAGE_H

#define PAGE_SHIFT	12U
#define PAGE_SIZE	(1U << PAGE_SHIFT)
#define PAGE_MASK	0xFFFFFFFFFFFFF000UL

/* size of the low MMIO address space: 2GB */
#define PLATFORM_LO_MMIO_SIZE	0x80000000UL

/* size of the high MMIO address space: 1GB */
#define PLATFORM_HI_MMIO_SIZE	0x40000000UL

#define MAX_STITCHED_EPTP		1

#define PML4_PAGE_NUM(size)	1UL
#define PDPT_PAGE_NUM(size)	(((size) + PML4E_SIZE - 1UL) >> PML4E_SHIFT)
#define PD_PAGE_NUM(size)	(((size) + PDPTE_SIZE - 1UL) >> PDPTE_SHIFT)
#define PT_PAGE_NUM(size)	(((size) + PDE_SIZE - 1UL) >> PDE_SHIFT)

/*
 * The size of the guest physical address space, covered by the EPT page table of a VM.
 * With the assumptions:
 * - The GPA of DRAM & MMIO are contiguous.
 * - Guest OS won't re-program device MMIO bars to the address not covered by
 *   this EPT_ADDRESS_SPACE.
 */
#define EPT_ADDRESS_SPACE(size)	(((size) != 0UL) ? ((size) + PLATFORM_LO_MMIO_SIZE + PLATFORM_HI_MMIO_SIZE) : 0UL)

#define TRUSTY_PML4_PAGE_NUM(size)	(1UL)
#define TRUSTY_PDPT_PAGE_NUM(size)	(1UL)
#define TRUSTY_PD_PAGE_NUM(size)	(PD_PAGE_NUM(size))
#define TRUSTY_PT_PAGE_NUM(size)	(PT_PAGE_NUM(size))
#define TRUSTY_PGTABLE_PAGE_NUM(size)	\
(TRUSTY_PML4_PAGE_NUM(size) + TRUSTY_PDPT_PAGE_NUM(size) + TRUSTY_PD_PAGE_NUM(size) + TRUSTY_PT_PAGE_NUM(size))

struct acrn_vm;

struct page {
	uint8_t contents[PAGE_SIZE];
} __aligned(PAGE_SIZE);

union pgtable_pages_info {
	struct {
		struct page *pml4_base;
		struct page *pdpt_base;
		struct page *pd_base;
		struct page *pt_base;
	} ppt;
	struct {
		uint64_t top_address_space;
		uint16_t operating_ept_id;
		uint16_t operating_ept_count;
		struct page *nworld_pml4_base;
		struct page *nworld_pdpt_base;
		struct page *nworld_pd_base;
		struct page *nworld_pt_base;

		struct page *para_pml4_base;
		struct page *para_pdpt_base;
		struct page *para_pd_base;
		struct page *para_pt_base;

		struct page *sworld_pgtable_base;
		struct page *sworld_memory_base;
	} ept;
};

struct memory_ops {
	union pgtable_pages_info *info;
	uint64_t (*get_default_access_right)(void);
	uint64_t (*pgentry_present)(uint64_t pte);
	struct page *(*get_pml4_page)(const union pgtable_pages_info *info);
	struct page *(*get_pdpt_page)(const union pgtable_pages_info *info, uint64_t gpa);
	struct page *(*get_pd_page)(const union pgtable_pages_info *info, uint64_t gpa);
	struct page *(*get_pt_page)(const union pgtable_pages_info *info, uint64_t gpa);
	struct page *(*get_para_pml4_page)(const union pgtable_pages_info *info);
	struct page *(*get_para_pdpt_page)(const union pgtable_pages_info *info, uint64_t gpa);
	struct page *(*get_para_pd_page)(const union pgtable_pages_info *info, uint64_t gpa);
	struct page *(*get_para_pt_page)(const union pgtable_pages_info *info, uint64_t gpa);
	uint16_t (*get_operating_ept_id)(const union pgtable_pages_info *info);
	void (*set_operating_ept_id)(union pgtable_pages_info *info, uint16_t vm_id, uint16_t id);
	uint16_t (*get_operating_ept_count)(const union pgtable_pages_info *info);
	int32_t (*alloc_operating_ept)(union pgtable_pages_info *info);
	void *(*get_sworld_memory_base)(const union pgtable_pages_info *info);
	void (*clflush_pagewalk)(const void *p);
	void (*tweak_exe_right)(uint64_t *entry);
	void (*recover_exe_right)(uint64_t *entry);
};

extern const struct memory_ops ppt_mem_ops;
void init_ept_mem_ops(struct memory_ops *mem_ops, uint16_t vm_id);
void *get_reserve_sworld_memory_base(void);

#endif /* PAGE_H */
