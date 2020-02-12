/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <types.h>
#include <rtl.h>
#include <pgtable.h>
#include <page.h>
#include <mmu.h>
#include <trusty.h>
#include <vtd.h>
#include <vm_configurations.h>
#include <security.h>

static struct page ppt_pml4_pages[PML4_PAGE_NUM(CONFIG_PLATFORM_RAM_SIZE + PLATFORM_LO_MMIO_SIZE)];
static struct page ppt_pdpt_pages[PDPT_PAGE_NUM(CONFIG_PLATFORM_RAM_SIZE + PLATFORM_LO_MMIO_SIZE)];
static struct page ppt_pd_pages[PD_PAGE_NUM(CONFIG_PLATFORM_RAM_SIZE + PLATFORM_LO_MMIO_SIZE)];

/* ppt: pripary page table */
static union pgtable_pages_info ppt_pages_info = {
	.ppt = {
		.pml4_base = ppt_pml4_pages,
		.pdpt_base = ppt_pdpt_pages,
		.pd_base = ppt_pd_pages,
	}
};

static inline uint64_t ppt_get_default_access_right(void)
{
	return (PAGE_PRESENT | PAGE_RW | PAGE_USER);
}

static inline void ppt_clflush_pagewalk(const void* etry __attribute__((unused)))
{
}

static inline uint64_t ppt_pgentry_present(uint64_t pte)
{
	return pte & PAGE_PRESENT;
}

static inline struct page *ppt_get_pml4_page(const union pgtable_pages_info *info)
{
	struct page *pml4_page = info->ppt.pml4_base;
	(void)memset(pml4_page, 0U, PAGE_SIZE);
	return pml4_page;
}

static inline struct page *ppt_get_pdpt_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pdpt_page = info->ppt.pdpt_base + (gpa >> PML4E_SHIFT);
	(void)memset(pdpt_page, 0U, PAGE_SIZE);
	return pdpt_page;
}

static inline struct page *ppt_get_pd_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pd_page = info->ppt.pd_base + (gpa >> PDPTE_SHIFT);
	(void)memset(pd_page, 0U, PAGE_SIZE);
	return pd_page;
}

static inline void nop_tweak_exe_right(uint64_t *entry __attribute__((unused))) {}
static inline void nop_recover_exe_right(uint64_t *entry __attribute__((unused))) {}

const struct memory_ops ppt_mem_ops = {
	.info = &ppt_pages_info,
	.get_default_access_right = ppt_get_default_access_right,
	.pgentry_present = ppt_pgentry_present,
	.get_pml4_page = ppt_get_pml4_page,
	.get_pdpt_page = ppt_get_pdpt_page,
	.get_pd_page = ppt_get_pd_page,
	.clflush_pagewalk = ppt_clflush_pagewalk,
	.tweak_exe_right = nop_tweak_exe_right,
	.recover_exe_right = nop_recover_exe_right,
};

static struct page sos_vm_pml4_pages[PML4_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_SOS_RAM_SIZE))];
static struct page sos_vm_pdpt_pages[PDPT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_SOS_RAM_SIZE))];
static struct page sos_vm_pd_pages[PD_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_SOS_RAM_SIZE))];
static struct page sos_vm_pt_pages[PT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_SOS_RAM_SIZE))];

/* uos_nworld_pml4_pages[i] is ...... of UOS i (whose vm_id = i +1) */
static struct page uos_nworld_pml4_pages[CONFIG_MAX_VM_NUM - 1U][PML4_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page uos_nworld_pdpt_pages[CONFIG_MAX_VM_NUM - 1U][PDPT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page uos_nworld_pd_pages[CONFIG_MAX_VM_NUM - 1U][PD_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page uos_nworld_pt_pages[CONFIG_MAX_VM_NUM - 1U][PT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];

/* pos_nworld_pml4_pages[i] is ...... of Para kernel EPT i */
/* Because the space is limited, we can only afford one machine to have multiple EPT storage */
static struct page pos_nworld_pml4_pages[1U][MAX_STITCHED_EPTP][PML4_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page pos_nworld_pdpt_pages[1U][MAX_STITCHED_EPTP][PDPT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page pos_nworld_pd_pages[1U][MAX_STITCHED_EPTP][PD_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];
static struct page pos_nworld_pt_pages[1U][MAX_STITCHED_EPTP][PT_PAGE_NUM(EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE))];

static struct page uos_sworld_pgtable_pages[CONFIG_MAX_VM_NUM - 1U][TRUSTY_PGTABLE_PAGE_NUM(TRUSTY_RAM_SIZE)];
/* pre-assumption: TRUSTY_RAM_SIZE is 2M aligned */
static struct page uos_sworld_memory[CONFIG_MAX_VM_NUM - 1U][TRUSTY_RAM_SIZE >> PAGE_SHIFT] __aligned(MEM_2M);

/* ept: extended page table*/
static union pgtable_pages_info ept_pages_info[CONFIG_MAX_VM_NUM] = {
	{
		.ept = {
			.top_address_space = EPT_ADDRESS_SPACE(CONFIG_SOS_RAM_SIZE),
			.nworld_pml4_base = sos_vm_pml4_pages,
			.nworld_pdpt_base = sos_vm_pdpt_pages,
			.nworld_pd_base = sos_vm_pd_pages,
			.nworld_pt_base = sos_vm_pt_pages,
		},
	},
};

void *get_reserve_sworld_memory_base(void)
{
	return uos_sworld_memory;
}

static inline uint64_t ept_get_default_access_right(void)
{
	return EPT_RWX;
}

static inline uint64_t ept_pgentry_present(uint64_t pte)
{
	return pte & EPT_RWX;
}

static inline void ept_clflush_pagewalk(const void* etry)
{
	iommu_flush_cache(etry, sizeof(uint64_t));
}

static inline struct page *ept_get_pml4_page(const union pgtable_pages_info *info)
{
	struct page *pml4_page = info->ept.nworld_pml4_base;
	(void)memset(pml4_page, 0U, PAGE_SIZE);
	return pml4_page;
}

static inline struct page *ept_get_pdpt_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pdpt_page = info->ept.nworld_pdpt_base + (gpa >> PML4E_SHIFT);
	(void)memset(pdpt_page, 0U, PAGE_SIZE);
	return pdpt_page;
}

static inline struct page *ept_get_pd_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pd_page;
	if (gpa < TRUSTY_EPT_REBASE_GPA) {
		pd_page = info->ept.nworld_pd_base + (gpa >> PDPTE_SHIFT);
	} else {
		pd_page = info->ept.sworld_pgtable_base + TRUSTY_PML4_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			TRUSTY_PDPT_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) + ((gpa - TRUSTY_EPT_REBASE_GPA) >> PDPTE_SHIFT);
	}
	(void)memset(pd_page, 0U, PAGE_SIZE);
	return pd_page;
}

static inline struct page *ept_get_pt_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pt_page;
	if (gpa < TRUSTY_EPT_REBASE_GPA) {
		pt_page = info->ept.nworld_pt_base + (gpa >> PDE_SHIFT);
	} else {
		pt_page = info->ept.sworld_pgtable_base + TRUSTY_PML4_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			TRUSTY_PDPT_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) + TRUSTY_PD_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			((gpa - TRUSTY_EPT_REBASE_GPA) >> PDE_SHIFT);
	}
	(void)memset(pt_page, 0U, PAGE_SIZE);
	return pt_page;
}

static inline struct page *ept_get_para_pml4_page(const union pgtable_pages_info *info)
{
	struct page *pml4_page = info->ept.para_pml4_base;
	(void)memset(pml4_page, 0U, PAGE_SIZE);
	return pml4_page;
}

static inline struct page *ept_get_para_pdpt_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pdpt_page = info->ept.para_pdpt_base + (gpa >> PML4E_SHIFT);
	(void)memset(pdpt_page, 0U, PAGE_SIZE);
	return pdpt_page;
}

static inline struct page *ept_get_para_pd_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pd_page;
	if (gpa < TRUSTY_EPT_REBASE_GPA) {
		pd_page = info->ept.para_pd_base + (gpa >> PDPTE_SHIFT);
	} else {
		pd_page = info->ept.sworld_pgtable_base + TRUSTY_PML4_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			TRUSTY_PDPT_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) + ((gpa - TRUSTY_EPT_REBASE_GPA) >> PDPTE_SHIFT);
	}
	(void)memset(pd_page, 0U, PAGE_SIZE);
	return pd_page;
}

static inline struct page *ept_get_para_pt_page(const union pgtable_pages_info *info, uint64_t gpa)
{
	struct page *pt_page;
	if (gpa < TRUSTY_EPT_REBASE_GPA) {
		pt_page = info->ept.para_pt_base + (gpa >> PDE_SHIFT);
	} else {
		pt_page = info->ept.sworld_pgtable_base + TRUSTY_PML4_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			TRUSTY_PDPT_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) + TRUSTY_PD_PAGE_NUM(TRUSTY_EPT_REBASE_GPA) +
			((gpa - TRUSTY_EPT_REBASE_GPA) >> PDE_SHIFT);
	}
	(void)memset(pt_page, 0U, PAGE_SIZE);
	return pt_page;
}

static inline void *ept_get_sworld_memory_base(const union pgtable_pages_info *info)
{
	return info->ept.sworld_memory_base;
}

/* The function is used to disable execute right for (2MB / 1GB)large pages in EPT */
static inline void ept_tweak_exe_right(uint64_t *entry)
{
	*entry &= ~EPT_EXE;
}

/* The function is used to recover the execute right when large pages are breaking into 4KB pages
 * Hypervisor doesn't control execute right for guest memory, recovers execute right by default.
 */
static inline void ept_recover_exe_right(uint64_t *entry)
{
	*entry |= EPT_EXE;
}

static inline uint16_t ept_get_operating_ept_id(const union pgtable_pages_info *info)
{
	return info->ept.operating_ept_id;
}

static inline void ept_set_operating_ept_id(union pgtable_pages_info *info, uint16_t vm_id, uint16_t id)
{
	info->ept.operating_ept_id = id;
	info->ept.para_pml4_base = pos_nworld_pml4_pages[vm_id - 1U][id];
	info->ept.para_pdpt_base = pos_nworld_pdpt_pages[vm_id - 1U][id];
	info->ept.para_pd_base = pos_nworld_pd_pages[vm_id - 1U][id];
	info->ept.para_pt_base = pos_nworld_pt_pages[vm_id - 1U][id];
}

static inline uint16_t ept_get_operating_ept_count(const union pgtable_pages_info *info)
{
	return info->ept.operating_ept_count;
}

static inline int32_t ept_alloc_operating_ept(union pgtable_pages_info *info)
{
	if (info->ept.operating_ept_count >= MAX_STITCHED_EPTP)
		return -1;
	info->ept.operating_ept_count++;
	return 0;
}

void init_ept_mem_ops(struct memory_ops *mem_ops, uint16_t vm_id)
{
	if (vm_id != 0U) {
		ept_pages_info[vm_id].ept.top_address_space = EPT_ADDRESS_SPACE(CONFIG_UOS_RAM_SIZE);
		ept_pages_info[vm_id].ept.nworld_pml4_base = uos_nworld_pml4_pages[vm_id - 1U];
		ept_pages_info[vm_id].ept.nworld_pdpt_base = uos_nworld_pdpt_pages[vm_id - 1U];
		ept_pages_info[vm_id].ept.nworld_pd_base = uos_nworld_pd_pages[vm_id - 1U];
		ept_pages_info[vm_id].ept.nworld_pt_base = uos_nworld_pt_pages[vm_id - 1U];

		/* for now we assign para ept to first slot */
		ept_pages_info[vm_id].ept.para_pml4_base = pos_nworld_pml4_pages[vm_id - 1U][0];
		ept_pages_info[vm_id].ept.para_pdpt_base = pos_nworld_pdpt_pages[vm_id - 1U][0];
		ept_pages_info[vm_id].ept.para_pd_base = pos_nworld_pd_pages[vm_id - 1U][0];
		ept_pages_info[vm_id].ept.para_pt_base = pos_nworld_pt_pages[vm_id - 1U][0];

		ept_pages_info[vm_id].ept.sworld_pgtable_base = uos_sworld_pgtable_pages[vm_id - 1U];
		ept_pages_info[vm_id].ept.sworld_memory_base = uos_sworld_memory[vm_id - 1U];

		ept_pages_info[vm_id].ept.operating_ept_id = 0;
		ept_pages_info[vm_id].ept.operating_ept_count = 0;

		mem_ops->get_sworld_memory_base = ept_get_sworld_memory_base;
	}
	mem_ops->info = &ept_pages_info[vm_id];
	mem_ops->get_default_access_right = ept_get_default_access_right;
	mem_ops->pgentry_present = ept_pgentry_present;
	mem_ops->get_pml4_page = ept_get_pml4_page;
	mem_ops->get_pdpt_page = ept_get_pdpt_page;
	mem_ops->get_pd_page = ept_get_pd_page;
	mem_ops->get_pt_page = ept_get_pt_page;
	mem_ops->get_para_pml4_page = ept_get_para_pml4_page;
	mem_ops->get_para_pdpt_page = ept_get_para_pdpt_page;
	mem_ops->get_para_pd_page = ept_get_para_pd_page;
	mem_ops->get_para_pt_page = ept_get_para_pt_page;
	mem_ops->clflush_pagewalk = ept_clflush_pagewalk;

	/* multiple ept management */
	mem_ops->get_operating_ept_count = ept_get_operating_ept_count;
	mem_ops->get_operating_ept_id = ept_get_operating_ept_id;
	mem_ops->set_operating_ept_id = ept_set_operating_ept_id;
	mem_ops->alloc_operating_ept = ept_alloc_operating_ept;

	/* Mitigation for issue "Machine Check Error on Page Size Change" */
	if (is_ept_force_4k_ipage()) {
		mem_ops->tweak_exe_right = ept_tweak_exe_right;
		mem_ops->recover_exe_right = ept_recover_exe_right;
	} else {
		mem_ops->tweak_exe_right = nop_tweak_exe_right;
		mem_ops->recover_exe_right = nop_recover_exe_right;
	}
}
