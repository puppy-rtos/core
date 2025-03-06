/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <puppy_core.h>

#define PUP_GET_CPU_ID() 0

#ifdef PUP_ARCH_CORTEX_M

__attribute__((always_inline)) inline pup_base_t arch_irq_lock(void) {
    pup_base_t key;

    __asm volatile(
    "mrs %0, PRIMASK;"
        "cpsid i"
        : "=r" (key)
        :
        : "memory");

    return key;
}

__attribute__((always_inline)) inline void arch_irq_unlock(pup_base_t key) {
    __asm volatile(
    "msr PRIMASK, %0;"
        : "=r" (key)
        : : "memory");
}

__attribute__((always_inline)) inline pup_uint8_t arch_irq_locked(pup_base_t key) {
    return key != 0U;
}
__attribute__((always_inline)) inline pup_uint8_t arch_in_irq(void) {
    volatile int tmp = 0;
    __asm volatile("mrs %0, IPSR;"
    : "=r" (tmp)
        :
        : "memory");
    return (tmp & 0x1f) != 0U;
}

pup_weak void arch_spin_lock_init(arch_spinlock_t* lock) {

}

pup_weak void arch_spin_lock(arch_spinlock_t* lock) {

}

pup_weak void arch_spin_unlock(arch_spinlock_t* lock) {

}

typedef struct {
    pup_uint32_t CPUID;                  /*!< Offset: 0x000 (R/ )  CPUID Base Register */
    pup_uint32_t ICSR;                   /*!< Offset: 0x004 (R/W)  Interrupt Control and State Register */
    pup_uint32_t RESERVED0;
    pup_uint32_t AIRCR;                  /*!< Offset: 0x00C (R/W)  Application Interrupt and Reset Control Register */
    pup_uint32_t SCR;                    /*!< Offset: 0x010 (R/W)  System Control Register */
    pup_uint32_t CCR;                    /*!< Offset: 0x014 (R/W)  Configuration Control Register */
    pup_uint32_t RESERVED1;
    pup_uint32_t SHPR[2U];               /*!< Offset: 0x01C (R/W)  System Handlers Priority Registers. [0] is RESERVED */
    pup_uint32_t SHCSR;                  /*!< Offset: 0x024 (R/W)  System Handler Control and State Register */
} SCB_Type;
#define SCS_BASE            (0xE000E000UL)                             /*!< System Control Space Base Address */
#define SCB_BASE            (SCS_BASE +  0x0D00UL)                    /*!< System Control Block Base Address */
#define SCB                 ((SCB_Type       *)     SCB_BASE         ) 
#define SCB_ICSR_PENDSVSET_Pos             28U                                            /*!< SCB ICSR: PENDSVSET Position */
#define SCB_ICSR_PENDSVSET_Msk             (1UL << SCB_ICSR_PENDSVSET_Pos)    

struct arch_thread {
    pup_uint32_t stack_ptr;
};

struct arch_cpu {
    void* from_sp_swap;
    void* to_sp_swap;
} arch_cpu[PUP_CPU_NR] = { 0 };

typedef struct exc_stack_frame {
    pup_uint32_t r0;
    pup_uint32_t r1;
    pup_uint32_t r2;
    pup_uint32_t r3;
    pup_uint32_t r12;
    pup_uint32_t lr;
    pup_uint32_t pc;
    pup_uint32_t psr;
}_esf_t;

typedef struct stack_frame {
    /* r4 ~ r11 register */
    pup_uint32_t r4;
    pup_uint32_t r5;
    pup_uint32_t r6;
    pup_uint32_t r7;
    pup_uint32_t r8;
    pup_uint32_t r9;
    pup_uint32_t r10;
    pup_uint32_t r11;

    _esf_t esf;
}_sf_t;

void* arch_new_thread(void* entry,
                      void* param1,
                      void* param2,
                      void* stack_addr,
                      pup_uint32_t stack_size) {
    pup_uint32_t i;
    struct arch_thread* arch_data;
    _sf_t* sf;

    arch_data = (struct arch_thread*)PUP_ALIGN_DOWN(((pup_uint32_t)stack_addr + stack_size) - sizeof(struct arch_thread), 8UL);
    sf = (_sf_t*)PUP_ALIGN_DOWN((pup_uint32_t)arch_data - sizeof(_sf_t), 8UL);

    /* init all register */
    for (i = 0; i < sizeof(_sf_t) / sizeof(pup_uint32_t); i++) {
        ((pup_uint32_t*)sf)[i] = 0xdeadbeef;
    }

    sf->esf.r0 = (pup_uint32_t)param1;
    sf->esf.r1 = (pup_uint32_t)param2;
    sf->esf.r2 = 0;
    sf->esf.r3 = 0;
    sf->esf.r12 = 0;
    sf->esf.lr = 0;
    sf->esf.pc = (pup_uint32_t)entry;
    sf->esf.psr = 0x01000000UL;

    arch_data->stack_ptr = ((pup_uint32_t)sf);
    return arch_data;
}

void arch_swap(void* from, void* to) {
#ifndef P_ARCH_CORTEX_M0
    __asm ("CLREX");
#endif
    arch_cpu[PUP_GET_CPU_ID()].from_sp_swap = from ? &((struct arch_thread*)from)->stack_ptr : PUP_NULL;
    arch_cpu[PUP_GET_CPU_ID()].to_sp_swap = &((struct arch_thread*)to)->stack_ptr;

    /* set pending bit to make sure we will take a PendSV exception */
    SCB->ICSR |= SCB_ICSR_PENDSVSET_Msk;

}
extern void* arch_get_from_sp(void);
extern void* arch_get_to_sp(void);

void* arch_get_from_sp(void) {
    return arch_cpu[PUP_GET_CPU_ID()].from_sp_swap;
}
void* arch_get_to_sp(void) {
    return arch_cpu[PUP_GET_CPU_ID()].to_sp_swap;
}

__attribute__((naked)) void PendSV_Handler(void) {
    // disable interrupt to protect context switch
    __asm (
    "    MRS     r2, PRIMASK\n"
        "    CPSID   I\n"

        "    PUSH    {r2, lr}\n"
        "    BL      arch_get_from_sp\n"
        "    POP     {r2, lr}\n"
        "    CBZ     r0, switch_to_thread \n"   // skip register save at the first time

        "    LDR     r1, [r0]\n"
        "    MRS     r1, psp              \n"   // get from thread stack pointer

        "    STMFD   r1!, {r4 - r11}      \n"   // push r4 - r11 register
        "    STR     r1, [r0]             \n"   // update from thread stack pointer

        "switch_to_thread:\n"
        "    PUSH    {r2, lr}\n"
        "    BL      arch_get_to_sp\n"
        "    POP     {r2, lr}\n"

        "    LDR     r1, [r0]\n"
        "    LDMFD   r1!, {r4 - r11}\n"         // pop r4 - r11 register
        "    MSR     psp, r1\n"//  update stack pointer

        "    PUSH    {r2, lr}\n"
        "    BL      pup_sched_swap_done_cb\n"
        "    POP     {r2, lr}\n"

        // restore interrupt
        "    MSR     PRIMASK, r2\n"

        "    ORR     lr, lr, #0x04\n"
        "    BX      lr\n"
        );
}

struct exception_info {
    pup_uint32_t exc_return;
    struct stack_frame stack_frame;
};

static void dump_contex_esf(_esf_t* esf) {
    PUP_PRINTK("psr: 0x%08x\n", esf->psr);
    PUP_PRINTK("r00: 0x%08x\n", esf->r0);
    PUP_PRINTK("r01: 0x%08x\n", esf->r1);
    PUP_PRINTK("r02: 0x%08x\n", esf->r2);
    PUP_PRINTK("r03: 0x%08x\n", esf->r3);
    PUP_PRINTK("r12: 0x%08x\n", esf->r12);
    PUP_PRINTK(" lr: 0x%08x\n", esf->lr);
    PUP_PRINTK(" pc: 0x%08x\n", esf->pc);
}

static void dump_contex(struct stack_frame* context) {
    PUP_PRINTK("psr: 0x%08x\n", context->esf.psr);
    PUP_PRINTK("r00: 0x%08x\n", context->esf.r0);
    PUP_PRINTK("r01: 0x%08x\n", context->esf.r1);
    PUP_PRINTK("r02: 0x%08x\n", context->esf.r2);
    PUP_PRINTK("r03: 0x%08x\n", context->esf.r3);
    PUP_PRINTK("r04: 0x%08x\n", context->r4);
    PUP_PRINTK("r05: 0x%08x\n", context->r5);
    PUP_PRINTK("r06: 0x%08x\n", context->r6);
    PUP_PRINTK("r07: 0x%08x\n", context->r7);
    PUP_PRINTK("r08: 0x%08x\n", context->r8);
    PUP_PRINTK("r09: 0x%08x\n", context->r9);
    PUP_PRINTK("r10: 0x%08x\n", context->r10);
    PUP_PRINTK("r11: 0x%08x\n", context->r11);
    PUP_PRINTK("r12: 0x%08x\n", context->esf.r12);
    PUP_PRINTK(" lr: 0x%08x\n", context->esf.lr);
    PUP_PRINTK(" pc: 0x%08x\n", context->esf.pc);
}

void arch_hardfault_exception(struct exception_info* exception_info) {
    struct stack_frame* context = &exception_info->stack_frame;

    if (exception_info->exc_return & (1 << 2)) {
        PUP_PRINTK("hard fault on thread\n");
    } else {
        PUP_PRINTK("hard fault on handler\n");
    }

    if ((exception_info->exc_return & 0x10) == 0) {
        PUP_PRINTK("FPU active!\n");
    }

    dump_contex(context);

    while (1);
}

__attribute__((naked)) void HardFault_Handler(void) {
    __asm ("    TST     lr, #0x04\n"
    "    ITE     EQ\n"
        "    MRSEQ   r0, msp\n"
        "    MRSNE   r0, psp\n"
        "    STMFD   r0!, {r4 - r11}\n"   // push r4 - r11 register
        "    STMFD   r0!, {lr}\n"

        "    TST     lr, #0x04\n"
        "    ITE     EQ\n"
        "    MSREQ   msp, r0\n"
        "    MSRNE   psp, r0\n"

        "    PUSH    {lr}\n"
        "    BL      arch_hardfault_exception\n"
        "    POP     {lr}\n"

        "    ORR     lr, lr, #0x04\n"
        "    BX      lr\n"
        );
}

#endif