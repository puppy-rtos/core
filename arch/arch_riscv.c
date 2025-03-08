/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <puppy_core.h>
#ifdef PUP_ARCH_RISCV
__attribute__((always_inline)) inline pup_base_t arch_irq_lock(void)
{
    pup_base_t key;

    __asm volatile("csrrci %0, mstatus, 8"
        : "=r" (key)
        :
        : "memory");

    return key;
}

__attribute__((always_inline)) inline void arch_irq_unlock(pup_base_t key)
{
    __asm volatile(
        "csrw mstatus, %1;"
        : "=r" (key)
        : "r" (key)
        : "memory");
}

__attribute__((always_inline)) inline pup_uint8_t arch_irq_locked(pup_base_t key)
{
    return !(key & 0x08);
}

pup_weak void arch_spin_lock_init(arch_spinlock_t *lock) {
    lock->flag = 0;
}

pup_weak __attribute__((always_inline)) inline void arch_spin_lock(arch_spinlock_t *lock) {
    pup_uint32_t temp;
    __asm volatile(
        "lw %[temp], (%[flag])\n" // Load from memory location pointed to by flag
        : [temp] "=&r" (temp)
        : [flag] "r" (&lock->flag) // Pass the address of lock->flag in a register
        : "memory"
    );
}

pup_weak __attribute__((always_inline)) inline void arch_spin_unlock(arch_spinlock_t *lock) {
    __asm volatile (
        "sw zero, (%[flag])\n" // Store zero to the memory location pointed to by flag
        : : [flag] "r" (&lock->flag), [zero] "r" ((pup_uint32_t)0) : "memory"
    );
}

struct arch_thread
{
    pup_uint32_t irq_flag;
    pup_uint32_t need_swap;
    pup_uint32_t stack_ptr;
};
void arch_irq_enter(void)
{
    struct arch_thread *arch;
    if (pthread_self() == PUP_NULL)
        return ;
    arch = pup_pthread_archdata(pthread_self());
    arch->irq_flag ++;

}
void arch_irq_leave(void)
{
    struct arch_thread *arch;
    if (pthread_self() == PUP_NULL)
        return ;
    arch = pup_pthread_archdata(pthread_self());
    arch->irq_flag --;
}
__attribute__((always_inline)) inline pup_uint8_t arch_in_irq(void)
{
    struct arch_thread *arch;
    if (pthread_self() == PUP_NULL)
        return PUP_TRUE;
    arch = pup_pthread_archdata(pthread_self()); 
    return (arch->irq_flag > 0);
}
typedef struct stack_frame
{
    pup_ubase_t epc;        /* epc - epc    - program counter                     */
    pup_ubase_t ra;         /* x1  - ra     - return address for jumps            */
    pup_ubase_t mstatus;    /*              - machine status register             */
    pup_ubase_t gp;         /* x3  - gp     - global pointer                      */
    pup_ubase_t tp;         /* x4  - tp     - thread pointer                      */
    pup_ubase_t t0;         /* x5  - t0     - temporary register 0                */
    pup_ubase_t t1;         /* x6  - t1     - temporary register 1                */
    pup_ubase_t t2;         /* x7  - t2     - temporary register 2                */
    pup_ubase_t s0_fp;      /* x8  - s0/fp  - saved register 0 or frame pointer   */
    pup_ubase_t s1;         /* x9  - s1     - saved register 1                    */
    pup_ubase_t a0;         /* x10 - a0     - return value or function argument 0 */
    pup_ubase_t a1;         /* x11 - a1     - return value or function argument 1 */
    pup_ubase_t a2;         /* x12 - a2     - function argument 2                 */
    pup_ubase_t a3;         /* x13 - a3     - function argument 3                 */
    pup_ubase_t a4;         /* x14 - a4     - function argument 4                 */
    pup_ubase_t a5;         /* x15 - a5     - function argument 5                 */
#ifndef __riscv_32e
    pup_ubase_t a6;         /* x16 - a6     - function argument 6                 */
    pup_ubase_t a7;         /* x17 - a7     - function argument 7                 */
    pup_ubase_t s2;         /* x18 - s2     - saved register 2                    */
    pup_ubase_t s3;         /* x19 - s3     - saved register 3                    */
    pup_ubase_t s4;         /* x20 - s4     - saved register 4                    */
    pup_ubase_t s5;         /* x21 - s5     - saved register 5                    */
    pup_ubase_t s6;         /* x22 - s6     - saved register 6                    */
    pup_ubase_t s7;         /* x23 - s7     - saved register 7                    */
    pup_ubase_t s8;         /* x24 - s8     - saved register 8                    */
    pup_ubase_t s9;         /* x25 - s9     - saved register 9                    */
    pup_ubase_t s10;        /* x26 - s10    - saved register 10                   */
    pup_ubase_t s11;        /* x27 - s11    - saved register 11                   */
    pup_ubase_t t3;         /* x28 - t3     - temporary register 3                */
    pup_ubase_t t4;         /* x29 - t4     - temporary register 4                */
    pup_ubase_t t5;         /* x30 - t5     - temporary register 5                */
    pup_ubase_t t6;         /* x31 - t6     - temporary register 6                */
#endif
}_sf_t;

void *arch_new_thread(void         *entry,
                    void        *param1,
                    void        *param2,
                    void    *stack_addr,
                    pup_uint32_t stack_size)
{
    int i;
    struct arch_thread *arch_data;
    _sf_t *sf;
    
    arch_data = (struct arch_thread *)PUP_ALIGN_DOWN(((pup_uint32_t)stack_addr + stack_size) - sizeof(struct arch_thread), 8);
    sf = (_sf_t *)PUP_ALIGN_DOWN((pup_uint32_t)arch_data - sizeof(_sf_t), 8);

    /* init all register */
    for (i = 0; i < sizeof(_sf_t) / sizeof(pup_uint32_t); i ++)
    {
        ((pup_uint32_t *)sf)[i] = 0xdeadbeef;
    }
    
    sf->a0 = (pup_uint32_t)param1;
    sf->a1 = (pup_uint32_t)param2;
    sf->ra = 0;
    sf->epc = (pup_uint32_t)entry;

    sf->mstatus = 0x1880;

    arch_data->irq_flag = 0;
    arch_data->need_swap = 0;
    arch_data->stack_ptr = ((pup_uint32_t)sf);
    return arch_data;
}
__attribute__((naked)) void riscv_swap(pup_ubase_t from, pup_ubase_t to);

int arch_need_swap(void)
{
    if (pthread_self())
    {
        struct arch_thread *arch;
        arch = pup_pthread_archdata(pthread_self());
        return arch->need_swap;
    }
    return 0;
}
void arch_need_swap_clean(void)
{
    if (pthread_self())
    {
        struct arch_thread *arch;
        arch = pup_pthread_archdata(pthread_self());
        arch->need_swap = 0;
    }
}

void *to_sp[PUP_CPU_NR] = {0};
void *arch_get_to_sp(void)
{
    return to_sp[PUP_GET_CPU_ID()];
}

void arch_swap(void *from, void* to)
{
    if (arch_in_irq() && from)
    {
        struct arch_thread *arch = from;
        arch->need_swap = 1;
        to_sp[PUP_GET_CPU_ID()] = &((struct arch_thread *)to)->stack_ptr;
        return;
    }
    pup_sched_swap_done_cb(); /* todo: 执行时的上下文不对 */
    if(from) {
        riscv_swap(&((struct arch_thread *)from)->stack_ptr, &((struct arch_thread *)to)->stack_ptr);
    } else {
        riscv_swap(PUP_NULL, &((struct arch_thread *)to)->stack_ptr);
    }
}

__attribute__((naked)) void riscv_swap(pup_ubase_t from, pup_ubase_t to)
{
    /* saved from thread context
    *     x1/ra       -> sp(0)
    *     x1/ra       -> sp(1)
    *     mstatus.mie -> sp(2)
    *     x(i)        -> sp(i-4)
    */

    __asm ("beqz a0, switch_to_thread");
#ifndef __riscv_32e
    __asm ("addi  sp,  sp, -32 * 4");
#else
    __asm ("addi  sp,  sp, -16 * 4");
#endif

    __asm ("sw sp,  (a0)");

    __asm ("sw x1,   0 * 4(sp)");
    __asm ("sw x1,   1 * 4(sp)");
    __asm ("csrr a0, mstatus");
    __asm ("andi a0, a0, 8");
    __asm ("bnez a0, save_mpie");
    __asm ("li   a0, 0x80");
    __asm ("save_mpie:");
    __asm ("sw a0,   2 * 4(sp)");

    __asm ("sw x4,   4 * 4(sp)");
    __asm ("sw x5,   5 * 4(sp)");
    __asm ("sw x6,   6 * 4(sp)");
    __asm ("sw x7,   7 * 4(sp)");
    __asm ("sw x8,   8 * 4(sp)");
    __asm ("sw x9,   9 * 4(sp)");
    __asm ("sw x10, 10 * 4(sp)");
    __asm ("sw x11, 11 * 4(sp)");
    __asm ("sw x12, 12 * 4(sp)");
    __asm ("sw x13, 13 * 4(sp)");
    __asm ("sw x14, 14 * 4(sp)");
    __asm ("sw x15, 15 * 4(sp)");
#ifndef __riscv_32e
    __asm ("sw x16, 16 * 4(sp)");
    __asm ("sw x17, 17 * 4(sp)");
    __asm ("sw x18, 18 * 4(sp)");
    __asm ("sw x19, 19 * 4(sp)");
    __asm ("sw x20, 20 * 4(sp)");
    __asm ("sw x21, 21 * 4(sp)");
    __asm ("sw x22, 22 * 4(sp)");
    __asm ("sw x23, 23 * 4(sp)");
    __asm ("sw x24, 24 * 4(sp)");
    __asm ("sw x25, 25 * 4(sp)");
    __asm ("sw x26, 26 * 4(sp)");
    __asm ("sw x27, 27 * 4(sp)");
    __asm ("sw x28, 28 * 4(sp)");
    __asm ("sw x29, 29 * 4(sp)");
    __asm ("sw x30, 30 * 4(sp)");
    __asm ("sw x31, 31 * 4(sp)");
#endif
    /* resw to thread context
    * sp(0) -> epc;
    * sp(1) -> ra;
    * sp(i) -> x(i+2)
    */
    __asm ("switch_to_thread:");
    __asm ("lw sp,  (a1)");

    /* resw ra to mepc */
    __asm ("lw a0,   0 * 4(sp)");
    __asm ("csrw mepc, a0");

    __asm ("lw x1,   1 * 4(sp)");

    __asm ("li    t0, 0x1800");

    __asm ("csrw  mstatus, t0");
    __asm ("lw a0,   2 * 4(sp)");
    __asm ("csrs mstatus, a0");

    __asm ("lw x4,   4 * 4(sp)");
    __asm ("lw x5,   5 * 4(sp)");
    __asm ("lw x6,   6 * 4(sp)");
    __asm ("lw x7,   7 * 4(sp)");
    __asm ("lw x8,   8 * 4(sp)");
    __asm ("lw x9,   9 * 4(sp)");
    __asm ("lw x10, 10 * 4(sp)");
    __asm ("lw x11, 11 * 4(sp)");
    __asm ("lw x12, 12 * 4(sp)");
    __asm ("lw x13, 13 * 4(sp)");
    __asm ("lw x14, 14 * 4(sp)");
    __asm ("lw x15, 15 * 4(sp)");
#ifndef __riscv_32e
    __asm ("lw x16, 16 * 4(sp)");
    __asm ("lw x17, 17 * 4(sp)");
    __asm ("lw x18, 18 * 4(sp)");
    __asm ("lw x19, 19 * 4(sp)");
    __asm ("lw x20, 20 * 4(sp)");
    __asm ("lw x21, 21 * 4(sp)");
    __asm ("lw x22, 22 * 4(sp)");
    __asm ("lw x23, 23 * 4(sp)");
    __asm ("lw x24, 24 * 4(sp)");
    __asm ("lw x25, 25 * 4(sp)");
    __asm ("lw x26, 26 * 4(sp)");
    __asm ("lw x27, 27 * 4(sp)");
    __asm ("lw x28, 28 * 4(sp)");
    __asm ("lw x29, 29 * 4(sp)");
    __asm ("lw x30, 30 * 4(sp)");
    __asm ("lw x31, 31 * 4(sp)");

    __asm ("addi sp,  sp, 32 * 4");
#else
    __asm ("addi sp,  sp, 16 * 4");
#endif

    __asm ("mret");
}


#endif