/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <puppy_core.h>

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

__attribute__((always_inline)) inline bool arch_irq_locked(pup_base_t key)
{
    return !(key & 0x08);
}


#include "platform.h"
#include "riscv.h"
extern void trap_vector(void);
extern void uart_isr(void);
extern void timer_handler(void);

void trap_init()
{
    /*
     * set the trap-vector base-address for machine-mode
     */
    w_mtvec((uint32_t)trap_vector);
}

void external_interrupt_handler()
{
    int irq = plic_claim();

    if (irq == 10){
        uart_isr();
    } else if (irq) {
        printk("unexpected interrupt irq = %d\n", irq);
    }

    if (irq) {
        plic_complete(irq);
    }
}

uint32_t trap_handler(uint32_t epc, uint32_t cause)
{
    uint32_t return_pc = epc;
    uint32_t cause_code = cause & 0xfff;

    if (cause & 0x80000000) {
        /* Asynchronous trap - interrupt */
        switch (cause_code) {
        case 3:
            // printk("software interruption!\n");
            sfi_handler();
            break;
        case 7:
            // printk("timer interruption!\n");
            timer_handler();
            break;
        case 11:
            // printk("external interruption!\n");
            external_interrupt_handler();
            break;
        default:
            printk("unknown async exception!\n");
            break;
        }
    } else {
        /* Synchronous trap - exception */
        printk("Sync exceptions!, code = %d\n", cause_code);
        printk("OOPS! What can I do!");
        // list_thread();
        while(1)
        {}
        // return_pc += 2;
    }

    return return_pc;
}

void trap_test()
{
    /*
     * Synchronous exception code = 7
     * Store/AMO access fault
     */
    *(int *)0x00000000 = 100;

    /*
     * Synchronous exception code = 5
     * Load access fault
     */
    //int a = *(int *)0x00000000;

    printk("Yeah! I'm return back from trap!\n");
}
// #include "nr_micro_shell.h"
// NR_SHELL_CMD_EXPORT(trap_test, trap_test);
#include <stdatomic.h>

#ifndef P_ARCH_CORTEX_M0
pup_weak void arch_spin_lock_init(arch_spinlock_t *lock)
{
    atomic_flag_clear(&lock->flag);
}

pup_weak __attribute__((always_inline)) inline void arch_spin_lock(arch_spinlock_t *lock)
{
    while (atomic_flag_test_and_set(&lock->flag)) {
        /* busy-wait */
    }
}

pup_weak __attribute__((always_inline)) inline void arch_spin_unlock(arch_spinlock_t *lock)
{
    atomic_flag_clear(&lock->flag);
}

#else
#include <pico/lock_core.h>

void arch_spin_lock_init(arch_spinlock_t *lock)
{
    static uint8_t spin_cnt = 0;

    if ( spin_cnt < 32)
    {
        lock->slock = (uint32_t)spin_lock_instance(spin_cnt);
        spin_cnt = spin_cnt + 1;
    }
    else
    {
        lock->slock = 0;
    }
}

void arch_spin_lock(arch_spinlock_t *lock)
{
    if ( lock->slock != 0 )
    {
        spin_lock_unsafe_blocking((spin_lock_t*)lock->slock);
    }
}

void arch_spin_unlock(arch_spinlock_t *lock)
{
    if ( lock->slock != 0 )
    {
        spin_unlock_unsafe((spin_lock_t*)lock->slock);
    }
}
#endif


#define KLOG_TAG  "arch.rv32"
#define KLOG_LVL   KLOG_INFO
#include <puppy_klog.h>


#define read_csr(reg) ({ unsigned long __tmp;                               \
    asm volatile ("csrr %0, " #reg : "=r"(__tmp));                          \
        __tmp; })

#define write_csr(reg, val) ({                                              \
    if (__builtin_constant_p(val) && (unsigned long)(val) < 32)             \
        asm volatile ("csrw " #reg ", %0" :: "i"(val));                     \
    else                                                                    \
        asm volatile ("csrw " #reg ", %0" :: "r"(val)); })

#define set_csr(reg, bit) ({ unsigned long __tmp;                           \
    if (__builtin_constant_p(bit) && (unsigned long)(bit) < 32)             \
        asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "i"(bit));   \
    else                                                                    \
        asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "r"(bit));   \
            __tmp; })

#define clear_csr(reg, bit) ({ unsigned long __tmp;                         \
    if (__builtin_constant_p(bit) && (unsigned long)(bit) < 32)             \
        asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "i"(bit));   \
    else                                                                    \
        asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "r"(bit));   \
            __tmp; })

struct arch_thread
{
    uint32_t irq_flag;
    uint32_t need_swap;
    uint32_t stack_ptr;
};
void arch_irq_enter(void)
{
    struct arch_thread *arch;
    if (pthread_self() == NULL)
        return ;
    arch = pup_pthread_archdata(pthread_self());
    arch->irq_flag ++;

}
void arch_irq_leave(void)
{
    struct arch_thread *arch;
    if (pthread_self() == NULL)
        return ;
    arch = pup_pthread_archdata(pthread_self());
    arch->irq_flag --;
}
__attribute__((always_inline)) inline bool arch_in_irq(void)
{
    struct arch_thread *arch;
    if (pthread_self() == NULL)
        return true;
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
                      uint32_t stack_size)
{
    int i;
    struct arch_thread *arch_data;
    _sf_t *sf;
    
    arch_data = (struct arch_thread *)PUP_ALIGN_DOWN(((uint32_t)stack_addr + stack_size) - sizeof(struct arch_thread), 8);
    sf = (_sf_t *)PUP_ALIGN_DOWN((uint32_t)arch_data - sizeof(_sf_t), 8);

    /* init all register */
    for (i = 0; i < sizeof(_sf_t) / sizeof(uint32_t); i ++)
    {
        ((uint32_t *)sf)[i] = 0xdeadbeef;
    }
    
    sf->a0 = (uint32_t)param1;
    sf->a1 = (uint32_t)param2;
    sf->ra = 0;
    sf->epc = (uint32_t)entry;

    sf->mstatus = 0x1880;

    arch_data->irq_flag = 0;
    arch_data->need_swap = 0;
    arch_data->stack_ptr = ((uint32_t)sf);
    return arch_data;
}
__attribute__((naked)) void riscv_swap(pup_ubase_t from, pup_ubase_t to);

void *arch_get_from_sp(void)
{
    struct arch_thread *arch;
    if (pthread_self() == NULL)
        return NULL;
    arch = pup_pthread_archdata(pthread_self());
    return &arch->stack_ptr;
}
void *arch_get_to_sp(void)
{
    struct arch_thread *arch;
    if (pup_thread_next() == NULL)
        return NULL;
    arch = pup_pthread_archdata(pup_thread_next());
    return &arch->stack_ptr;
}
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
void arch_swap(pthread_t old_thread, pthread_t new_thread)
{
    void *from, *to;
    if (arch_in_irq() && pthread_self())
    {
        struct arch_thread *arch;
        arch = pup_pthread_archdata(pthread_self());
        arch->need_swap = 1;
        return;
    }
    from = arch_get_from_sp();
    to = arch_get_to_sp();
    pup_sched_swap_done_cb(); /* todo: 执行时的上下文不对 */
    riscv_swap(from, to);
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

void dump_contex(struct stack_frame *context)
{
    printk("Stack frame:\n----------------------------------------\n");
    printk("ra      : 0x%08x\n", context->ra);
    printk("mstatus : 0x%08x\n", read_csr(0x300));//mstatus
    printk("t0      : 0x%08x\n", context->t0);
    printk("t1      : 0x%08x\n", context->t1);
    printk("t2      : 0x%08x\n", context->t2);
    printk("a0      : 0x%08x\n", context->a0);
    printk("a1      : 0x%08x\n", context->a1);
    printk("a2      : 0x%08x\n", context->a2);
    printk("a3      : 0x%08x\n", context->a3);
    printk("a4      : 0x%08x\n", context->a4);
    printk("a5      : 0x%08x\n", context->a5);
#ifndef __riscv_32e
    printk("a6      : 0x%08x\n", context->a6);
    printk("a7      : 0x%08x\n", context->a7);
    printk("t3      : 0x%08x\n", context->t3);
    printk("t4      : 0x%08x\n", context->t4);
    printk("t5      : 0x%08x\n", context->t5);
    printk("t6      : 0x%08x\n", context->t6);
#endif
}
// void trap_handler()
// {
//     uint32_t mscratch = read_csr(0x340);
//     // uint32_t irq_id = (mcause & 0x1F);
//     // uint32_t exception = !(mcause & 0x80000000);
//     // if(exception)
//     // {
//         dump_contex((struct stack_frame *)mscratch);
//     // }
//     // else
//     // {
//     //     rv32irq_table[irq_id].handler(irq_id, rv32irq_table[irq_id].param);
//     // }	
// }

