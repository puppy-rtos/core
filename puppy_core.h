/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __PUPPY_H__
#define __PUPPY_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>

#include <default_config.h>

#define pup_weak                   __attribute__((weak))
#define pup_section(x)             __attribute__((section(x)))
#define pup_used                   __attribute__((used))
#define pup_align(n)               __attribute__((aligned(n)))

typedef union {
    long long       thelonglong;
    long double     thelongdouble;
    uintmax_t       theuintmax_t;
    size_t          thesize_t;
    uintptr_t       theuintptr_t;
    void            *thepvoid;
    void            (*thepfunc)(void);
} pup_max_align_t;

#define P_UNUSED(x)                   ((void)x)

#if defined(__ARMCC_VERSION)           /* ARM Compiler */
typedef unsigned long ssize_t;
#endif

/* Puppy-RTOS object definitions */
typedef size_t            pup_ubase_t;
typedef ssize_t           pup_base_t;
typedef void             *pup_obj_t;
typedef pup_ubase_t       pup_tick_t;

#define P_ALIGN(size, align)           (((size) + (align) - 1) & ~((align) - 1))
#define P_ALIGN_DOWN(size, align)      ((size) & ~((align) - 1))

int printk(const char *fmt, ...);

struct _list_node {
    struct _list_node *next; /* ptr to next node    (pup_node_t) */
    struct _list_node *prev; /* ptr to previous node (pup_node_t) */
};
typedef struct _list_node pup_list_t;
typedef struct _list_node pup_node_t;

/**@}*/

/**
 * @addtogroup POSIX Threads
 * @{
 */

/* Detach state  */

#define PTHREAD_CREATE_JOINABLE       0
#define PTHREAD_CREATE_DETACHED       1

#define P_THREAD_STATE_INIT        0x00
#define P_THREAD_STATE_SLEEP       0x01
#define P_THREAD_STATE_BLOCK       0x02
#define P_THREAD_STATE_READY       0x03
#define P_THREAD_STATE_RUN         0x04
#define P_THREAD_STATE_DEAD        0x05

#define P_THREAD_PRIO_MAX          0xFF

struct pthread_attr_s
{
    const char *name;
    uint8_t priority;            /* Priority of the pthread */
    uint8_t detachstate;         /* Initialize to the detach state */

    void  *stackaddr;            /* Address of memory to be used as stack */
    size_t stacksize;            /* Size of the stack allocated for the pthread */
#if P_CPU_NR > 1
    uint8_t bindcpu;                 /* CPU number to run the pthread */
#endif
};
typedef struct pthread_attr_s pthread_attr_t;
typedef void *pthread_t;

void puppy_init(void);
void *puppy_main_thread(void *arg);

int pthread_attr_destroy(pthread_attr_t * thread_attributes);
int pthread_attr_getdetachstate(pthread_attr_t * thread_attributes, int * detach_state);
int pthread_attr_getstackaddr(pthread_attr_t * thread_attributes, void ** stack_address);
int pthread_attr_getstacksize(pthread_attr_t * thread_attributes, size_t * stack_size);
int pthread_attr_init(pthread_attr_t * thread_attributes);
int pthread_attr_setdetachstate(pthread_attr_t * thread_attributes, int detach_state);
int pthread_attr_setstackaddr(pthread_attr_t * thread_attributes, void * stack_address);
int pthread_attr_setstacksize(pthread_attr_t * thread_attributes, size_t stack_size);
void pthread_cleanup_pop(int execute);
void pthread_cleanup_push(void (*cleanup_handler)(void *), void * argument);
int pthread_create(pthread_t * thread_handle, pthread_attr_t * attr, void *(*start_routine)(void *), void *arg);
int pthread_detach(pthread_t thread_handle);
int pthread_equal(pthread_t first_thread, pthread_t second_thread);
void pthread_exit(void * exit_value);
int pthread_join(pthread_t thread_handle, void ** value_destination);
pthread_t pthread_self(void);
int sched_yield(void);
int sched_getcpu(void);
int pup_pthread_priority_change(pthread_t thread_handle, int new_priority, int * old_priority);
int pup_pthread_resume(pthread_t thread_handle);
int pup_pthread_start(size_t run_time_id, void * memory_start, size_t memory_size);
int pup_pthread_stack_check(pthread_t thread_handle, size_t * minimum_available_stack);
int pup_pthread_suspend(pthread_t thread_handle);
int pup_pthread_attr_getname(pthread_attr_t * thread_attributes, char ** name);
int pup_pthread_attr_getpriority(pthread_attr_t * thread_attributes, int * priority);
int pup_pthread_attr_gettimeslice(pthread_attr_t * thread_attributes, size_t * thread_time_slice);
int pup_pthread_attr_setname(pthread_attr_t * thread_attributes, char * name);
int pup_pthread_attr_setpriority(pthread_attr_t * thread_attributes, int priority);
int pup_pthread_attr_setcpu(pthread_attr_t * thread_attributes, int cpu);
int pup_pthread_attr_settimeslice(pthread_attr_t * thread_attributes, size_t thread_time_slice);
int pup_pthread_information_get(pthread_t thread_handle, char ** name, int * state, int * priority, 
 void ** stack_limit, void ** stack_pointer, size_t * minimum_stack, pthread_t * next_thread);
pthread_t pup_thread_next(void);

/**@}*/

/**
 * @addtogroup Semaphores
 * @{
 */

struct _sem_obj {
    uint16_t    value;
    pup_list_t  blocking_list;
};

typedef struct _sem_obj sem_t;

int sem_destroy(sem_t * semaphore_handle);
int sem_init(sem_t * semaphore_handle, int pshared, unsigned int value);
int sem_post(sem_t * semaphore_handle);
int sem_trywait(sem_t * semaphore_handle);
int sem_wait(sem_t * semaphore_handle);
// int pup_sem_extend_init(sem_t * semaphore_handle, int pshared, unsigned int value, 
//  semattr_t * semaphore_attributes);
// int pup_sem_timedwait(sem_t * semaphore_handle, tick_t timemout_ticks);
// int pup_semattr_destroy(semattr_t *semaphore_attributes);
// int pup_semattr_getcontroladdr(semattr_t *semaphore_attributes, void ** semaphore_control_address);
// int pup_semattr_getcontrolsize(semattr_t *semaphore_attributes, size_t * semaphore_control_size);
// int pup_semattr_getname(semattr_t *semaphore_attributes, char ** semaphore_name);
// int pup_semattr_init(semattr_t *semaphore_attributes);
// int pup_semattr_setcontroladdr(semattr_t *semaphore_attributes, void * semaphore_control_address, 
//  size_t semaphore_control_size);
// int pup_semattr_setname(semattr_t *semaphore_attributes, char * semaphore_name);

/**@}*/


/**
 * @addtogroup Arch Interface
 * @{
 */

pup_base_t arch_irq_lock(void);
void arch_irq_unlock(pup_base_t key);
bool arch_irq_locked(pup_base_t key);
bool arch_in_irq(void);
void *arch_new_thread(void         *entry,
                      void        *param1,
                      void        *param2,
                      void    *stack_addr,
                      uint32_t stack_size);
void arch_swap(pthread_t old_thread, pthread_t new_thread);
void *pup_pthread_archdata(pthread_t obj);

typedef union {
    unsigned long slock;
    struct __arch_tickets {
        unsigned short owner;
        unsigned short next;
    } tickets;
    atomic_flag flag;
} arch_spinlock_t;

void arch_spin_lock_init(arch_spinlock_t *lock);
void arch_spin_lock(arch_spinlock_t *lock);
void arch_spin_unlock(arch_spinlock_t *lock);

/**@}*/


/**
 * @addtogroup IPC
 * @{
 */


/**@}*/
#endif
