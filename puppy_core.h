/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __PUPPY_H__
#define __PUPPY_H__

#include <default_config.h>

#define pup_weak                   __attribute__((weak))
#define pup_section(x)             __attribute__((section(x)))
#define pup_used                   __attribute__((used))
#define pup_align(n)               __attribute__((aligned(n)))

#define PUP_UNUSED(x)                   ((void)x)
#define PUP_NULL                        (0)
#define PUP_FAIL                        (0)
#define PUP_TRUE                        (!PUP_FAIL)

#if defined(__ARMCC_VERSION)           /* ARM Compiler */
typedef unsigned long ssize_t;
#endif

/* Puppy-RTOS object definitions */
typedef unsigned long pup_ubase_t;
typedef long pup_base_t;
typedef void* pup_obj_t;
typedef pup_ubase_t       pup_tick_t;
typedef pup_ubase_t       pup_size_t;

/* base data typedef */
typedef unsigned char      pup_uint8_t;
typedef unsigned short     pup_uint16_t;
typedef unsigned int       pup_uint32_t;
typedef unsigned long long pup_uint64_t;
typedef signed char        pup_int8_t;
typedef signed short       pup_int16_t;
typedef signed int         pup_int32_t;
typedef signed long long   pup_int64_t;

#define PUP_ALIGN(size, align)           (((size) + (align) - 1) & ~((align) - 1))
#define PUP_ALIGN_DOWN(size, align)      ((size) & ~((align) - 1))
/**
 * pup_container_of - return the start address of struct type, while ptr is the
 * member of struct type.
 */
#define pup_container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

 /**
  * @addtogroup list
  * @{
  */

struct _list_node {
    struct _list_node* next; /* ptr to next node    (pup_node_t) */
    struct _list_node* prev; /* ptr to previous node (pup_node_t) */
};
typedef struct _list_node pup_list_t;
typedef struct _list_node pup_node_t;

/**@}*/

/**
 * @addtogroup POSIX_Thread
 * @{
 */

 /* Detach state  */

#define PTHREAD_CREATE_JOINABLE       0
#define PTHREAD_CREATE_DETACHED       1

#define PUP_THREAD_STATE_INIT        0x00
#define PUP_THREAD_STATE_SLEEP       0x01
#define PUP_THREAD_STATE_BLOCK       0x02
#define PUP_THREAD_STATE_READY       0x03
#define PUP_THREAD_STATE_RUN         0x04
#define PUP_THREAD_STATE_DEAD        0x05

#define PUP_THREAD_PRIO_MAX          0xFF

struct pthread_attr_s {
    const char* name;
    pup_uint8_t priority;            /* Priority of the pthread */
    pup_uint8_t detachstate;         /* Initialize to the detach state */

    void* stackaddr;            /* Address of memory to be used as stack */
    pup_size_t stacksize;            /* Size of the stack allocated for the pthread */
#if PUP_CPU_NR > 1
    pup_uint8_t bindcpu;                 /* CPU number to run the pthread */
#endif
};
typedef struct pthread_attr_s pthread_attr_t;
typedef void* pthread_t;

void puppy_init(void);
void* puppy_main_thread(void* arg);

/**
 * @brief Initialize thread attributes object.
 *
 * @param thread_attributes Pointer to the thread attributes object.
 * @return 0 on success, error code on failure.
 */
int pthread_attr_init(pthread_attr_t* thread_attributes);

/**
 * @brief Destroy thread attributes object.
 *
 * @param thread_attributes Pointer to the thread attributes object.
 * @return 0 on success, error code on failure.
 */
int pthread_attr_destroy(pthread_attr_t* thread_attributes);

/**
 * @brief Create a new thread.
 *
 * @param thread_handle Pointer to the thread handle.
 * @param attr Pointer to the thread attributes object.
 * @param start_routine Pointer to the start routine function.
 * @param arg Pointer to the argument passed to the start routine.
 * @return 0 on success, error code on failure.
 */
int pthread_create(pthread_t* thread_handle, pthread_attr_t* attr, void* (*start_routine)(void*), void* arg);

/**
 * @brief Terminate the calling thread.
 *
 * @param exit_value Pointer to the exit value.
 */
void pthread_exit(void* exit_value);

/**
 * @brief Get the calling thread's ID.
 *
 * @return The thread ID of the calling thread.
 */
pthread_t pthread_self(void);

/**
 * @brief Suspend a thread.
 *
 * @param thread_handle The handle of the thread to suspend.
 * @return 0 on success, error code on failure.
 */
int pthread_suspend(pthread_t thread_handle);

/**
 * @brief Resume a suspended thread.
 *
 * @param thread_handle The handle of the thread to resume.
 * @return 0 on success, error code on failure.
 */
int pthread_resume(pthread_t thread_handle);

/**
 * @brief Wait for a thread to terminate.
 *
 * @param thread_handle The handle of the thread to wait for.
 * @param value_destination Pointer to the location where the exit value will be stored.
 * @return 0 on success, error code on failure.
 */
int pthread_join(pthread_t thread_handle, void** value_destination);

int pthread_attr_getstackaddr(pthread_attr_t* thread_attributes, void** stack_address);
int pthread_attr_setstackaddr(pthread_attr_t* thread_attributes, void* stack_address);
int pthread_attr_getstacksize(pthread_attr_t* thread_attributes, pup_size_t* stack_size);
int pthread_attr_setstacksize(pthread_attr_t* thread_attributes, pup_size_t stack_size);
int sched_yield(void);
int sched_getcpu(void);

// int pup_pthread_attr_getname(pthread_attr_t * thread_attributes, char ** name);
int pthread_attr_setname(pthread_attr_t* thread_attributes, char* name);
// int pup_pthread_attr_getpriority(pthread_attr_t * thread_attributes, int * priority);
int pthread_attr_setpriority(pthread_attr_t* thread_attributes, int priority);
// int pup_pthread_attr_gettimeslice(pthread_attr_t * thread_attributes, size_t * thread_time_slice);
// int pup_pthread_attr_settimeslice(pthread_attr_t * thread_attributes, size_t thread_time_slice);
int pthread_attr_setcpu(pthread_attr_t* thread_attributes, int cpu);

/**@}*/

/**
 * @addtogroup Semaphores
 * @{
 */

struct _sem_obj {
    pup_uint16_t    value;
    pup_list_t  blocking_list;
};

typedef struct _sem_obj sem_t;

int sem_init(sem_t* semaphore_handle, int pshared, unsigned int value);
int sem_destroy(sem_t* semaphore_handle);
int sem_wait(sem_t* semaphore_handle);
int sem_trywait(sem_t* semaphore_handle);
int sem_post(sem_t* semaphore_handle);
// int sem_timedwait(sem_t * semaphore_handle, tick_t timemout_ticks);

/**@}*/


/**
 * @addtogroup Arch_Interface
 * @{
 */

pup_base_t arch_irq_lock(void);
void arch_irq_unlock(pup_base_t key);
pup_uint8_t arch_irq_locked(pup_base_t key);
pup_uint8_t arch_in_irq(void);
void* arch_new_thread(void* entry,
                      void* param1,
                      void* param2,
                      void* stack_addr,
                      pup_uint32_t stack_size);
void arch_swap(pthread_t old_thread, pthread_t new_thread);

typedef struct {
    volatile pup_uint32_t flag;
} arch_spinlock_t;

void arch_spin_lock_init(arch_spinlock_t* lock);
void arch_spin_lock(arch_spinlock_t* lock);
void arch_spin_unlock(arch_spinlock_t* lock);

/**@}*/


#endif
