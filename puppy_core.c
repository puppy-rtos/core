/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <puppy_core.h>
#include <string.h>

#define KLOG_TAG  "core"
#define KLOG_LVL  KLOG_WARNING
#include <puppy_klog.h>

/**
 * @brief static structure declaration
 */

static pup_list_t _g_pobj_list = {&_g_pobj_list, &_g_pobj_list};

const pthread_attr_t pthread_default_attr = {
    "pthread",
    PUP_SCHED_PRIO_DEFAULT,
    PTHREAD_CREATE_JOINABLE,    /* detach state */
    0,
    PUP_CONFIG_PTHREAD_STACK_DEFAULT, 
};

struct _pthread_obj {
    pthread_attr_t attr;

    uint8_t      state;
    uint8_t      prio;
    pup_node_t   tnode;
    pup_node_t   link_node;

    void        *entry;
    void        *param;
    void  *stackaddr;            /* Address of memory to be used as stack */
    size_t stacksize;            /* Size of the stack allocated for the pthread */
    int          errno;

    void        *cleanup;
#if PUP_CPU_NR > 1
    uint8_t      bindcpu;
    uint8_t      oncpu;
#endif
    /* exit value buf */
    void **exit_value;
    struct _pthread_obj *join_thread;

    /** arch-specifics */
    void *arch_data;
};
#define CPU_NA ((uint8_t)-1)

struct pup_cpu {
    pup_list_t ready_queue;
    pup_list_t dead_queue;
    struct _pthread_obj *curr_thread;
    struct _pthread_obj *next_thread;
    atomic_int sched_lock;
};

/**
 * @brief static function declaration
 */
static int pup_sched_ready_remove(struct _pthread_obj *thread);
static int pup_sched_ready_insert(struct _pthread_obj *thread);

/**
 * @addtogroup cpu
 * @{
 */

#ifndef PUP_GET_CPU_ID
#define PUP_GET_CPU_ID() 0
#endif

static struct pup_cpu _g_cpu[PUP_CPU_NR];

struct pup_cpu *pup_cpu_self(void) {
    return &_g_cpu[PUP_GET_CPU_ID()];
}

struct pup_cpu *pup_cpu_index(uint8_t cpuid) {
    if (cpuid >= PUP_CPU_NR)
        return NULL;
    return &_g_cpu[cpuid];
}
arch_spinlock_t _g_cpu_lock;
// idle thread stack for each cpu
static uint8_t _g_idle_thread_stack[PUP_CPU_NR][PUP_IDLE_THREAD_STACK_SIZE] __attribute__((aligned(PUP_ALIGN_SIZE)));
static void *_pup_idle_thread(void *param) { 
    while (1) {
        __asm("wfi");
    }
    return NULL;
}

void pup_cpu_init(void) {
    arch_spin_lock_init(&_g_cpu_lock);
    for (int i = 0; i < PUP_CPU_NR; i++) {
        pup_list_init(&_g_cpu[i].ready_queue);
        pup_list_init(&_g_cpu[i].dead_queue);
        _g_cpu[i].sched_lock = 1;

        // create idle thread
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pup_pthread_attr_setpriority(&attr, PUP_THREAD_PRIO_MAX);
        pthread_attr_setstacksize(&attr, PUP_IDLE_THREAD_STACK_SIZE);
        pthread_attr_setstackaddr(&attr, _g_idle_thread_stack[i]);
        pup_pthread_attr_setname(&attr, "idle");
#if PUP_CPU_NR > 1
        pup_pthread_attr_setcpu(&attr, i);
#endif
        pthread_create(NULL, &attr, _pup_idle_thread, NULL);
    }
}

/**@}*/

static int _g_errno;

int pup_get_errno(void) {
    struct _pthread_obj *_thread = pthread_self();
    if (_thread)
        return _thread->errno;
    else
        return _g_errno;
}

/**
 * @addtogroup sched
 * @{
 */


struct _pthread_obj *pup_sched_ready_highest(void);

void pup_sched_swap_done_cb(void) {
    struct pup_cpu *cpu = pup_cpu_self();
    cpu->next_thread->state = PUP_THREAD_STATE_RUN;
    cpu->curr_thread = cpu->next_thread;
    cpu->next_thread = NULL;
}

int pup_sched(void) {
    int ret = 0;
    struct _pthread_obj *_h_thread;
    pup_base_t key = arch_irq_lock();
    struct pup_cpu *_cpu = pup_cpu_self();

    if (_cpu->sched_lock == 0) {
        if (!_cpu->next_thread) {
            /* get prio higest thread */
            _h_thread = pup_sched_ready_highest();
            if (!_h_thread) {
                arch_irq_unlock(key);
                return 0;
            }
            if (_cpu->curr_thread && _cpu->curr_thread->state == PUP_THREAD_STATE_RUN && _h_thread->prio >= _cpu->curr_thread->prio) {
                arch_irq_unlock(key);
                return 0;
            }
            _cpu->next_thread = _h_thread;
            pup_sched_ready_remove(_h_thread);
            if (_cpu->curr_thread && _cpu->curr_thread->state == PUP_THREAD_STATE_RUN) {
                pup_sched_ready_insert(_cpu->curr_thread);
            }
        }

        arch_swap(_cpu->curr_thread, _cpu->next_thread);
        ret = pup_get_errno();
    }

    arch_irq_unlock(key);
    return -ret;
}

void pup_sched_lock(void) {
    atomic_fetch_add(&pup_cpu_self()->sched_lock, 1);
}
void pup_sched_unlock(void) {
    atomic_fetch_sub(&pup_cpu_self()->sched_lock, 1);
    if (!pup_cpu_self()->sched_lock) {
        pup_sched();
    }
}

int sched_getcpu(void) {
    return PUP_GET_CPU_ID();
}

static int pup_sched_ready_insert(struct _pthread_obj *thread) {
    static uint8_t cpuid_last = 0;
    struct _pthread_obj *old_thread = NULL, *temp_thread = NULL,*_thread = thread;
    pup_base_t key = arch_irq_lock();
    arch_spin_lock(&_g_cpu_lock);

    pup_node_t *node;
    pup_list_t *_ready_queue;
    KLOG_ASSERT(_thread != NULL);
    
#if PUP_CPU_NR > 1
    uint8_t need_send = CPU_NA;
    if (_thread->oncpu != CPU_NA) {
        cpuid_last = _thread->oncpu;
    }
    else if (_thread->bindcpu != CPU_NA) {
        cpuid_last = _thread->bindcpu;
    }
#endif
    _ready_queue = &pup_cpu_index(cpuid_last)->ready_queue;

    pup_list_for_each_node(_ready_queue, node) {
        temp_thread = pup_list_entry(node, struct _pthread_obj, tnode);
        if (temp_thread->prio > _thread->prio) {
            /* find out insert node */
            old_thread = temp_thread;
            break;
        }
    }
    
    _thread->state = PUP_THREAD_STATE_READY;
    if (old_thread) {
        pup_list_insert(&old_thread->tnode, &_thread->tnode);
    }
    else {
        pup_list_append(_ready_queue, &_thread->tnode);
    }
    
    KLOG_D("p_sched_ready_insert done:_ready_queue->head:%x", _ready_queue->next);

#if PUP_CPU_NR > 1
    if(cpuid_last != PUP_GET_CPU_ID()) {
        KLOG_D("need send ipi");
        need_send = cpuid_last;
    }
    cpuid_last = (cpuid_last + 1) % PUP_CPU_NR;
#endif

    arch_spin_unlock(&_g_cpu_lock);
    arch_irq_unlock(key);
    
#if PUP_CPU_NR > 1
    if(need_send != CPU_NA) {
        void arch_ipi_send(uint8_t cpuid);
        arch_ipi_send(need_send);
    }
#endif

    return 0;
}

struct _pthread_obj *pup_sched_ready_highest(void) {
    struct _pthread_obj *highest_thread = NULL;
    pup_base_t key = arch_irq_lock();
    arch_spin_lock(&_g_cpu_lock);

    pup_list_t *_ready_queue = &pup_cpu_self()->ready_queue;

    if (!pup_list_is_empty(_ready_queue)) {
        highest_thread = pup_list_entry(_ready_queue->next, struct _pthread_obj, tnode);
        KLOG_ASSERT(highest_thread != NULL);
    }

    arch_spin_unlock(&_g_cpu_lock);
    arch_irq_unlock(key);
    return highest_thread;
}

static int pup_sched_ready_remove(struct _pthread_obj *thread) {
    struct _pthread_obj *_thread = thread;
    pup_base_t key = arch_irq_lock();
    

    KLOG_D("p_sched_ready_remove:tnode:%x",&_thread->tnode);
    pup_list_remove(&_thread->tnode);

    arch_irq_unlock(key);
    return 0;
}


/**@}*/

/**
 * @addtogroup POSIX Thread
 * @{
 */

void pup_thread_entry(void (*entry)(void *parameter), void *param) {
    KLOG_D("p_thread_entry enter...");
    if (entry) {
        entry(param);
    }
    
    KLOG_D("p_thread_entry exit...");
    pthread_exit(NULL);
    while (1);
}
static void _p_thread_cleanup(struct _pthread_obj *obj) {

}

pthread_t pthread_self(void) {
    return pup_cpu_self()->curr_thread;
}
pthread_t pup_thread_next(void) {
    return pup_cpu_self()->next_thread;
}   
int pthread_attr_init(pthread_attr_t * thread_attributes) {
    *thread_attributes = pthread_default_attr;
    return 0;
}
int pthread_attr_setstackaddr(pthread_attr_t * thread_attributes, void * stack_address) {
    thread_attributes->stackaddr = stack_address;
    return 0;
}
int pthread_attr_setstacksize(pthread_attr_t * thread_attributes, size_t stack_size) {
    thread_attributes->stacksize = stack_size;
    return 0;
}

int pup_pthread_attr_setpriority(pthread_attr_t * thread_attributes, int priority) {
    thread_attributes->priority = priority;
    return 0;
}
#if PUP_CPU_NR > 1
int pup_pthread_attr_setcpu(pthread_attr_t * thread_attributes, int cpu){
    thread_attributes->bindcpu = cpu;
    return 0;
}
#endif
/**
 * @brief set the name of a thread
 * 
 * @param thread argument specifies the thread whose name is to be changed.
 * @param name name specifies the new name.
 * @return On success, these functions return 0; on error, they return a
 *             nonzero error number.
 */
int pthread_setname_np(pthread_t thread, const char *name)
{
    struct _pthread_obj *pthread_obj = thread;
    pthread_obj->attr.name = name;
    return 0;
}
int pup_pthread_attr_setname(pthread_attr_t * thread_attributes, char * name)
{
    thread_attributes->name = name;
    return 0;
}
int pthread_create(pthread_t * thread_handle, pthread_attr_t * attr,
                         void *(*start_routine)(void *), void *arg) {
    int ret = 0;
    struct _pthread_obj *pthread_obj;

    KLOG_ASSERT(attr && attr->stackaddr);
    // create pthread date from stack top.
    KLOG_D("pthread_obj attr.stackaddr:0x%x, size:%d", attr->stackaddr, attr->stacksize);
    pthread_obj = (struct _pthread_obj*)PUP_ALIGN_DOWN((pup_ubase_t)(attr->stackaddr + 
            (attr->stacksize - sizeof(struct _pthread_obj))) , PUP_ALIGN_SIZE);
    KLOG_D("pthread_obj created at addr:0x%x", pthread_obj);
    if (!pthread_obj) return 0;

    memset(pthread_obj, 0x0, sizeof(struct _pthread_obj));
    pthread_obj->attr = *attr;

    /* initial this pthread to system */
     /* set parameter */
    pthread_obj->entry = start_routine;
    pthread_obj->param = arg;
    pthread_obj->stackaddr = pthread_obj->attr.stackaddr;
    pthread_obj->stacksize = pthread_obj->attr.stacksize- PUP_ALIGN(sizeof(struct _pthread_obj),PUP_ALIGN_SIZE);
    pthread_obj->prio = pthread_obj->attr.priority;
    pthread_obj->state = PUP_THREAD_STATE_INIT;
    pthread_obj->cleanup = _p_thread_cleanup;
    pthread_obj->exit_value = NULL;
    pthread_obj->join_thread = NULL;
#if PUP_CPU_NR > 1
    pthread_obj->bindcpu = pthread_obj->attr.bindcpu;
    pthread_obj->oncpu = CPU_NA;
#endif

    pup_list_insert(&_g_pobj_list, &pthread_obj->link_node);

    memset(pthread_obj->stackaddr,0x23, pthread_obj->stacksize );

    pthread_obj->arch_data = arch_new_thread(pup_thread_entry, start_routine, arg, pthread_obj->stackaddr, pthread_obj->stacksize);

    if(thread_handle) *thread_handle = pthread_obj;
    /* start thread */
    pup_sched_ready_insert(pthread_obj);
    pup_sched();

    return ret;
}

int pthread_join(pthread_t thread_handle, void ** value_destination) {
    struct _pthread_obj *_thread = thread_handle;
    struct _pthread_obj *_self = pthread_self();
    pup_base_t key = arch_irq_lock();
    KLOG_ASSERT(_thread != NULL);
    KLOG_ASSERT(_thread != _self);
    KLOG_ASSERT(_thread->join_thread == NULL);
    
    if(_thread->state == PUP_THREAD_STATE_DEAD) {
        return -1;
    }

    _thread->exit_value = value_destination;
    _thread->join_thread = _self;
    _self->state = PUP_THREAD_STATE_BLOCK;
    pup_sched();

    arch_irq_unlock(key);
    return 0;
}

void pthread_exit(void * exit_value) {
    struct _pthread_obj *_thread = pthread_self();
    if (_thread->exit_value) {
        *_thread->exit_value = exit_value;
    }
    pup_base_t key = arch_irq_lock();

    if (_thread->join_thread) {
        pup_sched_ready_insert(_thread->join_thread);
        _thread->join_thread = NULL;
    }
    _thread->state = PUP_THREAD_STATE_DEAD;
    pup_sched();
    
    arch_irq_unlock(key);
}

void pup_pthread_list(void)
{
    pup_node_t *node;
    struct _pthread_obj *object;
    int maxlen;

    maxlen = 8;

    printk("thread    pri  state   stack size max used \n");
    printk("--------  ---  ------- ----------  ------  \n");

    pup_list_for_each_node(&_g_pobj_list, node)
    {
        object = pup_list_entry(node, struct _pthread_obj, link_node);
        {
            uint8_t stat;
            uint8_t *ptr;
            struct _pthread_obj *thread = (struct _pthread_obj *)object;

            printk("%-*.*s  %3d ", maxlen, maxlen, thread->attr.name, thread->prio);

            stat = thread->state;
            if (stat == PUP_THREAD_STATE_READY)        printk(" ready  ");
            else if (stat == PUP_THREAD_STATE_BLOCK)   printk(" blocked");
            else if (stat == PUP_THREAD_STATE_INIT)    printk(" init   ");
            else if (stat == PUP_THREAD_STATE_DEAD)    printk(" dead   ");
            else if (stat == PUP_THREAD_STATE_RUN)     printk(" running");
            else if (stat == PUP_THREAD_STATE_SLEEP)   printk(" sleep  ");

            ptr = (uint8_t *)thread->attr.stackaddr;
            while (*ptr == '#') ptr ++;
            printk(" 0x%08x    %02d%%  \n",
                        thread->attr.stacksize,
                        (thread->attr.stacksize - ((pup_ubase_t) ptr - (pup_ubase_t) thread->attr.stackaddr)) * 100
                        / thread->attr.stacksize);
        }
    }
}

int sched_yield(void) {
    struct _pthread_obj *_thread = pup_cpu_self()->curr_thread;
    pup_base_t key = arch_irq_lock();
    
    KLOG_ASSERT(pup_cpu_self()->curr_thread != NULL);
    KLOG_ASSERT(_thread->state == PUP_THREAD_STATE_RUN);

    pup_sched_ready_insert(_thread);
    pup_sched();
    
    arch_irq_unlock(key);
    return 0;
}

/**@}*/

void *pup_pthread_archdata(pthread_t obj) {
    struct _pthread_obj *thread = obj;
    return thread->arch_data;
}

const PUP_SECTION_START_DEFINE(PUP_INIT_SECTION, _init_start);
const PUP_SECTION_END_DEFINE(PUP_INIT_SECTION, _init_end);
static void _init_fn_run(void)
{
    struct pup_ex_fn *ptr_begin, *ptr_end;
    volatile struct pup_ex_fn *init_fn;
    ptr_begin = (struct pup_ex_fn *)PUP_SECTION_START_ADDR(_init_start);
    ptr_end = (struct pup_ex_fn *)PUP_SECTION_END_ADDR(_init_end);
    for (init_fn = ptr_begin; init_fn < ptr_end;)
    {
        KLOG_D("init [%s] init...",  init_fn->name);
        (init_fn ++)->func();
    }
}

void pup_show_version(void)
{
    printk("\n\nBuild Time: %s %s\n", __DATE__, __TIME__);
    printk("                           _         \n");
    printk("    ____   ____    _____  (_) _  __\n");
    printk("   / __ \\ / __ \\  / ___/ / / | |/_/\n");
    printk("  / /_/ // /_/ / (__  ) / /  >  <  \n");
    printk(" / .___/ \\____/ /____/ /_/  /_/|_|  \n");
    printk("/_/          Powered dy puppy-rtos\n");
}

char main_pthread_stack[4096];
void *puppy_main_thread(void *arg);
void puppy_init(void) {
    pthread_attr_t attr;
    
    pup_cpu_init();
    pup_show_version();
    _init_fn_run();
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, sizeof(main_pthread_stack));
    pthread_attr_setstackaddr(&attr, main_pthread_stack);
    pup_pthread_attr_setname(&attr, "main");
    
    pthread_create(NULL, &attr, puppy_main_thread, NULL);
#if PUP_CPU_NR > 1
    pup_subcpu_start();
#endif
    pup_sched_unlock();
    while (1);
}
/**
 * @addtogroup Semaphores
 * @{
 */

int sem_init(sem_t * semaphore_handle, int pshared, unsigned int value) {
    semaphore_handle->value = value;
    pup_list_init(&semaphore_handle->blocking_list);
    return 0;
}

int sem_destroy(sem_t * semaphore_handle) {
    return 0;
}

static void _block_thread(pup_list_t *list, struct _pthread_obj * thread) {
    struct _pthread_obj *temp_thread;
    if (pup_list_is_empty(list)) {
        pup_list_append(list, &thread->tnode);
    }
    else {
        pup_node_t *pos = list->next;
        while(pos != list) {
            temp_thread = pup_list_entry(pos, struct _pthread_obj, tnode);
            if (temp_thread->prio > thread->prio) {
                break;
            }
			pos = pos->next;
		}
        if (pos != list) {
            pup_list_insert(pos, &thread->tnode);
        }
        else {
            pup_list_append(list, &thread->tnode);
        }
    }
    KLOG_D("_block_thread:%s", thread->kobj.name);
    thread->state = PUP_THREAD_STATE_BLOCK;
}

static void _wakeup_block_thread(pup_list_t *list){ 
    struct _pthread_obj *_thread;
    _thread = pup_list_entry(list->next,
                            struct _pthread_obj, tnode);
    pup_list_remove(&_thread->tnode);
    KLOG_D("_wakeup_block_thread:%s", _thread->kobj.name);
    pup_sched_ready_insert(_thread);
}

int sem_post(sem_t * semaphore_handle) {
    sem_t *sem = semaphore_handle;
    pup_base_t key = arch_irq_lock();

    sem->value ++;
    if (pup_list_is_empty(&sem->blocking_list)) {
        goto _exit;
    }
    _wakeup_block_thread(&sem->blocking_list);
    pup_sched();
    return 0;
_exit:
    arch_irq_unlock(key);
    return -1;
}

int sem_trywait(sem_t * semaphore_handle) {
    return -1;
}

int sem_wait(sem_t * semaphore_handle) {
    sem_t *sem = semaphore_handle;
    int ret = 0;
    pup_base_t key = arch_irq_lock();
    if (sem->value > 0) {
        sem->value --;
        goto _exit;
    }
    _block_thread(&sem->blocking_list, pthread_self());
    ret = pup_sched();
    if (ret == 0) {
        sem->value --;
    }
_exit:
    arch_irq_unlock(key);
    return ret;
}

/**@}*/
