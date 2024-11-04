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
struct _list_node {
    union {
        struct _list_node *head; /* ptr to head of list (pup_list_t) */
        struct _list_node *next; /* ptr to next node    (pup_node_t) */
    };
    union {
        struct _list_node *tail; /* ptr to tail of list (pup_list_t) */
        struct _list_node *prev; /* ptr to previous node (pup_node_t) */
    };
};
typedef struct _list_node pup_list_t;
typedef struct _list_node pup_node_t;

const pthread_attr_t pthread_default_attr = {
    "pthread",
    P_SCHED_PRIO_DEFAULT,
    PTHREAD_CREATE_JOINABLE,    /* detach state */
    0,
    P_CONFIG_PTHREAD_STACK_DEFAULT, 
};

struct _pthread_obj {
    pthread_attr_t attr;

    uint8_t      state;
    uint8_t      prio;
    pup_node_t   tnode;

    void        *entry;
    void        *param;
    void  *stackaddr;            /* Address of memory to be used as stack */
    size_t stacksize;            /* Size of the stack allocated for the pthread */
    int          errno;

    void        *cleanup;
#if P_CPU_NR > 1
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
 * @addtogroup list
 * @{
 */

/**
 * pup_container_of - return the start address of struct type, while ptr is the
 * member of struct type.
 */
#define pup_container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

/**
 * @brief get the struct for this entry
 * @param node the entry point
 * @param type the type of structure
 * @param member the name of list in structure
 */
#define pup_list_entry(node, type, member) \
    pup_container_of(node, type, member)

/**
 * @brief Provide the primitive to iterate on a list
 * Note: the loop is unsafe and thus node should not be removed
 * @param list A pointer on a pup_list_t to iterate on.
 * @param node A pup_node_t pointer to peek each node of the list
 */
#define pup_list_for_each_node(list, node) \
    for (node = (list)->head; node != (list); node = node->next)

/**
 * @brief Provide the primitive to safely iterate on a list
 * Note: node can be removed, it will not break the loop.
 * @param list A pointer on a pup_list_t to iterate on.
 * @param node A pup_node_t pointer to peek each node of the list
 * @param node_s A pup_node_t pointer for the loop to run safely
 */
#define pup_list_for_each_node_safe(list, node, node_s) \
    for (node = (list)->head, node_s = node->next; node != (list); \
        node = node_s, node_s = node->next)

#define P_LIST_STATIC_INIT(list_ptr) { {(list_ptr)}, {(list_ptr)} }

static inline void pup_list_init(pup_list_t *list) {
    list->head = list->tail = list;
}

static inline bool pup_list_is_empty(pup_list_t *list) {
    return list->head == list;
}

static inline bool pup_node_is_linked(pup_node_t *node) {
    return node->next != NULL;
}

/**
 * @brief add node to tail of list
 *
 * This and other pup_list_*() functions are not thread safe.
 *
 * @param list the doubly-linked list to operate on
 * @param node the element to append
 */

static inline void pup_list_append(pup_list_t *list, pup_node_t *node) {
    pup_node_t *const tail = list->tail;

    node->next = list;
    node->prev = tail;

    tail->next = node;
    list->tail = node;
}

/**
 * @brief add node to head of list
 *
 * This and other pup_list_*() functions are not thread safe.
 *
 * @param list the doubly-linked list to operate on
 * @param node the element to append
 */

static inline void pup_list_prepend(pup_list_t *list, pup_node_t *node) {
    pup_node_t *const head = list->head;

    node->next = head;
    node->prev = list;

    head->prev = node;
    list->head = node;
}

/**
 * @brief Insert a node into a list
 *
 * Insert a node before a specified node in a dlist.
 *
 * @param successor the position before which "node" will be inserted
 * @param node the element to insert
 */
static inline void pup_list_insert(pup_node_t *successor, pup_node_t *node) {
    pup_node_t *const prev = successor->prev;

    node->prev = prev;
    node->next = successor;
    prev->next = node;
    successor->prev = node;
}

/**
 * @brief remove node from list.
 * @param node the node to remove from the list.
 */
static inline void pup_list_remove(pup_node_t *node) {
    node->next->prev = node->prev;
    node->prev->next = node->next;

    node->prev = node->next = NULL;
}


/**@}*/


/**
 * @addtogroup cpu
 * @{
 */

#ifndef PUP_GET_CPU_ID
#define PUP_GET_CPU_ID() 0
#endif

static struct pup_cpu _g_cpu[P_CPU_NR];

struct pup_cpu *pup_cpu_self(void) {
    return &_g_cpu[PUP_GET_CPU_ID()];
}

struct pup_cpu *pup_cpu_index(uint8_t cpuid) {
    if (cpuid >= P_CPU_NR)
        return NULL;
    return &_g_cpu[cpuid];
}
arch_spinlock_t _g_cpu_lock;
// idle thread stack for each cpu
static uint8_t _g_idle_thread_stack[P_CPU_NR][P_IDLE_THREAD_STACK_SIZE] __attribute__((aligned(P_ALIGN_SIZE)));
static void *_pup_idle_thread(void *param) { 
    while (1) {
        __asm("wfi");
    }
    return NULL;
}

void pup_cpu_init(void) {
    arch_spin_lock_init(&_g_cpu_lock);
    for (int i = 0; i < P_CPU_NR; i++) {
        pup_list_init(&_g_cpu[i].ready_queue);
        pup_list_init(&_g_cpu[i].dead_queue);
        _g_cpu[i].sched_lock = 1;

        // create idle thread
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pup_pthread_attr_setpriority(&attr, P_THREAD_PRIO_MAX);
        pthread_attr_setstacksize(&attr, P_IDLE_THREAD_STACK_SIZE);
        pthread_attr_setstackaddr(&attr, _g_idle_thread_stack[i]);
#if P_CPU_NR > 1
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
    cpu->next_thread->state = P_THREAD_STATE_RUN;
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
            if (_cpu->curr_thread && _cpu->curr_thread->state == P_THREAD_STATE_RUN && _h_thread->prio >= _cpu->curr_thread->prio) {
                arch_irq_unlock(key);
                return 0;
            }
            _cpu->next_thread = _h_thread;
            pup_sched_ready_remove(_h_thread);
            if (_cpu->curr_thread && _cpu->curr_thread->state == P_THREAD_STATE_RUN) {
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
    
#if P_CPU_NR > 1
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
    
    _thread->state = P_THREAD_STATE_READY;
    if (old_thread) {
        pup_list_insert(&old_thread->tnode, &_thread->tnode);
    }
    else {
        pup_list_append(_ready_queue, &_thread->tnode);
    }
    
    KLOG_D("p_sched_ready_insert done:_ready_queue->head:%x", _ready_queue->head);

#if P_CPU_NR > 1
    if(cpuid_last != PUP_GET_CPU_ID()) {
        KLOG_D("need send ipi");
        need_send = cpuid_last;
    }
    cpuid_last = (cpuid_last + 1) % P_CPU_NR;
#endif

    arch_spin_unlock(&_g_cpu_lock);
    arch_irq_unlock(key);
    
#if P_CPU_NR > 1
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
        highest_thread = pup_list_entry(_ready_queue->head, struct _pthread_obj, tnode);
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
#if P_CPU_NR > 1
int pup_pthread_attr_setcpu(pthread_attr_t * thread_attributes, int cpu){
    thread_attributes->bindcpu = cpu;
    return 0;
}
#endif
int pthread_create(pthread_t * thread_handle, pthread_attr_t * attr,
                         void *(*start_routine)(void *), void *arg) {
    int ret = 0;
    struct _pthread_obj *pthread_obj;

    KLOG_ASSERT(attr && attr->stackaddr);
    // create pthread date from stack top.
    KLOG_D("pthread_obj attr.stackaddr:0x%x, size:%d", attr->stackaddr, attr->stacksize);
    pthread_obj = (struct _pthread_obj*)P_ALIGN_DOWN((pup_ubase_t)(attr->stackaddr + 
            (attr->stacksize - sizeof(struct _pthread_obj))) , P_ALIGN_SIZE);
    KLOG_D("pthread_obj created at addr:0x%x", pthread_obj);
    if (!pthread_obj) return NULL;

    memset(pthread_obj, 0x0, sizeof(struct _pthread_obj));
    pthread_obj->attr = *attr;

    /* initial this pthread to system */
     /* set parameter */
    pthread_obj->entry = start_routine;
    pthread_obj->param = arg;
    pthread_obj->stackaddr = pthread_obj->attr.stackaddr;
    pthread_obj->stacksize = pthread_obj->attr.stacksize- P_ALIGN(sizeof(struct _pthread_obj),P_ALIGN_SIZE);
    pthread_obj->prio = pthread_obj->attr.priority;
    pthread_obj->state = P_THREAD_STATE_INIT;
    pthread_obj->cleanup = _p_thread_cleanup;
    pthread_obj->exit_value = NULL;
    pthread_obj->join_thread = NULL;
#if P_CPU_NR > 1
    pthread_obj->bindcpu = pthread_obj->attr.bindcpu;
    pthread_obj->oncpu = CPU_NA;
#endif
    
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
    KLOG_ASSERT(_thread->state != P_THREAD_STATE_DEAD);
    KLOG_ASSERT(_thread->join_thread == NULL);

    _thread->exit_value = value_destination;
    _thread->join_thread = _self;
    _self->state = P_THREAD_STATE_BLOCK;
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
    _thread->state = P_THREAD_STATE_DEAD;
    pup_sched();
    
    arch_irq_unlock(key);
}

int sched_yield(void) {
    struct _pthread_obj *_thread = pup_cpu_self()->curr_thread;
    pup_base_t key = arch_irq_lock();
    
    KLOG_ASSERT(pup_cpu_self()->curr_thread != NULL);
    KLOG_ASSERT(_thread->state == P_THREAD_STATE_RUN);

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

char main_pthread_stack[4096];
void *puppy_main_thread(void *arg);
void puppy_init(void) {
    pup_cpu_init();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, sizeof(main_pthread_stack));
    pthread_attr_setstackaddr(&attr, main_pthread_stack);
    pthread_create(NULL, &attr, puppy_main_thread, NULL);
#if P_CPU_NR > 1
    pup_subcpu_start();
#endif
    pup_sched_unlock();
    while (1);
}