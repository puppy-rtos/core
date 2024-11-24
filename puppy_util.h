/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PUPPY_INC_UTIL_H__
#define PUPPY_INC_UTIL_H__

int puppy_board_init(void);
int pup_hw_cons_getc(void);
int pup_hw_cons_output(const char *str, int len);
int printk(const char *fmt, ...);

#define PUP_ROM_SECTION "puppy_rom_sym."
#define PUP_RAM_SECTION "puppy_ram_sym."

#define PUP_SECTION_DATA(x) pup_section(x ".1")
#define PUP_SECTION_START_DEFINE(x, name) pup_used static pup_base_t name pup_section(x ".0")
#define PUP_SECTION_END_DEFINE(x, name)   pup_used static pup_base_t name pup_section(x ".2")
#define PUP_SECTION_START_ADDR(name) (&name + 1)
#define PUP_SECTION_END_ADDR(name)   (&name)

#define PUP_TC_PASS()         printk("Test Passed! at %s:%d\r\n", __FUNCTION__, __LINE__);
#define PUP_TC_FAIL()         printk("Test Failed! at %s:%d\r\n", __FUNCTION__, __LINE__); 
#define PUP_TC_LOG(...)   do {printk(__VA_ARGS__); printk("\r\n");} while (0);

struct pup_ex_fn
{
    const char *name;
    void      (*func)(void);
};

#define PUP_TC_SECTION PUP_ROM_SECTION "PUP_TC_LIST"
#define PUP_TC_FUNC(fn, name)                         \
    pup_used const static struct pup_ex_fn _pup_tc_##fn   \
    PUP_SECTION_DATA(PUP_TC_SECTION) = { #name, fn}

#define PUP_INIT_SECTION PUP_ROM_SECTION "PUP_INIT_LIST"
#define PUP_INIT_FUNC(fn)                                     \
    pup_used const char _init_##fn##_name[] = #fn;            \
    pup_used const static struct pup_ex_fn _init_##fn           \
    PUP_SECTION_DATA(PUP_INIT_SECTION) = { _init_##fn##_name, fn}

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
    struct _list_node *next; /* ptr to next node    (pup_node_t) */
    struct _list_node *prev; /* ptr to previous node (pup_node_t) */
};
typedef struct _list_node pup_list_t;
typedef struct _list_node pup_node_t;

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
    for (node = (list)->next; node != (list); node = node->next)

/**
 * @brief Provide the primitive to safely iterate on a list
 * Note: node can be removed, it will not break the loop.
 * @param list A pointer on a pup_list_t to iterate on.
 * @param node A pup_node_t pointer to peek each node of the list
 * @param node_s A pup_node_t pointer for the loop to run safely
 */
#define pup_list_for_each_node_safe(list, node, node_s) \
    for (node = (list)->next, node_s = node->next; node != (list); \
        node = node_s, node_s = node->next)

#define PUP_LIST_STATIC_INIT(list_ptr) { {(list_ptr)}, {(list_ptr)} }

static inline void pup_list_init(pup_list_t *list) {
    list->next = list->prev = list;
}

static inline bool pup_list_is_empty(pup_list_t *list) {
    return list->next == list;
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
    pup_node_t *const tail = list->prev;

    node->next = list;
    node->prev = tail;

    tail->next = node;
    list->prev = node;
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
    pup_node_t *const head = list->next;

    node->next = head;
    node->prev = list;

    head->prev = node;
    list->next = node;
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

typedef struct {
  uint8_t *buffer;
  size_t size;
  atomic_size_t head;
  atomic_size_t tail;
} pup_rb_t;

static inline bool pup_rb_init(pup_rb_t *rb, uint8_t *buffer, size_t size)
{
    if (rb == NULL || buffer == NULL || size == 0)
    {
        return false;
    }
    rb->buffer = buffer;
    rb->size = size;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    return true;
}

static inline bool pup_rb_write(pup_rb_t *rb, const uint8_t *data, size_t length)
{
    if (rb == NULL || data == NULL || length == 0) {
        return false;
    }

    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    if (tail + rb->size - head < length) {
        return false;
    }

    for (size_t i = 0; i < length; ++i) {
        rb->buffer[head % rb->size] = data[i];
        ++head;
    }

    atomic_store_explicit(&rb->head, head, memory_order_release);

    return true;
}

static inline bool pup_rb_read(pup_rb_t *rb, uint8_t *data, size_t length)
{
    if (rb == NULL || data == NULL || length == 0) {
        return false;
    }

    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    if (head - tail < length) {
        return false;
    }

    for (size_t i = 0; i < length; ++i) {
        data[i] = rb->buffer[tail % rb->size];
        ++tail;
    }

    atomic_store_explicit(&rb->tail, tail, memory_order_release);

    return true;
}

#endif
