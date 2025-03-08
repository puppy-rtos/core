
/*
 * Copyright (c) 2022-2023, The Puppy RTOS Authors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PUPPY_INC_DEF_CONFIG_H__
#define PUPPY_INC_DEF_CONFIG_H__

#ifndef PUP_ALIGN_SIZE
#define PUP_ALIGN_SIZE  4
#endif

#ifndef PUP_CONFIG_PTHREAD_STACK_MIN
#define PUP_CONFIG_PTHREAD_STACK_MIN     512
#endif

#ifndef PUP_CONFIG_PTHREAD_STACK_DEFAULT
#define PUP_CONFIG_PTHREAD_STACK_DEFAULT 1024
#endif

#ifndef PUP_IDLE_THREAD_STACK_SIZE
#define PUP_IDLE_THREAD_STACK_SIZE  1024
#endif

#ifndef PUP_MAIN_THREAD_STACK_SIZE
#define PUP_MAIN_THREAD_STACK_SIZE  1024
#endif

#ifndef PUP_PRINTK_BUF_SIZE
#define PUP_PRINTK_BUF_SIZE  512
#endif

#define PUP_SCHED_PRIO_DEFAULT 12
#define PUP_NAME_MAX 8

#ifndef PUP_CPU_NR
#define PUP_CPU_NR 1
#endif

#define PUP_ASSERT(...) 
#define PUP_PRINTK my_printf

#endif
