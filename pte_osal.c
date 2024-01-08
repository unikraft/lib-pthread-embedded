/* SPDX-License-Identifier: LGPL-2.0-or-later */
/*
 *      Unikraft port of POSIX Threads Library for embedded systems
 *      Copyright(C) 2019 Costin Lupu, University Politehnica of Bucharest
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * This port is derived from hermit/pte_osal.c.
 */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <uk/essentials.h>
#include <uk/init.h>
#include <uk/arch/time.h>
#include <uk/arch/atomic.h>
#include <uk/print.h>
#include <uk/thread.h>
#include <uk/sched.h>
#include "pte_osal.h"
#include "pthread.h"
#include "tls-helper.h"


typedef struct pte_thread_data {
	/* thread routine */
	pte_osThreadEntryPoint entry_point;
	/* thread routine arguments */
	void *argv;
	/* Unikraft thread */
	struct uk_thread *uk_thread;
	/* TLS */
	void *tls;
	/* Semaphore for triggering thread start */
	struct uk_semaphore start_sem;
	/* Semaphore for cancellation */
	struct uk_semaphore cancel_sem;
	/* Is non-zero if thread exited */
	int done;
} pte_thread_data_t;


/****************************************************************************
 *
 * Initialization
 *
 ***************************************************************************/

static bool initialized /* false */;

static int pthread_initcall(void)
{
	int result;

	uk_pr_info("Initialize pthread-embedded\n");
	result = pthread_init();

	if (result == PTE_TRUE)
		initialized = true;
	return result;
}
uk_early_initcall_prio(pthread_initcall, UK_PRIO_EARLIEST);

pte_osResult pte_osInit(void)
{
	pte_osResult result = PTE_OS_OK;
	pte_thread_data_t *ptd;
	struct uk_thread *crnt;

	/* Allocate and initialize TLS support */
	result = pteTlsGlobalInit(CONFIG_LIBPTHREAD_EMBEDDED_MAX_TLS);
	if (result != PTE_OS_OK) {
		uk_pr_err("Could not init global TLS");
		goto out;
	}

	/* Create a ptd for initializing thread. */
	ptd = calloc(1, sizeof(pte_thread_data_t));
	if (ptd == NULL) {
		result = PTE_OS_NO_RESOURCES;
		goto out;
	}

	ptd->tls = pteTlsThreadInit();
	if (ptd->tls == NULL) {
		uk_pr_err("Could not init TLS");
		free(ptd);
		result = PTE_OS_NO_RESOURCES;
		goto out;
	}

	crnt = uk_thread_current();
	crnt->priv = ptd;
	ptd->uk_thread = crnt;

out:
	return result;
}

/***************************************************************************
 *
 * Signal handling
 *
 **************************************************************************/
#if CONFIG_LIBUKSIGNAL
int pte_kill(pte_osThreadHandle threadId, int sig)
{
	//return uk_sig_thread_kill(threadId->uk_thread, sig);
	// FIXME after proper uksignal implementation is complete
	return 0;
}
#endif


/****************************************************************************
 *
 * Threads
 *
 ***************************************************************************/

static pte_thread_data_t *handle_to_ptd(pte_osThreadHandle h)
{
	return h;
}

static pte_thread_data_t *current_ptd(void)
{
	return uk_thread_current()->priv;
}

static void uk_stub_thread_entry(void *argv)
{
	pte_thread_data_t *ptd =
		(pte_thread_data_t *) uk_thread_current()->priv;

	UK_ASSERT(ptd);

	/* wait for the resume command */
	uk_semaphore_down(&ptd->start_sem);

	ptd->entry_point(argv);
}

/* NOTE: We need to be able to distinguish if we created a thread through
 *       pthread API or through uksched API. In case of pthread_create()
 *       we have to setup some different properties to the thread like creating
 *       it in paused state.
 *       In order to distinguish, we will use a magic number as entry function.
 *       With the thread argument we forward the actual entry point and argument
 *       vector. During creation our init callback will be executed by uksched
 *       and we are able to check if we find our magic number again and handle
 *       the initialization accordingly.
 */

/* Use a pointer that points to itself as magic number. This way we can be
 * sure that the magic number (= pointer address) is unique and reserved
 * for our purpose.
 */
static const void *PTE_CAPSULE_MAGIC = &PTE_CAPSULE_MAGIC;
struct pte_entry_capsule {
	void *magic;
	pte_osThreadEntryPoint entry_point;
	void *argv;
};

pte_osResult pte_osThreadCreate(pte_osThreadEntryPoint entry_point,
	int stack_size, int initial_prio, void *argv,
	pte_osThreadHandle *ph)
{
	struct pte_entry_capsule capsule;
	struct uk_thread *th;
	struct uk_sched *s = uk_sched_current();

	capsule.magic = PTE_CAPSULE_MAGIC;
	capsule.entry_point = entry_point;
	capsule.argv        = argv;

	/* Create the Unikraft thread. This will cause that pte_osInitThread()
	 * is called. The thread's priv pointer will point to the capsule
	 * after thread creation.
	 */

	th = uk_sched_thread_create_fn1(s, uk_stub_thread_entry, argv,
					0, 0, 0, NULL, &capsule, NULL);
	if (!th)
		return PTE_OS_NO_RESOURCES;

	/* pte_osInitThread() should have setup a newly created
	 * pte_thread_data_t which should be stored on th->priv
	 */
	UK_ASSERT(th->priv);

	/* Return the thread handle */
	*ph = th->priv;
	return PTE_OS_OK;
}

static int pte_osInitThread(struct uk_thread *th)
{
	pte_thread_data_t *ptd;
	struct pte_entry_capsule *capsule;

	/* Initialize pte with first thread creation */
	if (unlikely(!initialized)) {
		uk_pr_warn("Thread %p created without " STRINGIFY(__LIBNAME__)
			   " initialized. Utilizing the pthread API from this context may lead to memory leaks.\n",
			   th);
		return 0;
	}

	ptd = calloc(1, sizeof(pte_thread_data_t));
	if (!ptd)
		goto err_out;

	/* Allocate TLS structure for this thread. */
	ptd->tls = pteTlsThreadInit();
	if (!ptd->tls) {
		uk_pr_err("Could not allocate TLS\n");
		goto err_free_ptd;
	}

	capsule = (struct pte_entry_capsule *)th->priv;
	/* How did we enter this function? */
	if (capsule && capsule->magic == PTE_CAPSULE_MAGIC) {
		/*
		 * Found the magic value. Thread was created
		 * by pte_osThreadCreate().
		 */
		ptd->entry_point = capsule->entry_point;
		ptd->argv        = capsule->argv;

		/* this thread has to wait for further setup */
		uk_semaphore_init(&ptd->start_sem, 0);
	} else {
		/* Thread not created by pte_osThreadCreate()*/

		free(ptd);
		return 0;
		/* TODO: Not implemented yet. */
		/* We will encapsulate our thread entry point,
		 * we have to move our actual entry to ptd
		 */
		//ptd->entry_point = (pte_osThreadEntryPoint) th->entry;
		//ptd->argv        = th->arg;

		/* uksched threads need to start automatically */
		//uk_semaphore_init(&ptd->start_sem, 1);
	}

	/* Setup encapsulated entry point */
	//th->entry = uk_stub_thread_entry;
	//th->arg   = ptd;
	uk_semaphore_init(&ptd->cancel_sem, 0);
	ptd->done = 0;

	/* Store cross references (uk_thread <-> pte_thread_data_t) */
	th->priv = ptd;
	ptd->uk_thread = th;

#if CONFIG_LIBUKSIGNAL
	/* FIXME after uksignal implementation: inherit signal mask */
	//ptd->uk_thread->signals_container.mask =
	//	uk_thread_current()->signals_container.mask;
#endif
	return 0;

err_free_ptd:
	free(ptd);
err_out:
	return -1;
}

static void pte_osFiniThread(struct uk_thread *th)
{
	/* We clean up resources in pte_osThreadDelete() */
}

UK_THREAD_INIT_PRIO(pte_osInitThread, pte_osFiniThread, UK_PRIO_EARLIEST);

pte_osResult pte_osThreadStart(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	/* wake up thread */
	uk_semaphore_up(&ptd->start_sem);

	return 0;
}

pte_osResult pte_osThreadDelete(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	/* free resources */
	pteTlsThreadDestroy(ptd->tls);
	free(ptd);

	return PTE_OS_OK;
}

pte_osResult pte_osThreadExitAndDelete(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);
	UK_ASSERT(ptd->uk_thread);

	if (ptd->uk_thread->sched)
		uk_thread_terminate(ptd->uk_thread);
	pte_osThreadDelete(h);

	return PTE_OS_OK;
}

void pte_osThreadExit(void)
{
	pte_thread_data_t *ptd = current_ptd();

	ptd->done = 1;
	uk_sched_thread_exit();
}

pte_osResult pte_osThreadWaitForEnd(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);
	pte_thread_data_t *self_ptd = current_ptd();

	while (1) {
		if (ptd->done) {
			if (ptd->uk_thread) {
				uk_thread_block(ptd->uk_thread);

				/* The thread is destroyed after the wait */
				ptd->uk_thread = NULL;
			}

			return PTE_OS_OK;
		}

		if (self_ptd && self_ptd->cancel_sem.count > 0)
			return PTE_OS_INTERRUPTED;

		else
			uk_sched_yield();
	}
}

pte_osResult pte_osThreadCancel(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	uk_semaphore_up(&ptd->cancel_sem);

	return PTE_OS_OK;
}

pte_osResult pte_osThreadCheckCancel(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	if (ptd && ptd->cancel_sem.count > 0)
		return PTE_OS_INTERRUPTED;

	return PTE_OS_OK;
}

pte_osThreadHandle pte_osThreadGetHandle(void)
{
	return current_ptd();
}

int pte_osThreadGetPriority(pte_osThreadHandle h)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	/* No priorities implemented. */
	int ret = 0;

	return ret ? PTE_OS_GENERAL_FAILURE : PTE_OS_OK;
}

pte_osResult pte_osThreadSetPriority(pte_osThreadHandle h, int new_prio)
{
	pte_thread_data_t *ptd = handle_to_ptd(h);

	/* No priorities implemented. */
	int ret = 0;

	return ret ? PTE_OS_GENERAL_FAILURE : PTE_OS_OK;
}

void pte_osThreadSleep(unsigned int msecs)
{
	__nsec nsec = ukarch_time_msec_to_nsec(msecs);

	uk_sched_thread_sleep(nsec);
}

int pte_osThreadGetMinPriority(void)
{
	/* No priorities implemented. */
	return 0;
}

int pte_osThreadGetMaxPriority(void)
{
	/* No priorities implemented. */
	return 0;
}

int pte_osThreadGetDefaultPriority(void)
{
	/* No priorities implemented. */
	return 0;
}

/****************************************************************************
 *
 * Mutexes
 *
 ****************************************************************************/

pte_osResult pte_osMutexCreate(pte_osMutexHandle *ph)
{
	struct uk_mutex *m;

	if (!ph)
		return PTE_OS_INVALID_PARAM;

	m = malloc(sizeof(struct uk_mutex));
	if (!m)
		return PTE_OS_NO_RESOURCES;

	uk_mutex_init(m);

	*ph = m;

	return PTE_OS_OK;
}

pte_osResult pte_osMutexDelete(pte_osMutexHandle h)
{
	if (!h)
		return PTE_OS_INVALID_PARAM;

	free(h);

	return PTE_OS_OK;
}

pte_osResult pte_osMutexLock(pte_osMutexHandle h)
{
	if (!h)
		return PTE_OS_INVALID_PARAM;

	uk_mutex_lock(h);

	return PTE_OS_OK;
}

pte_osResult pte_osMutexTimedLock(pte_osMutexHandle h,
	unsigned int timeoutMsecs)
{
	return PTE_OS_GENERAL_FAILURE;
}


pte_osResult pte_osMutexUnlock(pte_osMutexHandle h)
{
	if (!h)
		return PTE_OS_INVALID_PARAM;

	uk_mutex_unlock(h);

	return PTE_OS_OK;
}

/****************************************************************************
 *
 * Semaphores
 *
 ***************************************************************************/

pte_osResult pte_osSemaphoreCreate(int init_value, pte_osSemaphoreHandle *ph)
{
	struct uk_semaphore *s;

	if (!ph)
		return PTE_OS_INVALID_PARAM;

	s = malloc(sizeof(struct uk_semaphore));
	if (!s)
		return PTE_OS_NO_RESOURCES;

	uk_semaphore_init(s, init_value);

	*ph = s;

	return PTE_OS_OK;
}

pte_osResult pte_osSemaphoreDelete(pte_osSemaphoreHandle h)
{
	if (!h)
		return PTE_OS_INVALID_PARAM;

	free(h);

	return PTE_OS_OK;
}

pte_osResult pte_osSemaphorePost(pte_osSemaphoreHandle h, int count)
{
	int i;

	if (!h)
		return PTE_OS_INVALID_PARAM;

	for (i = 0; i < count; i++)
		uk_semaphore_up(h);

	return PTE_OS_OK;
}

pte_osResult pte_osSemaphorePend(pte_osSemaphoreHandle h,
	unsigned int *ptimeout_msecs)
{
	__nsec timeout;

	if (!h)
		return PTE_OS_INVALID_PARAM;

	if (ptimeout_msecs) {
		timeout = ukarch_time_msec_to_nsec(*ptimeout_msecs);

		if (uk_semaphore_down_to(h, timeout) == __NSEC_MAX)
			return PTE_OS_TIMEOUT;

	} else
		uk_semaphore_down(h);

	return PTE_OS_OK;
}

pte_osResult pte_osSemaphoreCancellablePend(pte_osSemaphoreHandle h,
	unsigned int *ptimeout_msecs)
{
	pte_thread_data_t *ptd = current_ptd();
	pte_osResult result = PTE_OS_OK;
	__nsec timeout = 0, start_time = ukplat_monotonic_clock();

	if (ptimeout_msecs)
		timeout = ukarch_time_msec_to_nsec(*ptimeout_msecs);

	while (1) {
		if (uk_semaphore_down_try(h))
			/* semaphore is up */
			break;

		else if (timeout &&
			(ukplat_monotonic_clock() - start_time > timeout)) {
			/* The timeout expired */
			result = PTE_OS_TIMEOUT;
			break;

		} else if (ptd && ptd->cancel_sem.count > 0) {
			/* The thread was cancelled */
			result = PTE_OS_INTERRUPTED;
			break;

		} else
			/* Maybe next time... */
			uk_sched_yield();
	}

	return result;
}

#if 0
/* We use macros instead */
/****************************************************************************
 *
 * Atomic Operations
 *
 ***************************************************************************/

static int atomic_add(int *ptarg, int val)
{
	return __atomic_add_fetch(ptarg, val, __ATOMIC_SEQ_CST);
}

int pte_osAtomicExchange(int *ptarg, int val)
{
	return ukarch_exchange_n(ptarg, val);
}

int pte_osAtomicCompareExchange(int *pdest, int exchange, int comp)
{
	int orig = *pdest;

	ukarch_compare_exchange_sync(pdest, comp, exchange);

	return orig;
}

int pte_osAtomicExchangeAdd(int volatile *paddend, int value)
{
	return ukarch_fetch_add(paddend, value);
}

int pte_osAtomicDecrement(int *pdest)
{
	return atomic_add(pdest, -1);
}

int pte_osAtomicIncrement(int *pdest)
{
	return atomic_add(pdest, 1);
}
#endif

/****************************************************************************
 *
 * Thread Local Storage
 *
 ***************************************************************************/

static void *current_tls(void)
{
	pte_thread_data_t *ptd = current_ptd();

	return ptd ? ptd->tls : NULL;
}

pte_osResult pte_osTlsSetValue(unsigned int key, void *value)
{
	return pteTlsSetValue(current_tls(), key, value);
}

void *pte_osTlsGetValue(unsigned int index)
{
	return (void *) pteTlsGetValue(current_tls(), index);
}

pte_osResult pte_osTlsAlloc(unsigned int *pkey)
{
	return pteTlsAlloc(pkey);
}

pte_osResult pte_osTlsFree(unsigned int index)
{
	return pteTlsFree(index);
}

/***************************************************************************
 *
 * Miscellaneous
 *
 ***************************************************************************/

int ftime(struct timeb *tb)
{
	__nsec now = ukplat_wall_clock();

	if (tb) {
		tb->time = ukarch_time_nsec_to_sec(now);
		tb->millitm = ukarch_time_nsec_to_msec(ukarch_time_subsec(now));
	}

	return 0;
}
