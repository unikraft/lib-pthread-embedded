#ifndef __PTE_OSAL_H__
#define __PTE_OSAL_H__

#include <uk/mutex.h>
#include <uk/semaphore.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pte_thread_data *pte_osThreadHandle;
typedef struct uk_semaphore *pte_osSemaphoreHandle;
typedef struct uk_mutex *pte_osMutexHandle;

#define OS_MAX_SIMUL_THREADS \
	CONFIG_LIBPTHREAD_EMBEDDED_MAX_SIMUL_THREADS

#define pte_threadhandle_to_ukthread(handle) \
	((struct uk_thread *)(handle))

#ifdef __cplusplus
}
#endif


#include "pte_generic_osal.h"

#endif /* __PTE_OSAL_H__ */
