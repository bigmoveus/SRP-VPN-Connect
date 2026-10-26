#pragma once

/*
 * Memory manager bootstrap APIs and dedicated-memory state hooks.
 */

#include "wlibc.h"


struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

/**
 * @brief Initialize global memory allocator backend.
 */
void memorymanagerInit(void);

/**
 * @brief Set dedicated-memory state used by memory manager.
 *
 * @param new_state Dedicated memory state.
 */
void memorymanagerSetState(dedicated_memory_t *new_state);

/**
 * @brief Create a dedicated memory context (if supported by backend).
 *
 * @return dedicated_memory_t* Dedicated memory state or NULL.
 */
dedicated_memory_t *memorymanagerCreateDedicatedMemory(void);


