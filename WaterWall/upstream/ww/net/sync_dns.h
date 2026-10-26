#pragma once

/*
 * Synchronous DNS resolution helper for address contexts.
 */

#include "wlibc.h"
#include "address_context.h"

// TODO (internal cache , prefer v4/6)
/**
 * @brief Resolve a domain-based address context to an IP address in-place.
 *
 * @param s_ctx Address context to resolve.
 * @return true Resolution succeeded.
 * @return false Resolution failed.
 */
bool resolveContextSync(address_context_t *s_ctx);
