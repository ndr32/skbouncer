/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_EVENT_H
#define SKB_EVENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "skbouncer.h"

const char *skb_direction_name(uint8_t dir);

/* Times are local wall clock. A NULL `verdict` and `reason` mean no policy
 * is loaded, and the column or key is left out. */
void skb_event_header(FILE *out, bool verdict, bool action);
/* `container` is the name for ev->cgroup_id, or NULL if it is none. */
void skb_event_print(FILE *out, const struct skb_event *ev, const char *container,
		     const char *verdict, const char *reason);

/* One JSON object per line, with no header. */
void skb_event_print_json(FILE *out, const struct skb_event *ev,
			  const char *container, const char *verdict, const char *reason);

#endif /* SKB_EVENT_H */
