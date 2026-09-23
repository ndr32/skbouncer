/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_EVENT_H
#define SKB_EVENT_H

#include <stdint.h>
#include <stdio.h>

#include "skbouncer.h"

const char *skb_direction_name(uint8_t dir);

void skb_event_header(FILE *out);
void skb_event_print(FILE *out, const struct skb_event *ev);

/* One JSON object per line; no header. */
void skb_event_print_json(FILE *out, const struct skb_event *ev);

#endif /* SKB_EVENT_H */
