/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_EVENT_H
#define SKB_EVENT_H

#include <stdio.h>

#include "skbouncer.h"

void skb_event_header(FILE *out);
void skb_event_print(FILE *out, const struct skb_event *ev);

#endif /* SKB_EVENT_H */
