#ifndef DT_TRACE_H_
#define DT_TRACE_H_

#include <linux/list.h>

int dt_trace_start(void);
int dt_trace_stop(void);

int dt_trace_init(struct hlist_head* attrs);
void dt_trace_exit(void);

#endif