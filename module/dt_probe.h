#ifndef DT_PROBE_H_
#define DT_PROBE_H_

#include <linux/list.h>

int dt_probe_init(struct hlist_head* attrs);
void dt_probe_exit(void);

#endif