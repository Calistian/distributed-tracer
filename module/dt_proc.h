#ifndef DT_PID_H_
#define DT_PID_H_

#include <linux/list.h>

int dt_proc_ref(pid_t pid, uint64_t tag);
int dt_proc_ref_current(uint64_t tag);

int dt_proc_unref(pid_t pid, uint64_t tag);
int dt_proc_unref_current(uint64_t tag);

bool dt_proc_has(pid_t pid);
bool dt_proc_has_current(void);

int dt_proc_init(struct hlist_head* attrs);
void dt_proc_exit(void);

#endif