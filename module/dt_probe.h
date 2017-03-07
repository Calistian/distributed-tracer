#ifndef DT_PROBE_H_
#define DT_PROBE_H_

#include <linux/kobject.h>

// Sysfs attribute for the probe
extern struct kobj_attribute dt_probe_probe_attr;

int dt_probe_init(void);
void dt_probe_exit(void);

#endif