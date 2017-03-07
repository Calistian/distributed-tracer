#ifndef DT_SYSFS_H_
#define DT_SYSFS_H_

#include <linux/kobject.h>

struct dt_sysfs_attrs
{
	struct kobj_attribute* add_pid;
	struct kobj_attribute* remove_pid;
	struct kobj_attribute* list_pid;
	struct kobj_attribute* probe; 
};

int dt_sysfs_init(const char* name, struct dt_sysfs_attrs* attrs);
void dt_sysfs_exit(void);

#endif