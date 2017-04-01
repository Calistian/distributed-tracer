#ifndef DT_SYSFS_H_
#define DT_SYSFS_H_

#include <linux/kobject.h>
#include <linux/list.h>

struct dt_sysfs_attr
{
	struct kobj_attribute* attr;
	struct hlist_node list;
};

int dt_sysfs_init(const char* name, struct hlist_head* first);
void dt_sysfs_exit(void);

#endif