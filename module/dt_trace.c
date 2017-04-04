#include <linux/kobject.h>

#include "dt_sysfs.h"
#include "dt_trace.h"

atomic_t dt_trace_active;
EXPORT_SYMBOL(dt_trace_active);

static ssize_t dt_trace_trace_show(struct kobject* obj, struct kobj_attribute* attr, char* buf)
{
	if(atomic_read(&dt_trace_active))
		*buf = '1';
	else
		*buf = '0';
	return 1;
}

static struct kobj_attribute dt_trace_trace_attr = __ATTR(trace, 0444, dt_trace_trace_show, NULL);
static struct dt_sysfs_attr dt_trace_trace_sysfs_attr = {
	.attr = &dt_trace_trace_attr
};

int dt_trace_start(void)
{
	atomic_set(&dt_trace_active, 1);
	return 0;
}

int dt_trace_stop(void)
{
	atomic_set(&dt_trace_active, 0);
	return 0;
}

int dt_trace_init(struct hlist_head* attrs)
{
	atomic_set(&dt_trace_active, 0);
	hlist_add_head(&dt_trace_trace_sysfs_attr.list, attrs);
	return 0;
}

void dt_trace_exit(void)
{
	atomic_set(&dt_trace_active, 0);
}