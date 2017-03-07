
#include "dt_sysfs.h"
#include "dt.h"

static struct kobject* dt_sysfs_obj;

int dt_sysfs_init(const char* name, struct dt_sysfs_attrs* attrs)
{
	int ret;
	struct attribute* dt_sysfs_obj_attrs[] = {
		&attrs->add_pid->attr,
		&attrs->remove_pid->attr,
		&attrs->list_pid->attr,
		&attrs->probe->attr,
		NULL
	};
	struct attribute_group dt_sysfs_obj_attr_group = {
		.attrs = dt_sysfs_obj_attrs
	};
	dt_sysfs_obj = kobject_create_and_add(name, NULL);
	if(!dt_sysfs_obj)
	{
		printk(DT_PRINTK_ERR "Failed to create sysfs entry");
		return -1;
	}
	ret = sysfs_create_group(dt_sysfs_obj, &dt_sysfs_obj_attr_group);
	if(ret < 0)
	{
		printk(DT_PRINTK_ERR "Failed to create sysfs group");
		kobject_put(dt_sysfs_obj);
		return ret;
	}
	return 0;
}

void dt_sysfs_exit(void)
{
	kobject_put(dt_sysfs_obj);
}