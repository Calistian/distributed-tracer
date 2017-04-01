
#include "dt_sysfs.h"
#include "dt.h"

#include <linux/slab.h>

static struct kobject* dt_sysfs_obj;

size_t list_size(struct hlist_head* list)
{
	struct hlist_node* entry;
	size_t size = 0;

	hlist_for_each(entry, list) size++;

	return size;
}

int dt_sysfs_init(const char* name, struct hlist_head* list)
{
	int ret;
	int i = 0;
	struct dt_sysfs_attr* entry;

	struct attribute** attrs = kmalloc(sizeof(struct attribute*) * (list_size(list)+1), GFP_KERNEL);
	struct attribute_group group = {
		.attrs = attrs
	};

	hlist_for_each_entry(entry, list, list)
	{
		attrs[i] = &entry->attr->attr;
		i++;
	}
	attrs[i] = NULL;

	dt_sysfs_obj = kobject_create_and_add(name, NULL);
	if(!dt_sysfs_obj)
	{
		printk(DT_PRINTK_ERR "Failed to create sysfs entry");
		return -1;
	}
	ret = sysfs_create_group(dt_sysfs_obj, &group);
	if(ret < 0)
	{
		printk(DT_PRINTK_ERR "Failed to create sysfs group");
		kobject_put(dt_sysfs_obj);
		return ret;
	}

	kfree(attrs);

	return 0;
}

void dt_sysfs_exit(void)
{
	kobject_put(dt_sysfs_obj);
}