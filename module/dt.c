
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "dt.h"
#include "dt_proc.h"
#include "dt_probe.h"
#include "dt_sysfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Harper-Cyr");
MODULE_DESCRIPTION("Kernel-side of " DT_MODULE_NAME);
MODULE_VERSION("alpha");

static int __init dt_init(void)
{
	int ret = 0;
	struct hlist_head sysfs_attrs = HLIST_HEAD_INIT;

	ret = dt_proc_init(&sysfs_attrs);
	if(ret < 0)
	{
		printk(DT_PRINTK_ERR "Could not initialize pid");
		return ret;
	}
	ret = dt_probe_init(&sysfs_attrs);
	if(ret < 0)
	{
		dt_proc_exit();
		printk(DT_PRINTK_ERR "Could not initialize probe");
		return ret;
	}
	ret = dt_sysfs_init(DT_MODULE_NAME, &sysfs_attrs);
	if(ret < 0)
	{
		dt_probe_exit();
		dt_proc_exit();
		printk(DT_PRINTK_ERR "Could not initialize sysfs");
		return ret;
	}
	return 0;
}
module_init(dt_init);

static void __exit dt_exit(void)
{
	dt_sysfs_exit();
	dt_probe_exit();
	dt_proc_exit();
}
module_exit(dt_exit);