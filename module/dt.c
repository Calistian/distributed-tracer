
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "dt.h"
#include "dt_pid.h"
#include "dt_probe.h"
#include "dt_sysfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Harper-Cyr");
MODULE_DESCRIPTION("Kernel-side of " DT_MODULE_NAME);
MODULE_VERSION("alpha");

static struct dt_sysfs_attrs dt_sysfs_attrs = {
	.add_pid = &dt_pid_add_pid_attr,
	.remove_pid = &dt_pid_remove_pid_attr,
	.list_pid = &dt_pid_list_pid_attr,
	.probe = &dt_probe_probe_attr
};

static int __init dt_init(void)
{
	int ret = 0;
	ret = dt_pid_init();
	if(ret < 0)
	{
		printk(DT_PRINTK_ERR "Could not initialize pid");
		return ret;
	}
	ret = dt_probe_init();
	if(ret < 0)
	{
		dt_pid_exit();
		printk(DT_PRINTK_ERR "Could not initialize probe");
		return ret;
	}
	ret = dt_sysfs_init(DT_MODULE_NAME, &dt_sysfs_attrs);
	if(ret < 0)
	{
		dt_probe_exit();
		dt_pid_exit();
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
	dt_pid_exit();
}
module_exit(dt_exit);