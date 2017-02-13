
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/ip.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <net/flow.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Harper-Cyr");
MODULE_DESCRIPTION("Kernel-side of");
MODULE_VERSION("alpha");

#define MODULE_NAME "distributed-tracer"
#define PRINTK_INFO KERN_INFO MODULE_NAME ": "
#define PRINTK_ERR KERN_ERR MODULE_NAME ": "

#define PID_LIST_MAX_SIZE 32
static pid_t pid_list[PID_LIST_MAX_SIZE];
rwlock_t pid_list_lock;

//##########################################################################################
//##########################################################################################
//##########################################################################################

static int init_pid_attr(void)
{
	memset(pid_list, 0, sizeof(pid_t)*PID_LIST_MAX_SIZE);
	rwlock_init(&pid_list_lock);
	return 0;
}

static pid_t read_pid(const char* buf, size_t size)
{
	int used_alloc = 0;
	char* tmpbuf;

	if(size == 0)
		return 0;

	if(buf[size] != '\0')
	{
		tmpbuf = kmalloc(size + 1, GFP_KERNEL);
		memcpy(tmpbuf, buf, size);
		tmpbuf[size] = '\0';
		used_alloc = 1;
	}
	else
		tmpbuf = (char*)buf;

	pid_t pid;
	long int lpid;
	int err = kstrtol(tmpbuf, 10, &lpid);
	if(used_alloc)
		kfree(tmpbuf);

	if(err)
		return 0;
	pid = lpid;

	return pid;
}

static ssize_t controller_add_pid_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	int i;
	int found;
	pid_t pid = read_pid(buf, size);

	if(pid == 0)
		return -EINVAL;

	read_lock(&pid_list_lock);
	for(i = 0; i < PID_LIST_MAX_SIZE; i++)
	{
		if(pid_list[i] == pid)
			return size;
	}
	read_unlock(&pid_list_lock);

	write_lock(&pid_list_lock);
	for(i = 0; i < PID_LIST_MAX_SIZE; i++)
	{
		if(pid_list[i] == 0)
		{
			pid_list[i] = pid;
			found = 1;
			break;
		}
	}
	write_unlock(&pid_list_lock);
	if(!found)
		return -ENOMEM;

	return size;
}

static ssize_t controller_remove_pid_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	int i;
	int found = 0;
	pid_t pid = read_pid(buf, size);

	if(pid == 0)
		return -EINVAL;

	write_lock(&pid_list_lock);
	for(i = 0; i < PID_LIST_MAX_SIZE; i++)
	{
		if(pid_list[i] == pid)
		{
			pid_list[i] = 0;
			found = 1;
			break;
		}
	}
	write_unlock(&pid_list_lock);

	if(!found)
		return -EINVAL;

	return size;
}

static ssize_t controller_list_pid_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf)
{
	int written = 0;
	int i;
	for(i = 0; i < PID_LIST_MAX_SIZE; i++)
	{
		if(pid_list[i] != 0)
		{
			written += snprintf(buf + written, PAGE_SIZE - written, "%d\n", pid_list[i]);
			if(written >= PAGE_SIZE)
				break;
		}
	}
	return written;
}

static void cleanup_pid_attr(void)
{

}

static struct kobj_attribute controller_add_pid_attr = __ATTR(add_pid, 0220, NULL, controller_add_pid_store);
static struct kobj_attribute controller_remove_pid_attr = __ATTR(remove_pid, 0220, NULL, controller_remove_pid_store);
static struct kobj_attribute controller_list_pid_attr = __ATTR(list_pid, 0444, controller_list_pid_show, NULL);

//##########################################################################################
//##########################################################################################
//##########################################################################################

int is_pid_in_list(pid_t pid)
{
	int i;
	int ret = 0;
	read_lock(&pid_list_lock);
	for(i = 0; i < PID_LIST_MAX_SIZE; i++)
	{
		if(pid_list[i] != 0 && pid_list[i] == pid)
		{
			ret = 1;
			break;
		}
	}
	read_unlock(&pid_list_lock);
	return ret;
}

static int ip_queue_xmit_probe_fn(struct sock* sk, struct sk_buff* skb, struct flowi* fl)
{
	struct task_struct* cur = current;
	if(cur && is_pid_in_list(cur->pid))
	{
		printk(PRINTK_INFO "Test");
	}
	jprobe_return();
	return 0;
}

struct jprobe ip_queue_xmit_probe = {
	.entry = ip_queue_xmit_probe_fn,
	.kp = {
		.symbol_name = "ip_queue_xmit"
	}
};
int registered;

static int init_probe_attr(void)
{
	registered = 0;
	return 0;
}

static int register_ip_queue_xmit_probe(void)
{
	if(registered)
		return 0;
	int ret = register_jprobe(&ip_queue_xmit_probe);
	if(ret < 0)
	{
		printk(PRINTK_ERR "Failed to register ip_queue_xmit probe\n");
		return ret;
	}
	registered = 1;
	return 0;
}

static void unregister_ip_queue_xmit_probe(void)
{
	if(!registered)
		return;
	unregister_jprobe(&ip_queue_xmit_probe);
	registered = 0;
}

static ssize_t controller_probe_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf)
{
	if(registered)
		*buf = '1';
	else
		*buf = '0';
	return 1;
}

static ssize_t controller_probe_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	if(size < 1)
		return -EINVAL;
	if(*buf == '0')
		unregister_ip_queue_xmit_probe();
	else if(*buf == '1')
	{
		int ret = register_ip_queue_xmit_probe();
		if(ret < 0)
		{
			return -EACCES;
		}
	}
	else
		return -EINVAL;
	return size;
}

static void cleanup_probe_attr(void)
{
	unregister_ip_queue_xmit_probe();
}

static struct kobj_attribute controller_probe_attr = __ATTR(probe, 0664, controller_probe_show, controller_probe_store);

//##########################################################################################
//##########################################################################################
//##########################################################################################

static struct kobject* controller_root_object;
static struct attribute* controller_root_object_attributes[] = {
	&controller_add_pid_attr.attr,
	&controller_remove_pid_attr.attr,
	&controller_list_pid_attr.attr,
	&controller_probe_attr.attr,
	NULL
};

static int __init tracer_init(void)
{
	int ret;
	controller_root_object = kobject_create_and_add(MODULE_NAME, NULL);
	if(controller_root_object == NULL)
	{
		printk(PRINTK_ERR "Failed to create sysfs entry\n");
		return -1;
	}
	struct attribute_group attr_group = {
		.attrs = controller_root_object_attributes
	};
	ret = sysfs_create_group(controller_root_object, &attr_group);
	if(ret < 0)
	{
		kobject_put(controller_root_object);
		printk(PRINTK_ERR "Failed to add attributes to sysfs entry %d\n", ret);
		return ret;
	}
	ret = init_pid_attr();
	if(ret < 0)
	{
		kobject_put(controller_root_object);
		printk(PRINTK_ERR "Failed to initialize the pid controller %d\n", ret);
		return ret;
	}
	ret = init_probe_attr();
	if(ret < 0)
	{
		cleanup_pid_attr();
		kobject_put(controller_root_object);
		printk(PRINTK_ERR "Failed to initialize the probe controller %d\n", ret);
		return ret;
	}
	return 0;
}
module_init(tracer_init);

static void __exit tracer_exit(void)
{
	cleanup_probe_attr();
	cleanup_pid_attr();
	kobject_put(controller_root_object);
}
module_exit(tracer_exit);