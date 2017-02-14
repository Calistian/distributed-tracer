/*
	Kernel module for the distributed tracer
	To use this kernel module, there are 4 files in the /sys/distributed-tracer for control
		add_pid : write the PID in decimal to this file to add a PID to the watchlist
		remove_pid : write the PID in decimal to this file to remove a PID from the watchlist
		list_pid : Read the file to list all PIDs.
		probe : write 0 to disable the probe, 1 to enable it
*/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <net/ip.h>
#include <net/flow.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Harper-Cyr");
MODULE_DESCRIPTION("Kernel-side of the distributed tracer");
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

/*
	Initializes the PID table
*/
static int init_pid_attr(void)
{
	memset(pid_list, 0, sizeof(pid_t)*PID_LIST_MAX_SIZE);
	rwlock_init(&pid_list_lock);
	return 0;
}

/*
	Reads a PID from a decimal string

	buf: The string
	size: The size of the string

	return: The PID, 0 if PID is invalid
*/
static pid_t read_pid(const char* buf, size_t size)
{
	int used_alloc = 0;
	char* tmpbuf;
	pid_t pid;
	long int lpid;
	int err;

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

	err = kstrtol(tmpbuf, 10, &lpid);
	if(used_alloc)
		kfree(tmpbuf);

	if(err)
		return 0;
	pid = lpid;

	return pid;
}

/*
	add_pid file write callback, adds a PID in the table if there is space
*/
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

/*
	remove_pid file write callback, removes a PID from the table if it's there
*/
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

/*
	list_pid file read callback, lists, one per line, all PIDs in the table
*/
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

/*
	Cleans up the PID table
*/
static void cleanup_pid_attr(void)
{

}

static struct kobj_attribute controller_add_pid_attr = __ATTR(add_pid, 0220, NULL, controller_add_pid_store);
static struct kobj_attribute controller_remove_pid_attr = __ATTR(remove_pid, 0220, NULL, controller_remove_pid_store);
static struct kobj_attribute controller_list_pid_attr = __ATTR(list_pid, 0444, controller_list_pid_show, NULL);

//##########################################################################################
//##########################################################################################
//##########################################################################################

/*
	Checks if the PID is in the table
*/
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

/*
	Probe function that will be placed at the entry of ip_queue_xmit
*/
static int ip_queue_xmit_probe_fn(struct sock* sk, struct sk_buff* skb, struct flowi* fl)
{
	char* data;
	struct task_struct* cur = current;
	// Do something only if the calling PID is in the PID table
	if(cur && is_pid_in_list(cur->pid))
	{
		printk(PRINTK_INFO "ip_queue_xmit %d", cur->pid);
		data = skb->data;
		// Flip the first reserved bit in the TCP header and update checksum accordingly
		data[12] |= (1 << 3);
		data[16] ^= (1 << 3);
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

/*
	Initializes the probe
*/
static int init_probe_attr(void)
{
	registered = 0;
	return 0;
}

/*
	Adds the probe
*/
static int register_ip_queue_xmit_probe(void)
{
	int ret;
	if(registered)
		return 0;
	ret = register_jprobe(&ip_queue_xmit_probe);
	if(ret < 0)
	{
		printk(PRINTK_ERR "Failed to register ip_queue_xmit probe\n");
		return ret;
	}
	registered = 1;
	return 0;
}

/*
	Removes the probe
*/
static void unregister_ip_queue_xmit_probe(void)
{
	if(!registered)
		return;
	unregister_jprobe(&ip_queue_xmit_probe);
	registered = 0;
}

/*
	probe file read callback, returns the value of registered
*/
static ssize_t controller_probe_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf)
{
	if(registered)
		*buf = '1';
	else
		*buf = '0';
	return 1;
}

/*
	probe file write callback, sets the value of registered and places/removes the probe
*/
static ssize_t controller_probe_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	int ret;

	if(size < 1)
		return -EINVAL;
	if(*buf == '0')
		unregister_ip_queue_xmit_probe();
	else if(*buf == '1')
	{
		ret = register_ip_queue_xmit_probe();
		if(ret < 0)
		{
			return -EACCES;
		}
	}
	else
		return -EINVAL;
	return size;
}

/*
	Cleanup's the probe
*/
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
	struct attribute_group attr_group = {
		.attrs = controller_root_object_attributes
	};

	controller_root_object = kobject_create_and_add(MODULE_NAME, NULL);
	if(controller_root_object == NULL)
	{
		printk(PRINTK_ERR "Failed to create sysfs entry\n");
		return -1;
	}
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