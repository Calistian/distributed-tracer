

#include <linux/hashtable.h>
#include <linux/kobject.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "dt.h"
#include "dt_proc.h"
#include "dt_sysfs.h"

#ifndef DT_PROC_TABLE_SIZE
#define DT_PROC_TABLE_SIZE 4
#endif

static DEFINE_HASHTABLE(dt_proc_table, DT_PROC_TABLE_SIZE);
static rwlock_t dt_proc_table_lock;

struct dt_proc_entry
{
	struct hlist_node list;
	struct mm_struct* mm;
	uint64_t tag;
	atomic_t refcount;
	pid_t pid;
};
struct kmem_cache* dt_proc_entry_alloc;


static struct dt_proc_entry* __dt_proc_get_entry(struct task_struct* task, uint64_t tag, bool check_tag)
{
	struct dt_proc_entry* entry;
	hash_for_each_possible(dt_proc_table, entry, list, (uint64_t)task->mm)
	{
		if(entry->mm == task->mm && (!check_tag || entry->tag == tag))
		{
			return entry;
		}
	}
	return NULL;
}

static struct dt_proc_entry* __dt_proc_create_entry(struct task_struct* task, uint64_t tag)
{
	struct dt_proc_entry* entry;

	entry = kmem_cache_alloc(dt_proc_entry_alloc, GFP_KERNEL);
	entry->mm = task->mm;
	entry->tag = tag;
	atomic_set(&entry->refcount, 1);
	entry->pid = task->pid;

	hash_add(dt_proc_table, &entry->list, (uint64_t)task->mm);

	return entry;
}

static int dt_proc_ref_do(struct task_struct* task, uint64_t tag)
{
	struct dt_proc_entry* entry;
	int ret;

	read_lock(&dt_proc_table_lock);
	entry = __dt_proc_get_entry(task, tag, false);
	if(entry)
	{
		if(entry->tag == tag)
			atomic_inc(&entry->refcount);
		ret = atomic_read(&entry->refcount);
	}
	read_unlock(&dt_proc_table_lock);

	if(!entry)
	{
		write_lock(&dt_proc_table_lock);
		entry = __dt_proc_create_entry(task, tag);
		ret = atomic_read(&entry->refcount);
		write_unlock(&dt_proc_table_lock);
	}

	return ret;
}

static int dt_proc_unref_do(struct task_struct* task, uint64_t tag)
{
	struct dt_proc_entry* entry;
	int ret;

	write_lock(&dt_proc_table_lock);
	entry = __dt_proc_get_entry(task, tag, true);
	if(entry)
	{
		atomic_dec(&entry->refcount);
		ret = atomic_read(&entry->refcount);
		if (ret == 0)
		{
			hash_del(&entry->list);
			kmem_cache_free(dt_proc_entry_alloc, entry);
		}
	}
	write_unlock(&dt_proc_table_lock);

	return ret;
}

static bool dt_proc_has_do(struct task_struct* task)
{
	bool ret;

	read_lock(&dt_proc_table_lock);
	ret = __dt_proc_get_entry(task, 0, false) != NULL;
	read_unlock(&dt_proc_table_lock);

	return ret;
}

int dt_proc_ref(pid_t pid, uint64_t tag)
{
	struct pid* p = find_pid_ns(pid, &init_pid_ns);
	struct task_struct* task = pid_task(p, PIDTYPE_PID);
	if(task)
		return dt_proc_ref_do(task, tag);
	else
		return 0;
}

int dt_proc_ref_current(uint64_t tag)
{
	return dt_proc_ref_do(current, tag);
}

int dt_proc_unref(pid_t pid, uint64_t tag)
{
	struct pid* p = find_pid_ns(pid, &init_pid_ns);
	struct task_struct* task = pid_task(p, PIDTYPE_PID);
	if(task)
		return dt_proc_unref_do(task, tag);
	else
		return 0;
}

int dt_proc_unref_current(uint64_t tag)
{
	return dt_proc_unref_do(current, tag);
}

bool dt_proc_has(pid_t pid)
{
	struct pid* p = find_pid_ns(pid, &init_pid_ns);
	struct task_struct* task = pid_task(p, PIDTYPE_PID);
	if(task)
		return dt_proc_has_do(task);
	else
		return false;
}

bool dt_proc_has_current(void)
{
	return dt_proc_has_do(current);
}

/*
	Creates a list of PIDs from a space-separated string,
	it's used to parse the store for add_pid and remove_pid

	buf: The string to read from
	size: The size of the string
	pid_size: Out variable that will contain the number of PIDs

	return: The PID list, you **MUST** kfree the return value
*/
static pid_t* dt_proc_create_pid_list(const char* buf, size_t size, size_t* pid_size)
{
	char* mbuf = NULL;
	char* tmpbuf = NULL;
	char* next_pid = NULL;
	int err = 0;
	pid_t* ret = NULL;
	size_t pid_count = 0;
	long lpid = 0;

	mbuf = kmalloc(size + 1, GFP_KERNEL); // Worst case we waste 1 byte (or PAGE_SIZE if we need a new page :))
	if(unlikely(!mbuf))
		goto on_err;
	memcpy(mbuf, buf, size);
	mbuf[size] = '\0';

	// Count the number of pids for the allocation
	pid_count = 1;
	tmpbuf = mbuf;
	while(*tmpbuf != '\0')
	{
		if(*tmpbuf == ' ')
			++pid_count;
		++tmpbuf;
	}
	ret = kmalloc(sizeof(pid_t)*pid_count, GFP_KERNEL);
	if(unlikely(!ret))
		goto on_err;
	
	// Parse the string
	tmpbuf = mbuf;
	next_pid = mbuf;
	pid_count = 0;
	while(*tmpbuf != '\0')
	{
		if(*tmpbuf == ' ')
		{
			*tmpbuf = '\0';
			err = kstrtol(next_pid, 10, &lpid);
			if(!err)
			{
				ret[pid_count] = lpid;
				++pid_count;
			}
			next_pid = tmpbuf + 1;
		}
		++tmpbuf;
	}
	err = kstrtol(next_pid, 10, &lpid);
	if(!err)
	{
		ret[pid_count] = lpid;
		++pid_count;
	}
	*pid_size = pid_count;

cleanup:
	kfree(mbuf);
	return ret;
on_err:
	kfree(ret);
	ret = NULL;
	goto cleanup;
}

// Store function for the add_pid attribute, adds a PID to the table of PIDs if it's not there
static ssize_t dt_proc_add_pid_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	pid_t* to_add;
	size_t n;
	size_t i;

	to_add = dt_proc_create_pid_list(buf, size, &n);
	if(unlikely(!to_add))
	{
		printk(DT_PRINTK_WARN "Could not add PIDs");
		return -EINVAL;
	}

	for(i = 0; i < n; i++)
	{
		dt_proc_ref(to_add[i], 0);
	}
	kfree(to_add);
	return size;
}

// Store function for the remove_pid attribute, removes a PID from the table of PIDs if it's there
static ssize_t dt_proc_remove_pid_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	pid_t* to_remove;
	size_t n;
	size_t i;

	to_remove = dt_proc_create_pid_list(buf, size, &n);
	if(unlikely(!to_remove))
	{
		printk(DT_PRINTK_WARN "Could not remove PIDs");
		return -EINVAL;
	}

	for(i = 0; i < n; i++)
	{
		dt_proc_unref(to_remove[i], 0);
	}

	kfree(to_remove);
	return size;
}

// Show function for the list_pid attribute
static ssize_t dt_proc_list_pid_show(struct kobject* obj, struct kobj_attribute* attr, char* buf)
{
	size_t written = 0;
	struct dt_proc_entry* entry;
	int bkt;

	read_lock(&dt_proc_table_lock);
	hash_for_each(dt_proc_table, bkt, entry, list)
	{
		written += snprintf(buf + written, PAGE_SIZE - written, "%d %u (%llx)\n", entry->pid, atomic_read(&entry->refcount), entry->tag);
		if(written >= PAGE_SIZE)
			break;
	}
	read_unlock(&dt_proc_table_lock);

	return written;
}

static struct kobj_attribute dt_proc_add_pid_attr = __ATTR(add_pid, 0220, NULL, dt_proc_add_pid_store);
static struct dt_sysfs_attr dt_proc_add_pid_sysfs_attr = {
	.attr = &dt_proc_add_pid_attr
};
static struct kobj_attribute dt_proc_remove_pid_attr = __ATTR(remove_pid, 0220, NULL, dt_proc_remove_pid_store);
static struct dt_sysfs_attr dt_proc_remove_pid_sysfs_attr = {
	.attr = &dt_proc_remove_pid_attr
};
static struct kobj_attribute dt_proc_list_pid_attr = __ATTR(list_pid, 0444, dt_proc_list_pid_show, NULL);
static struct dt_sysfs_attr dt_proc_list_pid_sysfs_attr = {
	.attr = &dt_proc_list_pid_attr
};

int dt_proc_init(struct hlist_head* attrs)
{
	dt_proc_entry_alloc = kmem_cache_create("dt_proc_entry", sizeof(struct dt_proc_entry), 0, 0, NULL);
	if(!dt_proc_entry_alloc)
	{
		printk(DT_PRINTK_ERR "Failed to create dt_proc_entry_alloc");
		return -1;
	}
	hash_init(dt_proc_table);
	rwlock_init(&dt_proc_table_lock);

	hlist_add_head(&dt_proc_add_pid_sysfs_attr.list, attrs);
	hlist_add_head(&dt_proc_remove_pid_sysfs_attr.list, attrs);
	hlist_add_head(&dt_proc_list_pid_sysfs_attr.list, attrs);

	return 0;
}

void dt_proc_exit(void)
{
	struct dt_proc_entry* entry;
	struct hlist_node* tmp;
	int bkt;

	hash_for_each_safe(dt_proc_table, bkt, tmp, entry, list)
	{
		hash_del(&entry->list);
		kmem_cache_free(dt_proc_entry_alloc, entry);
	}
	kmem_cache_destroy(dt_proc_entry_alloc);
}