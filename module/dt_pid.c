#include <linux/kobject.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "dt.h"
#include "dt_pid.h"

// Number of buckets for the PID hashtable
#ifndef DT_PID_TABLE_SIZE
#define DT_PID_TABLE_SIZE 4
#endif

/*
	Hashtable containing the PID to watch for, and also the R/W spinlock.
	Read mostly because we do a lot more searching than modifying (hopefully).
	Increasing refcount counts as searching.
*/
static DEFINE_READ_MOSTLY_HASHTABLE(dt_pid_table, DT_PID_TABLE_SIZE);
static rwlock_t dt_pid_table_lock;

/*
	Entry in the PID hashtable, the key for the hashtable is pid.

	pid: The pid
	refcount: The reference count of the entry. At 0 the entry will be deleted
	list: The list node in the hashtable

*/
struct dt_pid_entry
{
	pid_t pid;
	atomic_t refcount;
	struct hlist_node list;
};

/*
	Creates a list of PIDs from a space-separated string,
	it's used to parse the store for add_pid and remove_pid

	buf: The string to read from
	size: The size of the string
	pid_size: Out variable that will contain the number of PIDs

	return: The PID list, you **MUST** kfree the return value
*/
static pid_t* create_pid_list(const char* buf, size_t size, size_t* pid_size)
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
static ssize_t dt_pid_add_pid_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	pid_t* to_add;
	size_t n;
	size_t i;

	to_add = create_pid_list(buf, size, &n);
	if(unlikely(!to_add))
	{
		printk(DT_PRINTK_WARN "Could not add PIDs");
		return -EINVAL;
	}

	for(i = 0; i < n; i++)
	{
		dt_pid_ref(to_add[i]);
	}
	kfree(to_add);
	return size;
}

// Store function for the remove_pid attribute, removes a PID from the table of PIDs if it's there
static ssize_t dt_pid_remove_pid_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	pid_t* to_remove;
	size_t n;
	size_t i;

	to_remove = create_pid_list(buf, size, &n);
	if(unlikely(!to_remove))
	{
		printk(DT_PRINTK_WARN "Could not remove PIDs");
		return -EINVAL;
	}

	for(i = 0; i < n; i++)
	{
		dt_pid_unref(to_remove[i]);
	}

	kfree(to_remove);
	return size;
}

// Show function for the list_pid attribute
static ssize_t dt_pid_list_pid_show(struct kobject* obj, struct kobj_attribute* attr, char* buf)
{
	size_t written = 0;
	struct dt_pid_entry* entry;
	int bkt;

	read_lock(&dt_pid_table_lock);
	hash_for_each(dt_pid_table, bkt, entry, list)
	{
		written += snprintf(buf + written, PAGE_SIZE - written, "%d ", entry->pid);
		if(written >= PAGE_SIZE)
			break;
	}
	read_unlock(&dt_pid_table_lock);

	return written;
}

struct kobj_attribute dt_pid_add_pid_attr = __ATTR(add_pid, 0220, NULL, dt_pid_add_pid_store);
struct kobj_attribute dt_pid_remove_pid_attr = __ATTR(remove_pid, 0220, NULL, dt_pid_remove_pid_store);
struct kobj_attribute dt_pid_list_pid_attr = __ATTR(list_pid, 0444, dt_pid_list_pid_show, NULL);

int dt_pid_init(void)
{
	rwlock_init(&dt_pid_table_lock);
	hash_init(dt_pid_table);
	return 0;
}

void dt_pid_exit(void)
{
	int bkt;
	struct dt_pid_entry* entry;
	struct hlist_node* tmp;
	hash_for_each_safe(dt_pid_table, bkt, tmp, entry, list)
	{
		hash_del(&entry->list);
		kfree(entry);
	}
}

static struct dt_pid_entry* __dt_pid_get_entry(pid_t pid)
{
	struct dt_pid_entry* entry;
	
	hash_for_each_possible(dt_pid_table, entry, list, pid)
	{
		if(entry->pid == pid)
			return entry;
	}
	return NULL;
}

static inline int __dt_pid_ref_entry(struct dt_pid_entry* entry)
{
	atomic_inc(&entry->refcount);
	return atomic_read(&entry->refcount);
}

static inline int __dt_pid_unref_entry(struct dt_pid_entry* entry)
{
	atomic_dec(&entry->refcount);
	if(atomic_read(&entry->refcount) == 0)
	{
		hash_del(&entry->list);
		kfree(entry);
		return 0;
	}
	return atomic_read(&entry->refcount);
}

static struct dt_pid_entry* __dt_pid_add_entry(pid_t pid)
{
	struct dt_pid_entry* entry;

	entry = __dt_pid_get_entry(pid);
	if(entry)
	{
		__dt_pid_ref_entry(entry);
	}
	else
	{
		entry = kmalloc(sizeof(struct dt_pid_entry), GFP_KERNEL);
		entry->pid = pid;
		atomic_set(&entry->refcount, 1);
		hash_add(dt_pid_table, &entry->list, entry->pid);
	}
	return entry;
}

int dt_pid_ref(pid_t pid)
{
	struct dt_pid_entry* entry;
	int refcount = 0;

	read_lock(&dt_pid_table_lock);
	entry = __dt_pid_get_entry(pid);
	if(entry)
	{
		refcount = __dt_pid_ref_entry(entry);
	}
	read_unlock(&dt_pid_table_lock);

	if(!entry)
	{
		write_lock(&dt_pid_table_lock);
		entry = __dt_pid_add_entry(pid);
		refcount = atomic_read(&entry->refcount);
		write_unlock(&dt_pid_table_lock);
	}

	return refcount;
}

int dt_pid_unref(pid_t pid)
{
	struct dt_pid_entry* entry;
	int refcount;

	write_lock(&dt_pid_table_lock);
	entry = __dt_pid_get_entry(pid);
	if(entry)
	{
		refcount = __dt_pid_unref_entry(entry);
	}
	write_unlock(&dt_pid_table_lock);

	return refcount;
}

int dt_pid_refcount(pid_t pid)
{
	struct dt_pid_entry* entry;
	int refcount = 0;

	read_lock(&dt_pid_table_lock);
	entry = __dt_pid_get_entry(pid);
	if(entry)
		refcount = atomic_read(&entry->refcount);
	read_unlock(&dt_pid_table_lock);

	return refcount;
}