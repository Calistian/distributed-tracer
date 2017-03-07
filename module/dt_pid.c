#include <linux/kobject.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "dt.h"
#include "dt_pid.h"

// Number of buckets for the PID hashtable
#ifndef DT_PID_TABLE_SIZE
#define DT_PID_TABLE_SIZE 4
#endif

static inline bool __dt_pid_has_pid(pid_t pid);

// Hashtable containing the PID to watch for, and also the R/W spinlock
static DEFINE_READ_MOSTLY_HASHTABLE(dt_pid_table, DT_PID_TABLE_SIZE);
static rwlock_t dt_pid_table_lock;

/*
	Entry in the PID hashtable, the key for the hashtable is pid

	pid: The pid
	list: The list node in the hashtable

*/
struct dt_pid_entry
{
	pid_t pid;
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
	struct dt_pid_entry* entry = NULL;

	to_add = create_pid_list(buf, size, &n);
	if(unlikely(!to_add))
	{
		printk(DT_PRINTK_WARN "Could not add PIDs");
		return -EINVAL;
	}

	write_lock(&dt_pid_table_lock);
	for(i = 0; i < n; i++)
	{
		// Check if PID is there
		if(likely(!__dt_pid_has_pid(to_add[i])))
		{
			entry = kmalloc(sizeof(struct dt_pid_entry), GFP_KERNEL);
			entry->pid = to_add[i];
			hash_add(dt_pid_table, &entry->list, entry->pid);
		}
	}
	write_unlock(&dt_pid_table_lock);
	kfree(to_add);
	return size;
}

// Store function for the remove_pid attribute, removes a PID from the table of PIDs if it's there
static ssize_t dt_pid_remove_pid_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	pid_t* to_remove;
	size_t n;
	size_t i;
	struct dt_pid_entry* entry;
	struct hlist_node* tmp;

	to_remove = create_pid_list(buf, size, &n);
	if(unlikely(!to_remove))
	{
		printk(DT_PRINTK_WARN "Could not remove PIDs");
		return -EINVAL;
	}

	write_lock(&dt_pid_table_lock);
	for(i = 0; i < n; i++)
	{
		hash_for_each_possible_safe(dt_pid_table, entry, tmp, list, to_remove[i])
		{
			if(entry->pid == to_remove[i])
			{
				hash_del(&entry->list);
				kfree(entry);
			}

		}
	}
	write_unlock(&dt_pid_table_lock);
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

// No-lock version of dt_pid_has_pid, use it from an already locked pid table
static inline bool __dt_pid_has_pid(pid_t pid)
{
	bool ret = false;
	struct dt_pid_entry* entry;
	hash_for_each_possible(dt_pid_table, entry, list, pid)
	{
		if(entry->pid == pid)
		{
			ret = true;
			break;
		}
	};
	return ret;
}

bool dt_pid_has_pid(pid_t pid)
{
	int ret;
	// Acquire the lock and use the non-lock version
	read_lock(&dt_pid_table_lock);
	ret = __dt_pid_has_pid(pid);
	read_unlock(&dt_pid_table_lock);
	return ret;
}