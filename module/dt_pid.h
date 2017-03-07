#ifndef DT_PID_H_
#define DT_PID_H_

#include <linux/kobject.h>

// Sysfs attribures for the pid list
extern struct kobj_attribute dt_pid_add_pid_attr;
extern struct kobj_attribute dt_pid_remove_pid_attr;
extern struct kobj_attribute dt_pid_list_pid_attr;

int dt_pid_init(void);
void dt_pid_exit(void);

/*
	Increases the refcount of a PID,
	if the PID is not in the table, it will be added with a refcount of 1.
	This function has no effect on PID activated using sysfs

	pid: The pid to reference

	return: The number of refcounts, -1 for an always activated pid
*/
int dt_pid_ref(pid_t pid);

/*
	Decreases the refcount of a PID,
	if the PID refcount reaches 0, the PID will be removed from the table.
	This function has no effect on PID activated using sysfs

	pid: The pid to unreference

	return: The number of refs, 0 if removed / not in the table, -1 if always active
*/
int dt_pid_unref(pid_t pid);

/*
	Returns the reference count of a PID.

	pid: The pid to check

	return: The number of references, 0 if not in the table, -1 if always active
*/
int dt_pid_refcount(pid_t pid);

/*
	Checks if the PID is in the table.

	pid: The pid to check

	return: true if the pid is in the table.
*/
static inline bool dt_pid_has_pid(pid_t pid)
{
	return dt_pid_refcount(pid) != 0;
}

#endif