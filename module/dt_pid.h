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
	Checks if a PID is in the PID list

	pid: The PID to check for

	return: Whether the PID is in the list
*/
bool dt_pid_has_pid(pid_t pid);

#endif