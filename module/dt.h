#ifndef DT_H_
#define DT_H_

#include <linux/kernel.h>

// Module name for logging
#ifndef DT_MODULE_NAME
#define DT_MODULE_NAME "distributed-tracer"
#endif

// Utility printk prefix for logging with the module name
#define DT_PRINTK_INFO KERN_INFO DT_MODULE_NAME ": "
#define DT_PRINTK_WARN KERN_WARNING DT_MODULE_NAME ": "
#define DT_PRINTK_ERR KERN_ERR DT_MODULE_NAME ": "

#endif