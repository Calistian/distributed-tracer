#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/pid.h>

#include <net/ip.h>
#include <net/tcp.h>

#include "dt.h"
#include "dt_probe.h"
#include "dt_pid.h"

#ifndef DT_PROBE_SK_BUFF_TABLE_SIZE
#define DT_PROBE_SK_BUFF_TABLE_SIZE 8
#endif

/*
	Creates a jprobe from the probed function.
	The jprobe will be called <fn>_jprobe and the entry function must be called <fn>_jprobe_fn
*/
#define DT_DECL_JPROBE(fn) static struct jprobe fn##_jprobe = {\
	.entry = fn##_jprobe_fn,\
	.kp = {\
		.symbol_name = #fn\
	}\
}

#define DT_DECL_KRETPROBE(fn) static struct kretprobe fn##_kretprobe = {\
	.handler = fn##_kretprobe_fn,\
	.kp = {\
		.symbol_name = #fn\
	}\
}

struct dt_probe_cache_entry
{
	struct sock* sk;
	struct msghdr* msg;
	pid_t pid;
	struct hlist_node list;
};

static int ip_queue_xmit_jprobe_fn(struct sock* sk, struct sk_buff* skb, struct flowi* fl)
{
	struct tcphdr* th;
	struct task_struct* task = current;

	// Do something only if the calling PID is being watched and the packet is TCP.
	if(sk->sk_type == SOCK_STREAM && task && dt_pid_has_pid(task->pid))
	{
		th = (struct tcphdr*)skb->data;
		// Flip the first reserved bit in the TCP header and update checksum accordingly
		th->res1 |= (1 << 3);
		th->check ^= (1 << 3);
	}

	jprobe_return();
	return 0;
}

static int tcp_v4_do_rcv_jprobe_fn(struct sock* sk, struct sk_buff* skb)
{
	jprobe_return();
	return 0;
}

DT_DECL_JPROBE(ip_queue_xmit);
DT_DECL_JPROBE(tcp_v4_do_rcv);

static atomic_t registered = ATOMIC_INIT(0);

static int dt_probe_register(void)
{
	int err;
	int value = 1;

	value = atomic_xchg(&registered, value);
	if(value == 0)
	{
		err = register_jprobe(&ip_queue_xmit_jprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register ip_queue_xmit jprobe");
			atomic_set(&registered, 0);
			return err;
		}
		err = register_jprobe(&tcp_v4_do_rcv_jprobe);
		if(err < 0)
		{
			unregister_jprobe(&ip_queue_xmit_jprobe);
			printk(DT_PRINTK_ERR "Failed to register tcp_v4_do_rcv jprobe");
			atomic_set(&registered, 0);
			return err;
		}
	}
	return 0;
}

static int dt_probe_unregister(void)
{
	if(atomic_read(&registered) == 1)
	{
		unregister_jprobe(&tcp_v4_do_rcv_jprobe);
		unregister_jprobe(&ip_queue_xmit_jprobe);
		atomic_set(&registered, 0);
	}

	return 0;
}

static ssize_t dt_probe_probe_show(struct kobject* obj, struct kobj_attribute* attr, char* buf)
{
	if(atomic_read(&registered))
		*buf = '1';
	else
		*buf = '0';
	return 1;
}

static ssize_t dt_probe_probe_store(struct kobject* obj, struct kobj_attribute* attr, const char* buf, size_t size)
{
	int err = 0;

	if(size < 1)
		return -EINVAL;
	if(*buf == '1')
		err = dt_probe_register();
	else if(*buf == '0')
		err = dt_probe_unregister();
	else
		err = -EINVAL;
	if(err < 0)
		return err;

	return size;
}

struct kobj_attribute dt_probe_probe_attr = __ATTR(probe, 0664, dt_probe_probe_show, dt_probe_probe_store);

int dt_probe_init(void)
{

	printk(DT_PRINTK_WARN "==================================================================");
	return 0;
}

void dt_probe_exit(void)
{
	dt_probe_unregister();
}