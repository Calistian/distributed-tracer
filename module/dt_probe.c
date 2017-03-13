#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/pid.h>

#include <net/ip.h>
#include <net/tcp.h>

#include "dt.h"
#include "dt_probe.h"
#include "dt_pid.h"

#ifndef DT_PROBE_TCP_RECVMSG_CACHE_TABLE_SIZE
#define DT_PROBE_TCP_RECVMSG_CACHE_TABLE_SIZE 8
#endif

#define DT_PTR_SIZE (sizeof(void*))

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

static struct kmem_cache* dt_probe_tcp_recvmsg_cache_alloc;
static DEFINE_HASHTABLE(dt_probe_tcp_recvmsg_cache_table, DT_PROBE_TCP_RECVMSG_CACHE_TABLE_SIZE);
static spinlock_t dt_probe_tcp_recvmsg_cache_table_lock;
struct dt_probe_tcp_recvmsg_cache_entry
{
	pid_t pid;
	struct iov_iter iter;
	struct hlist_node list;
};

static struct kmem_cache* dt_probe_tcp_mark_alloc;
struct dt_probe_tcp_mark
{
	char old[DT_PTR_SIZE];
	bool marked;
};

static int ip_queue_xmit_jprobe_fn(struct sock* sk, struct sk_buff* skb, struct flowi* fl)
{
	struct tcphdr* th;
	struct task_struct* task = current;

	// Do something only if the calling PID is being watched and the packet is TCP. Only mark data packets (PSH)
	if(sk->sk_type == SOCK_STREAM && dt_pid_has_pid(task->pid))
	{
		th = tcp_hdr(skb);
		if(th->psh)
		{
			// Flip the first reserved bit in the TCP header and update checksum accordingly
			th->res1 |= (1 << 3);
			th->check ^= (1 << 3);
		}
	}

	jprobe_return();
	return 0;
}

static int tcp_v4_do_rcv_jprobe_fn(struct sock* sk, struct sk_buff* skb)
{
	struct iphdr* ih;
	struct tcphdr* th;
	char* data;
	size_t data_len;
	struct dt_probe_tcp_mark* mark;
	int i;

	ih = ip_hdr(skb);
	th = tcp_hdr(skb);
	data = (char*)th + tcp_hdrlen(skb);
	data_len = be16_to_cpu(ih->tot_len) - (size_t)(data - (char*)ih);

	// Only check data packets
	if(!th->psh)
		jprobe_return();

	if(data_len < DT_PTR_SIZE)
	{
		if(th->res1 & (1 << 3))
		{
			printk(DT_PRINTK_ERR "Could not trace marked packet because the content is too small (%lu)", data_len);
		}
	}
	else
	{
		jprobe_return(); // Don't go there yet, it breaks stuff

		// TODO Modify sk_buff data and checksum
		mark = kmem_cache_alloc(dt_probe_tcp_mark_alloc, GFP_KERNEL);
		memcpy(mark->old, data, DT_PTR_SIZE);
		mark->marked = (th->res1 & (1 << 3)) != 0;
		// Copies the address of the mark into the data
		*(void**)data = mark;

		// Update checksum
		for(i = 0; i < 4; i++)
			th->check ^= *((uint16_t*)mark->old + i) ^ cpu_to_be16(*((uint16_t*)data + i));
	}

	jprobe_return();
	return 0;
}

static int tcp_recvmsg_jprobe_fn(struct sock* sk, struct msghdr* msg, size_t len, int nonblock, int flags, int* addr_len)
{
	struct task_struct* cur = current;
	struct dt_probe_tcp_recvmsg_cache_entry* entry;

	entry = kmem_cache_alloc(dt_probe_tcp_recvmsg_cache_alloc, GFP_KERNEL);

	entry->pid = cur->pid;
	memcpy(&entry->iter, &msg->msg_iter, sizeof(struct iov_iter));

	spin_lock(&dt_probe_tcp_recvmsg_cache_table_lock);
	hash_add(dt_probe_tcp_recvmsg_cache_table, &entry->list, entry->pid);
	spin_unlock(&dt_probe_tcp_recvmsg_cache_table_lock);

	jprobe_return();
	return 0;
}

static int tcp_recvmsg_kretprobe_fn(struct kretprobe_instance* inst, struct pt_regs* regs)
{
	struct task_struct* cur = current;
	struct dt_probe_tcp_recvmsg_cache_entry* entry;
	struct hlist_node* tmp;
	bool found = false;

	spin_lock(&dt_probe_tcp_recvmsg_cache_table_lock);
	hash_for_each_possible_safe(dt_probe_tcp_recvmsg_cache_table, entry, tmp, list, cur->pid)
	{
		if(entry->pid == cur->pid)
		{
			hash_del(&entry->list);
			found = true;
			break;
		}
	}
	spin_unlock(&dt_probe_tcp_recvmsg_cache_table_lock);

	if(likely(found))
	{
		kmem_cache_free(dt_probe_tcp_recvmsg_cache_alloc, entry);
		return 0; // Don't go there yet, it breaks stuff

		// TODO Check modified data and restore old data
		
	}

	return 0;
}

DT_DECL_JPROBE(ip_queue_xmit);
DT_DECL_JPROBE(tcp_v4_do_rcv);
DT_DECL_JPROBE(tcp_recvmsg);
DT_DECL_KRETPROBE(tcp_recvmsg);

static atomic_t registered = ATOMIC_INIT(0);

static int dt_probe_register(void)
{
	int err = 0;
	int value = 1;

	value = atomic_xchg(&registered, value);
	if(value == 0)
	{
		err = register_jprobe(&ip_queue_xmit_jprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register ip_queue_xmit jprobe");
			goto on_err;
		}
		err = register_jprobe(&tcp_v4_do_rcv_jprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register tcp_v4_do_rcv jprobe");
			goto on_err;
		}
		err = register_jprobe(&tcp_recvmsg_jprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register tcp_recvmsg jprobe");
			goto on_err;
		}
		err = register_kretprobe(&tcp_recvmsg_kretprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register tcp_recvmsg kretprobe");
			goto on_err;
		}
	}
	return 0;

on_err:
	unregister_kretprobe(&tcp_recvmsg_kretprobe);
	unregister_jprobe(&tcp_recvmsg_jprobe);
	unregister_jprobe(&tcp_v4_do_rcv_jprobe);
	unregister_jprobe(&ip_queue_xmit_jprobe);
	atomic_set(&registered, 0);
	return err;
}

static int dt_probe_unregister(void)
{
	if(atomic_read(&registered) == 1)
	{
		unregister_kretprobe(&tcp_recvmsg_kretprobe);
		unregister_jprobe(&tcp_recvmsg_jprobe);
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
	spin_lock_init(&dt_probe_tcp_recvmsg_cache_table_lock);
	hash_init(dt_probe_tcp_recvmsg_cache_table);
	dt_probe_tcp_recvmsg_cache_alloc = kmem_cache_create("dt_probe_tcp_recvmsg_cache", sizeof(struct dt_probe_tcp_recvmsg_cache_entry), 0, 0, NULL);
	if(!dt_probe_tcp_recvmsg_cache_alloc)
	{
		printk(DT_PRINTK_ERR "Could not create dt_probe_tcp_recvmsg_cache_alloc");
		return -1;
	}
	dt_probe_tcp_mark_alloc = kmem_cache_create("dt_probe_tcp_mark_alloc", sizeof(struct dt_probe_tcp_mark), 0, 0, NULL);
	if(!dt_probe_tcp_mark_alloc)
	{
		kmem_cache_destroy(dt_probe_tcp_recvmsg_cache_alloc);
		printk(DT_PRINTK_ERR "Could not create dt_probe_tcp_mark_alloc");
		return -1;
	}
	printk(DT_PRINTK_INFO "==================================================================");
	return 0;
}

void dt_probe_exit(void)
{
	struct dt_probe_tcp_recvmsg_cache_entry* entry;
	struct hlist_node* tmp;
	int bkt;

	dt_probe_unregister();

	// In case of memory leak, should not happen :)
	hash_for_each_safe(dt_probe_tcp_recvmsg_cache_table, bkt, tmp, entry, list)
	{
		printk(DT_PRINTK_WARN "Memory leak detected for dt_probe_tcp_recvmsg_cache_table");
		hash_del(&entry->list);
		kmem_cache_free(dt_probe_tcp_recvmsg_cache_alloc, entry);
	}
	kmem_cache_destroy(dt_probe_tcp_recvmsg_cache_alloc);

	kmem_cache_destroy(dt_probe_tcp_mark_alloc);
}