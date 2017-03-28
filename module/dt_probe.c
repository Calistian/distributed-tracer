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
#ifndef DT_PROBE_MARK_TABLE_SIZE
#define DT_PROBE_MARK_TABLE_SIZE 8
#endif

#define DT_PTR_SIZE (sizeof(void*))

#define DT_BAD_CHECKSUM 0xffff

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
	bool marked;
	struct hlist_node list;
};

static struct kmem_cache* dt_probe_mark_alloc;
static DEFINE_HASHTABLE(dt_probe_mark_table, DT_PROBE_MARK_TABLE_SIZE);
static spinlock_t dt_probe_mark_table_lock;
struct dt_probe_mark_entry
{
	struct sk_buff* skb;
	struct hlist_node list;
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
	struct tcphdr* th;
	struct dt_probe_mark_entry* entry;
	
	th = tcp_hdr(skb);

	if(th->psh && (th->res1 & (1 << 3)))
	{
		// Re-flip the first reserved bit and restore checksum
		th->res1 &= ~(1 << 3);
		th->check ^= (1 << 3);

		entry = kmem_cache_alloc(dt_probe_mark_alloc, GFP_KERNEL);
		entry->skb = skb;

		spin_lock(&dt_probe_mark_table_lock);
		hash_add(dt_probe_mark_table, &entry->list, (uint64_t)skb);
		spin_unlock(&dt_probe_mark_table_lock);

	}

	jprobe_return();
	return 0;
}

static int tcp_recvmsg_jprobe_fn(struct sock* sk, struct msghdr* msg, size_t len, int nonblock, int flags, int* addr_len)
{
	struct dt_probe_tcp_recvmsg_cache_entry* entry;

	entry = kmem_cache_alloc(dt_probe_tcp_recvmsg_cache_alloc, GFP_KERNEL);
	entry->pid = current->pid;
	entry->marked = false;

	spin_lock(&dt_probe_tcp_recvmsg_cache_table_lock);
	hash_add(dt_probe_tcp_recvmsg_cache_table, &entry->list, entry->pid);
	spin_unlock(&dt_probe_tcp_recvmsg_cache_table_lock);

	jprobe_return();
	return 0;
}

static int tcp_recvmsg_kretprobe_fn(struct kretprobe_instance* inst, struct pt_regs* regs)
{
	struct dt_probe_tcp_recvmsg_cache_entry* entry;
	struct hlist_node* tmp;
	pid_t curpid = current->pid;

	spin_lock(&dt_probe_tcp_recvmsg_cache_table_lock);
	hash_for_each_possible_safe(dt_probe_tcp_recvmsg_cache_table, entry, tmp, list, curpid)
	{
		if(entry->pid == curpid)
		{
			if(entry->marked)
				printk(DT_PRINTK_INFO "Found marked packet for %d", curpid);
			hash_del(&entry->list);
			kmem_cache_free(dt_probe_tcp_recvmsg_cache_alloc, entry);
		}
	}
	spin_unlock(&dt_probe_tcp_recvmsg_cache_table_lock);
	return 0;
}

static int skb_copy_datagram_iter_jprobe_fn(const struct sk_buff* skb, int offset, struct iov_iter* to, int len)
{
	struct dt_probe_tcp_recvmsg_cache_entry* cache_entry;

	struct dt_probe_mark_entry* mark_entry;
	struct hlist_node* mark_tmp;

	pid_t curpid = current->pid;

	spin_lock(&dt_probe_mark_table_lock);
	hash_for_each_possible_safe(dt_probe_mark_table, mark_entry, mark_tmp, list, (uint64_t)skb)
	{
		if(unlikely(mark_entry->skb == skb))
		{
			spin_lock(&dt_probe_tcp_recvmsg_cache_table_lock);
			hash_for_each_possible(dt_probe_tcp_recvmsg_cache_table, cache_entry, list, curpid)
			{
				if(cache_entry->pid == curpid)
				{
					cache_entry->marked = true;
				}
			}
			spin_unlock(&dt_probe_tcp_recvmsg_cache_table_lock);
			hash_del(&mark_entry->list);
			kmem_cache_free(dt_probe_mark_alloc, mark_entry);
		}
	}
	spin_unlock(&dt_probe_mark_table_lock);

	jprobe_return();
	return 0;
}


DT_DECL_JPROBE(ip_queue_xmit);
DT_DECL_JPROBE(tcp_v4_do_rcv);
DT_DECL_JPROBE(tcp_recvmsg);
DT_DECL_KRETPROBE(tcp_recvmsg);
DT_DECL_JPROBE(skb_copy_datagram_iter);

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
		err = register_jprobe(&skb_copy_datagram_iter_jprobe);
		if(err < 0)
		{
			printk(DT_PRINTK_ERR "Failed to register skb_copy_datagram_iter jprobe");
			goto on_err;
		}
	}
	return 0;

on_err:
	unregister_jprobe(&skb_copy_datagram_iter_jprobe);
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
		unregister_jprobe(&skb_copy_datagram_iter_jprobe);
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

	spin_lock_init(&dt_probe_mark_table_lock);
	hash_init(dt_probe_mark_table);

	dt_probe_tcp_recvmsg_cache_alloc = kmem_cache_create("dt_probe_tcp_recvmsg_cache", sizeof(struct dt_probe_tcp_recvmsg_cache_entry), 0, 0, NULL);
	if(!dt_probe_tcp_recvmsg_cache_alloc)
	{
		printk(DT_PRINTK_ERR "Could not create dt_probe_tcp_recvmsg_cache_alloc");
		return -1;
	}

	dt_probe_mark_alloc = kmem_cache_create("dt_probe_mark", sizeof(struct dt_probe_mark_entry), 0, 0, NULL);
	if(!dt_probe_mark_alloc)
	{
		kmem_cache_destroy(dt_probe_tcp_recvmsg_cache_alloc);
		printk(DT_PRINTK_ERR "Could not create dt_probe_mark_alloc");
		return -1;
	}
	printk(DT_PRINTK_INFO "==================================================================");
	return 0;
}

void dt_probe_exit(void)
{
	struct dt_probe_tcp_recvmsg_cache_entry* cache_entry;
	struct dt_probe_mark_entry* mark_entry;
	struct hlist_node* tmp;
	int bkt;

	dt_probe_unregister();

	// In case of memory leak, should not happen :)
	hash_for_each_safe(dt_probe_tcp_recvmsg_cache_table, bkt, tmp, cache_entry, list)
	{
		printk(DT_PRINTK_WARN "Memory leak detected for dt_probe_tcp_recvmsg_cache_table");
		hash_del(&cache_entry->list);
		kmem_cache_free(dt_probe_tcp_recvmsg_cache_alloc, cache_entry);
	}

	// In case of memory leak, should not happen :)
	hash_for_each_safe(dt_probe_mark_table, bkt, tmp, mark_entry, list)
	{
		printk(DT_PRINTK_WARN "Memory leak detected for dt_probe_mark_table");
		hash_del(&mark_entry->list);
		kmem_cache_free(dt_probe_mark_alloc, mark_entry);
	}

	kmem_cache_destroy(dt_probe_tcp_recvmsg_cache_alloc);
	kmem_cache_destroy(dt_probe_mark_alloc);
}