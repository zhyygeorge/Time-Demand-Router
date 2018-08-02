/*
 * net/sched/sch_red.c	Random Early Detection queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 * J Hadi Salim 980914:	computation fixes
 * Alexey Makarenko <makar@phoenix.kharkov.ua> 990814: qave on idle link was calculated incorrectly.
 * J Hadi Salim 980816:  ECN support
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/red.h>


/*	Parameters, settable by user:
	-----------------------------

	limit		- bytes (must be > qth_max + burst)

	Hard limit on queue length, should be chosen >qth_max
	to allow packet bursts. This parameter does not
	affect the algorithms behaviour and can be chosen
	arbitrarily high (well, less than ram size)
	Really, this limit will never be reached
	if RED works correctly
 */

#define MAXLEN 100000
#define OCCUPIED 1
#define VIRTUAL_OCCUPIED 2
#define SIDE_MOUNT 4

/********************************add my code********************************/
//declaration
int qHead = 0;              //AQM+使用数组模拟循环列表，qHead指向队首
int qLength = MAXLEN;       //队列的最大长度
int search_method = 1;      //查询优化策略
int max_depth = 10;         //优化策略使用的最大深度
int bandwidth = 10;		//初始带宽
int packDelay;		//包时延，具体定义在red_change


//格子信息
struct bucket_info{		
        struct sk_buff *first_skb; //第一个数据包
        struct sk_buff *last_skb;  //最后一个数据包（侧挂）
        int oci;		//虚占用
        char flag;	//占用
};
struct bucket_info bis[MAXLEN];

/********************************add my code********************************/
struct red_sched_data {
	u32			limit;		/* HARD maximal queue length */
	unsigned char		flags;
	struct timer_list	adapt_timer;
	struct red_parms	parms;
	struct red_vars		vars;
	struct red_stats	stats;
	struct Qdisc		*qdisc;
};

static inline int red_use_ecn(struct red_sched_data *q)
{
	return q->flags & TC_RED_ECN;
}

static inline int red_use_harddrop(struct red_sched_data *q)
{
	return q->flags & TC_RED_HARDDROP;
}



/********************************add my code********************************/
int bi_empty(struct bucket_info bi)
{
        if( !((bi.flag & OCCUPIED) || 
                (bi.flag & VIRTUAL_OCCUPIED)) ){    //未占用且未虚占用
                return 1;
        }
	return 0;
}

int liner_search(int s)                             //线性查找到队列首部
{
	int i,il;
	for(i = s;i >= qHead;i--)
	{
		il = i % qLength;
		if(bi_empty( bis[il] )){          
			return il;
                }
	}
	return -1;
}

int liner_search_with_max_depth(int s,int depth)    //线性查找，并设置最大队列深度
{
	int i,il;
	for(i = s; i >= qHead; i--)
	{
		if(s - i > depth)	//changed by zhyy , origin is if(s- qHead)>depth
			return -1;
		il = i % qLength;
		if(bi_empty( bis[il] ))
		{         
			return il;
                }
	}
	return -1;
}

int liner_search_with_probability(int s,int depth)  //线性查找，概率随着深度变小，并在depth后减小至0
{
	int i,il,probability,rand;
	for(i = s;i >= qHead;i--)
	{
		if(s - i > depth)	//changed by zhyy , origin is if(s- qHead)>depth
			return -1;
                //概率从深度为0，到深度未depth线性递减直至depth之后概率减为0,概率递减模型？
		probability = qHead - (s - i);  //probability 从qHead减小至0
		get_random_bytes(&rand,sizeof(int));
		rand = rand < 0 ? -rand : rand;
		rand = rand % qHead;                // 0 <= rand < qHead
		il = i % qLength;
		if(bi_empty( bis[il] ) && probability >= rand){      //找到空位，且概率允许  
                        return il;
		}
	}
	return -1;
}


/*
 * 参数传递方式
 * min表示查询方式
 * max表示查询深度
 */


static int red_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	//int i;
	int d,s,sl;         //demand,slot,slot_looped
	int ret = NET_XMIT_CN;
	struct red_sched_data *q = qdisc_priv(sch);

	d = 50;//time demand initializeed
	if(skb->data[13] == 0)
	{			//IP 报文
		struct iphdr *iph = (struct iphdr *)(skb ->data + 14);
		if(iph ->ihl * 4 -sizeof(struct iphdr) > 0)
		{               //有ip option字段
			unsigned char *ipops = skb->data + 34;             //找到ip option的位置
			d = ntohl(*(u32 *)(ipops + 4));                    //获取报文内记录的时延需求，以微秒为单位
			if(packDelay == 0)
				packDelay = 1000;
			d = d / packDelay;                                 //除以每个报文的传输时间，获得位置
                }
	}
      //d = 10;
	s = d + qHead;                           //循环队列中位置slot
	sl = s % qLength;

	if(bi_empty(bis[sl]))
	{                   //未被占用
		bis[sl].flag |= OCCUPIED;
		bis[sl].first_skb = skb;
		bis[sl].last_skb = skb;
		ret = NET_XMIT_SUCCESS;
	}
	else
	{                                    //虚占用前面的
		int pos = -1;		    //查找空位是否成功的标志位

		if(search_method == 1)
			pos = liner_search(s);

		else if(search_method == 2)
			pos = liner_search_with_max_depth(s,max_depth);

		else if(search_method == 3)
			pos = liner_search_with_probability(s,max_depth);
		else
		{
                    printk("unsupported search method\n");
		}
		if(pos != -1)
		{                   //查找到空位
			bis[pos].flag |= VIRTUAL_OCCUPIED;
			bis[pos].oci = sl;           //虚占用真实报文
			bis[sl].last_skb ->next = skb;
			bis[sl].last_skb  = skb;
			bis[sl].flag |= OCCUPIED;    //侧挂和占用同用OCCUPIED表示
			ret = NET_XMIT_SUCCESS;
		}
	}


//        char str[MAXLEN];                           //debug 信息 
//        for(i = 0;i <= 50;i++){
//               int il = (i + qHead) % qLength;
//               str[i] = bis[il].flag + '0';
//       }
//        str[51] = '\0';
//        printk("%s\n",str);
//       

	if(ret == NET_XMIT_SUCCESS){
		sch->q.qlen++;
	}else{                                     //丢包
		q->stats.pdrop++;
		sch->qstats.drops++;
		qdisc_drop(skb, sch, to_free);
	}

	return ret;
}


static struct sk_buff *red_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	//struct red_sched_data *q = qdisc_priv(sch);
    	int i,j;
	skb = bis[0].first_skb;
    	for(i = qHead;i < qHead + qLength;i++)
	{
		int il = i % qLength;
		if(bis[il].flag & OCCUPIED)
		{
			skb = bis[il].first_skb;
			if(skb == NULL)
				return NULL;
			bis[il].first_skb = skb ->next;

			for(j = i - 1;j >= qHead;j--)
			{          //查找是否有虚占用
				int jl = j % qLength;
				if((bis[jl].flag & VIRTUAL_OCCUPIED) &&  bis[jl].oci == il)
				{      //解除虚占用 
					bis[jl].flag &= ~VIRTUAL_OCCUPIED;
				}
			}

                   if(skb ->next == NULL)
			{             //解除占用         
                            bis[il].flag &= ~OCCUPIED;
                        }

                   qHead = (qHead + 1) % qLength;
                   break;
		}
	}

	if(skb)
	{
            //qdisc_bstats_update(sch,skb);
            sch->q.qlen--;
	}

	return skb;
}

static struct sk_buff *red_peek(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	return child->ops->peek(child);
}

static void red_reset(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	sch->qstats.backlog = 0;
	sch->q.qlen = 0;
	red_restart(&q->vars);
}

static void red_destroy(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);

	del_timer_sync(&q->adapt_timer);
	qdisc_destroy(q->qdisc);
}

static const struct nla_policy red_policy[TCA_RED_MAX + 1] = {
	[TCA_RED_PARMS]	= { .len = sizeof(struct tc_red_qopt) },
	[TCA_RED_STAB]	= { .len = RED_STAB_SIZE },
	[TCA_RED_MAX_P] = { .type = NLA_U32 },
};

static int red_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_RED_MAX + 1];
	struct tc_red_qopt *ctl;
	struct Qdisc *child = NULL;
	int err;
	u32 max_P;
/*******************************add my code******************************/
	int i;	
	char * search_method_str[3] = {"liner search ","search with maximum depth","search with probability"};
/*******************************add my code******************************/
	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_RED_MAX, opt, red_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_RED_PARMS] == NULL ||
	    tb[TCA_RED_STAB] == NULL)
		return -EINVAL;

 	max_P = tb[TCA_RED_MAX_P] ? nla_get_u32(tb[TCA_RED_MAX_P]) : 0;

	ctl = nla_data(tb[TCA_RED_PARMS]);

	if (ctl->limit > 0) {
		child = fifo_create_dflt(sch, &bfifo_qdisc_ops, ctl->limit);
		if (IS_ERR(child))
			return PTR_ERR(child);
	}

	if (child != &noop_qdisc)
		qdisc_hash_add(child, true);
	sch_tree_lock(sch);
	q->flags = ctl->flags;
	q->limit = ctl->limit;
	if (child) {
		qdisc_tree_reduce_backlog(q->qdisc, q->qdisc->q.qlen,
					  q->qdisc->qstats.backlog);
		qdisc_destroy(q->qdisc);
		q->qdisc = child;
	}

	red_set_parms(&q->parms,
		      ctl->qth_min, ctl->qth_max, ctl->Wlog,
		      ctl->Plog, ctl->Scell_log,
		      nla_data(tb[TCA_RED_STAB]),
		      max_P);
	red_set_vars(&q->vars);

	del_timer(&q->adapt_timer);
	if (ctl->flags & TC_RED_ADAPTATIVE)
		mod_timer(&q->adapt_timer, jiffies + HZ/2);

	if (!q->qdisc->q.qlen)
		red_start_of_idle_period(&q->vars);

	sch_tree_unlock(sch);

    //利用RED队列的配置参数获取aqmplus队列的关键参数，搜索算法，搜索深度，队列最大深度
    //网卡带宽用 limit的最后一位表示，1 : 10M ,2 : 100M,3 : 1000M ...
	//char * search_method_str[3] = {"liner search ","search with maximum depth","search with probability"};
	search_method = (q ->parms.qth_min >> q ->parms.Wlog) / 100;
	max_depth = q ->parms.qth_max >> q ->parms.Wlog;
	qLength = q ->limit;

    //估算每个报文的传输时间，现在为写死
	for(i = 1;i < q ->limit % 10;i++)
		bandwidth *= 10;
	packDelay = 1500 * 8 / bandwidth;        //单位 : 微秒

    //输出aqmplus获得的关键参数
	printk("%s: installed, max depth: %d, packet delay: %d\n",search_method_str[search_method - 1],max_depth,packDelay);

	return 0;
}

static inline void red_adaptative_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct red_sched_data *q = qdisc_priv(sch);
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	red_adaptative_algo(&q->parms, &q->vars);
	mod_timer(&q->adapt_timer, jiffies + HZ/2);
	spin_unlock(root_lock);
}

static int red_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct red_sched_data *q = qdisc_priv(sch);


	q->qdisc = &noop_qdisc;
	setup_timer(&q->adapt_timer, red_adaptative_timer, (unsigned long)sch);
	return red_change(sch, opt);
}

static int red_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	struct tc_red_qopt opt = {
		.limit		= q->limit,
		.flags		= q->flags,
		.qth_min	= q->parms.qth_min >> q->parms.Wlog,
		.qth_max	= q->parms.qth_max >> q->parms.Wlog,
		.Wlog		= q->parms.Wlog,
		.Plog		= q->parms.Plog,
		.Scell_log	= q->parms.Scell_log,
	};

	sch->qstats.backlog = q->qdisc->qstats.backlog;
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	if (nla_put(skb, TCA_RED_PARMS, sizeof(opt), &opt) ||
	    nla_put_u32(skb, TCA_RED_MAX_P, q->parms.max_P))
		goto nla_put_failure;
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static int red_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct tc_red_xstats st = {
		.early	= q->stats.prob_drop + q->stats.forced_drop,
		.pdrop	= q->stats.pdrop,
		.other	= q->stats.other,
		.marked	= q->stats.prob_mark + q->stats.forced_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int red_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct red_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;
	return 0;
}

static int red_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct red_sched_data *q = qdisc_priv(sch);

	if (new == NULL)
		new = &noop_qdisc;

	*old = qdisc_replace(sch, new, &q->qdisc);
	return 0;
}

static struct Qdisc *red_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct red_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}
/*********************add my code**********************/
/*static unsigned long red_get(struct Qdisc *sch, u32 classid)//not in linux-4.14.11
{
	return 1;
}*/
static unsigned long red_find(struct Qdisc *sch, u32 classid)
{
	return 1;
}
/*
static void red_put(struct Qdisc *sch, unsigned long arg)
{
}
*/
/********************add my code**********************/
static void red_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops red_class_ops = {
	.graft	=	red_graft,
	.leaf		=	red_leaf,
/*********************add my code**********************/
	.find 	=	red_find,//fix for linux-4.14.11
//	.get		=	red_get, //not in linux-4.14.11, in linux 4.12.13
//	.put		=	red_put, //not in linux-4.14.11, in linux 4.12.13
/*********************add my code**********************/
	.walk		=	red_walk,
	.dump		=	red_dump_class,
};

static struct Qdisc_ops red_qdisc_ops __read_mostly = {
	.id		=	"red",
	.priv_size	=	sizeof(struct red_sched_data),
	.cl_ops	=	&red_class_ops,
	.enqueue	=	red_enqueue,
	.dequeue	=	red_dequeue,
	.peek		=	red_peek,
	.init		=	red_init,
	.reset	=	red_reset,
	.destroy	=	red_destroy,
	.change	=	red_change,
	.dump		=	red_dump,
	.dump_stats	=	red_dump_stats,
	.owner	=	THIS_MODULE,
};

static int __init red_module_init(void)
{
	return register_qdisc(&red_qdisc_ops);
}

static void __exit red_module_exit(void)
{
	unregister_qdisc(&red_qdisc_ops);
}

module_init(red_module_init)
module_exit(red_module_exit)

MODULE_LICENSE("GPL");
