修改的文件是net/sched/sch_red.c (为了方便对比我把源文件拷贝过来了一份可以看）
修改的内容为：
1.函数static struct sk_buff *red_dequeue(struct Qdisc *sch)
增加了初始化skb的内容，skb初始化为队列第一个格子里的内容。
2.函数int liner_search_with_max_depth(int s,int depth)    //线性查找，并设置最大队列深度
更改了查找长度的逻辑，具体请见注释。
3.int liner_search_with_probability(int s,int depth)  //线性查找，概率随着深度变小，并在depth后减小至0
更改了查找长度的逻辑，具体请见注释。






编译： make
模块加载到内核：insmod aqmplus.ko

配置aqmplus队列：
tc qdisc add dev eth0 root red limit 10002 min 100 max 200 avpkt 1 burst 1000 probability 1

limit参数表示AQM+队列的最大长度 
limit参数的最后1位代表带宽，1表示10M，2表示100M，3表示1000M

min参数表示AQM+队列的搜索算法 要除100，因为tc工具会初步检测参数合法性，要一个较大的值
max参数表示AQM+队列的向下搜索最大深度

卸载：
tc qdisc del dev eth0 root
rmmod aqmplus.ko


