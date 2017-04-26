#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/module.h>  
#include <linux/init.h>  
#include <linux/types.h>  
#include <linux/string.h>  
#include <asm/uaccess.h>  
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/ip.h>  
#include <linux/tcp.h> 
#include <linux/skbuff.h>


//hook函数
unsigned int my_hookfn(unsigned int hooknum,  
    struct sk_buff *skb,  
    const struct net_device *in,  
    const struct net_device *out,  
    int (*okfn)(struct sk_buff *)){

    struct iphdr     *ip_header_ = NULL;
    struct tcphdr    *tcp_header_ = NULL;

    ip_header_ = ip_hdr(skb);

    if (ip_header_->protocol == IPPROTO_TCP)
    {
    	tcp_header_ = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl * 4);

    	if (htons(tcp_header_->dest) != 80)
        	return NF_ACCEPT;
    }
    

    return NF_DROP;
}

//hook参数
static struct nf_hook_ops nfho = {  
    .hook = my_hookfn,  
    .pf = PF_INET,  
    .hooknum = NF_INET_LOCAL_IN,  
    .priority = NF_IP_PRI_FIRST,  
    .owner = THIS_MODULE,  
}; 

//hook初始化
static int __init sknf_init(void)  
{  
    if (nf_register_hook(&nfho)) {  
        printk(KERN_ERR"nf_register_hook() failed\n");  
        return -1;  
    }  
    return 0;  
} 

//hook退出  
static void __exit sknf_exit(void)  
{  
    nf_unregister_hook(&nfho);  
}  
  
module_init(sknf_init);  
module_exit(sknf_exit);  
MODULE_AUTHOR("wangjinwen");  
MODULE_LICENSE("GPL");  