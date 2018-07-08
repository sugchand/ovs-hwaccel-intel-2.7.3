/*
 * Copyright (c) 2018 Intel, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <errno.h>
#include <rte_config.h>

#include "netdev-dpdk-hw.h"
#include "dpif-netdev.h"
#include "netdev-provider.h"
#include "openvswitch/vlog.h"



VLOG_DEFINE_THIS_MODULE(netdev_dpdkhw_flow);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* status of flow translation in each layer */
enum xlate_status {
    FLOW_XLATE_SUCCESS = 1<<0,
    FLOW_XLATE_NOT_NEEDED = 1<<1, /* Protocol layer can be skipped */
    FLOW_XLATE_LAST = 1<<2, /* Last protocol layer, No more translation */
    FLOW_XLATE_FAILED = 1<<3
};

/*
 * flow install error strings based on the enum set
 * 'hw_switch_flow_install_err'. Updating the enum must update this string
 * array as well.
 */
char hw_switch_flow_install_err_str[][FLOW_INSTALL_ERR_STR_LEN] =
{
    /* FLOW_INSTALL_SUPPORTED */
    "hardware flow install is supported in the device",
    /* FLOW_PRESENT_IN_HW */
    "Flow already present in hardware",
    /* FLOW_PROTO_UNSUPPORTED */
    "Flow protocol is unsupported in the hardware",
    /* FLOW_MAX_LIMIT_REACHED */
    "Flow max limit for the device is reached",
    /* FLOW_IN_MULTI_HW */
    "Flow is span across more than one accelerated device",
    /* FLOW_WITH_NON_HW_PORTS */
    "Flow need non hardware accelerated ports"
};

struct flow_xlate_dic {
    enum rte_flow_item_type rte_flow_type;
    /*
     * Flow xlate function to translate specific header match into rtl format.
     * Each rte_flow_item_type, it is necessary to define a corresponding
     * xlate function in this structure. Return 0 if the flow is being translated
     * successfully and error code otherwise.
     */
    enum xlate_status (*flow_xlate)(struct match *match,
                       struct rte_flow_batch *batch,
                       const void *md);
};

static inline bool
is_rte_flow_batch_full(struct rte_flow_batch *flow_batch)
{
    if (flow_batch->used >= flow_batch->max_size) {
        return true;
    }
    return false;
}

/*
 * rte_flow_start must have the size
 * MAX_DPDKHW_RTE_FLOW_SIZE * sizeof(rte_flow_item)
 */
void
init_rte_flow_batch(struct rte_flow_batch *batch,
                    struct rte_flow_item rte_flow_start[],
                    uint32_t batch_size)
{
    batch->used = 0;
    batch->max_size = batch_size;
    /* rte_flow_start is an array of rte_flow_item */
    batch->flow_batch = rte_flow_start;
}

static inline bool
rte_flow_item_push(struct rte_flow_batch *batch, void *flow,
                   void *mask, enum rte_flow_item_type type)
{
    struct rte_flow_item *flow_item;
    if (is_rte_flow_batch_full(batch)) {
        VLOG_ERR("Failed to install flow entry, the flow batch set is full");
        return false;
    }
    flow_item = batch->flow_batch + batch->used;
    flow_item->spec = flow;
    flow_item->mask = mask;
    flow_item->type = type;
    flow_item->last = NULL;
    batch->used++;
    return true;

}

static void
dpdkhw_rte_eth_set_action(const struct ovs_key_ethernet *key,
                          struct rte_flow_action hw_action_batch[],
                          int *const idx)
{
    if (!eth_addr_is_zero(key->eth_src)) {
        struct rte_flow_action_eth_set *eth_action_src =
                                       xmalloc(sizeof *eth_action_src);
        memcpy(&eth_action_src->addr, &key->eth_src,
                                      sizeof eth_action_src->addr);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ETH_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = eth_action_src;
        (*idx)++;
    }
    if (!eth_addr_is_zero(key->eth_dst)) {
        struct rte_flow_action_eth_set *eth_action_dst =
                                      xmalloc(sizeof *eth_action_dst);
        memcpy(&eth_action_dst->addr, &key->eth_dst,
                                      sizeof eth_action_dst->addr);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ETH_DST_ADDR_SET;
        hw_action_batch[*idx].conf = eth_action_dst;
        (*idx)++;
    }
}

/*
 * Set ttl for ipv4 and ipv6
 */
static void
dpdkhw_rte_ip_ttl_set_action(uint8_t ttl,
                             struct rte_flow_action hw_action_batch[],
                             int *const idx)
{
    struct rte_flow_action_ttl_set *ip_ttl_action =
                       xmalloc(sizeof *ip_ttl_action);
    ip_ttl_action->ttl = ttl;
    ip_ttl_action->layer = 0;
    hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_TTL_SET;
    hw_action_batch[*idx].conf = ip_ttl_action;
    (*idx)++;
}

/*
 * Set tos(dscp,ecn) for ipv4 and ipv6
 */
static void
dpdkhw_rte_ip_tos_set_action(uint8_t tos,
                             struct rte_flow_action hw_action_batch[],
                             int *const idx)
{
    struct rte_flow_action_dscp_ecn_set *ip_tos_action =
                         xmalloc(sizeof *ip_tos_action);
    ip_tos_action->dscp_ecn = tos;
    ip_tos_action->mask = 0xFF;
    ip_tos_action->layer = 0;
    hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DSCP_ECN_SET;
    hw_action_batch[*idx].conf = ip_tos_action;
    (*idx)++;
}

static void
dpdkhw_rte_ipv4_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv4 *ipv4_key;
    ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
    if (ipv4_key->ipv4_src) {
        struct rte_flow_action_ipv4_addr_set *ipv4_src_addr_action =
                            xmalloc(sizeof *ipv4_src_addr_action);
        ipv4_src_addr_action->addr = ipv4_key->ipv4_src;
        ipv4_src_addr_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_src_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_dst) {
        struct rte_flow_action_ipv4_addr_set *ipv4_dst_addr_action =
                            xmalloc(sizeof *ipv4_dst_addr_action);
        ipv4_dst_addr_action->layer = 0;
        ipv4_dst_addr_action->addr = ipv4_key->ipv4_dst;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_DST_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_dst_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_ttl) {
        dpdkhw_rte_ip_ttl_set_action(ipv4_key->ipv4_ttl, hw_action_batch,
                                     idx);
    }
    if (ipv4_key->ipv4_tos) {
        dpdkhw_rte_ip_tos_set_action(ipv4_key->ipv4_tos, hw_action_batch,
                                     idx);
    }
}

static void
dpdkhw_rte_ipv6_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv6 *ipv6_key;
    ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
    /* rte flow can only set src and dst ipv6 address */
    if (ipv6_addr_is_set(&ipv6_key->ipv6_src)) {
        struct rte_flow_action_ipv6_addr_set *ipv6_src_action =
                       xmalloc(sizeof *ipv6_src_action);
        memcpy(&ipv6_src_action->addr, &ipv6_key->ipv6_src,
                            sizeof ipv6_src_action->addr);
        ipv6_src_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = ipv6_src_action;
        (*idx)++;
    }
    if (ipv6_addr_is_set(&ipv6_key->ipv6_dst)) {
        struct rte_flow_action_ipv6_addr_set *ipv6_dst_action =
                       xmalloc(sizeof *ipv6_dst_action);
        memcpy(&ipv6_dst_action->addr, &ipv6_key->ipv6_dst,
                            sizeof ipv6_dst_action->addr);
        ipv6_dst_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_DST_ADDR_SET;
        hw_action_batch[*idx].conf = ipv6_dst_action;
        (*idx)++;
    }
    if (ipv6_key->ipv6_label) {
        /* ipv6 label is set for the ipv6 header */
        struct rte_flow_action_ipv6_label_set *ipv6_label_action =
                                 xmalloc(sizeof *ipv6_label_action);
        /* ipv6 label mask is 0xFFFFF000, Shift last 4 bits to the left
         * for the 20 bit packing.
         */
        ipv6_label_action->label = (ipv6_key->ipv6_label & 0xFFFF0000);
        ipv6_label_action->label |= (ipv6_key->ipv6_label & 0x00000F00) << 4;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_LABEL_SET;
        hw_action_batch[*idx].conf = ipv6_label_action;
        (*idx)++;
    }
    if (ipv6_key->ipv6_hlimit) {
        dpdkhw_rte_ip_ttl_set_action(ipv6_key->ipv6_hlimit, hw_action_batch,
                                     idx);
    }
    if (ipv6_key->ipv6_tclass) {
        dpdkhw_rte_ip_tos_set_action(ipv6_key->ipv6_tclass, hw_action_batch,
                                     idx);
    }
}

static void
dpdkhw_rte_l4_set_action(ovs_be16 src_port, ovs_be16 dst_port,
                         struct rte_flow_action hw_action_batch[],
                         int *const idx)
{
    if (src_port) {
        struct rte_flow_action_pt_num_set *l4_src_action =
                            xmalloc(sizeof *l4_src_action);
        l4_src_action->pt_num = src_port;
        l4_src_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_SRC_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_src_action;
        (*idx)++;
    }
    if (dst_port) {
        struct rte_flow_action_pt_num_set *l4_dst_action =
                             xmalloc(sizeof *l4_dst_action);
        l4_dst_action->pt_num = dst_port;
        l4_dst_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DST_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_dst_action;
        (*idx)++;
    }
}

static int
dpdkhw_rte_set_action(const struct nlattr *a,
                      struct rte_flow_action hw_action_batch[],
                      int *idx)
{
    enum ovs_key_attr type = nl_attr_type(a);
    int ret = 0;
    switch (type) {
    case OVS_KEY_ATTR_ETHERNET: {
        dpdkhw_rte_eth_set_action(nl_attr_get(a), hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_IPV4: {
        dpdkhw_rte_ipv4_set_action(a, hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_IPV6: {
        dpdkhw_rte_ipv6_set_action(a, hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6: {
        const struct ovs_key_icmp *icmp_key =
                        nl_attr_get_unspec(a, sizeof(struct ovs_key_icmp));
        if (icmp_key->icmp_type) {
            struct rte_flow_action_icmp_type_set *icmp_type_action =
                                    xmalloc(sizeof *icmp_type_action);
            icmp_type_action->type = icmp_key->icmp_type;
            icmp_type_action->layer = 0;
            hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ICMP_TYPE_SET;
            hw_action_batch[*idx].conf = icmp_type_action;
            (*idx)++;
        }
        if (icmp_key->icmp_code) {
            struct rte_flow_action_icmp_code_set *icmp_code_action =
                                    xmalloc(sizeof *icmp_code_action);
            icmp_code_action->code = icmp_key->icmp_code;
            icmp_code_action->layer = 0;
            hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ICMP_CODE_SET;
            hw_action_batch[*idx].conf = icmp_code_action;
            (*idx)++;
        }
        break;
    }

    case OVS_KEY_ATTR_TCP: {
        const struct ovs_key_tcp *tcp_key =
                nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));
        dpdkhw_rte_l4_set_action(tcp_key->tcp_src, tcp_key->tcp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_UDP: {
        const struct ovs_key_udp *udp_key =
               nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));
        dpdkhw_rte_l4_set_action(udp_key->udp_src, udp_key->udp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_SCTP: {
        const struct ovs_key_sctp *sctp_key =
               nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));
        dpdkhw_rte_l4_set_action(sctp_key->sctp_src, sctp_key->sctp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_VLAN: {
        /* Set the 12 bit VID */
        struct rte_flow_action_vlan_set *vlan_action =
                xmalloc(sizeof *vlan_action);
        vlan_action->tag = nl_attr_get_u16(a);
        vlan_action->mask = RTE_FLOW_ACTION_MASK_VLAN_VID;
        vlan_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_VLAN_SET;
        hw_action_batch[*idx].conf = vlan_action;
        (*idx)++;
        /* Set the User priority */
        struct rte_flow_action_vlan_set *vlan_action_pri =
                xmalloc(sizeof *vlan_action_pri);
        vlan_action_pri->tag = vlan_action->tag;
        vlan_action_pri->mask = RTE_FLOW_ACTION_MASK_VLAN_PRI;
        vlan_action_pri->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_VLAN_SET;
        hw_action_batch[*idx].conf = vlan_action_pri;
        (*idx)++;
        break;
    }

    case OVS_KEY_ATTR_ARP:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_MPLS:
    case OVS_KEY_ATTR_RECIRC_ID:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_TUNNEL:
    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case __OVS_KEY_ATTR_MAX:
    default:
        VLOG_ERR_RL(&rl, "Set action is not implemented");
        ret = -EINVAL;
    }
    return ret;
}

static int
dpdkhw_em_action_xlate(struct rte_flow_action hw_action_batch[],
                        const struct nlattr *actions,
                        size_t actions_len,
                        const struct offload_info *ofld_info)
{
    const struct nlattr *a;
    unsigned int left;
    int ret = 0;
    int i = 0;
    int max_action_entry = MAX_DPDKHW_RTE_ACTION_SIZE - 1;

    if (!actions_len || !actions) {
        VLOG_DBG_RL(&rl, "No actions to offload, Install drop action");
        hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_DROP;
        hw_action_batch[i].conf = NULL;
        return ret;
    }
    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        if(i >= max_action_entry) {
            VLOG_WARN("Max action entry limit reached,"
                      " cannot add more actions");
            return EPERM;
        }
        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            /*
             * Current POC only supports the output action to a port.
             */
            struct rte_flow_action_switch_port *rte_action_port =
                    xmalloc(sizeof *rte_action_port);
            odp_port_t out_port = nl_attr_get_odp_port(a);
            /* Output port should be hardware port number. */
            struct netdev *netdev = get_hw_netdev(out_port,
                                                  ofld_info->port_hmap_obj);
            if (!netdev) {
                VLOG_WARN("Cannot offload a flow with non accelerated output"
                          " port %u", odp_to_u32(out_port));
                return EPERM;
            }

            uint16_t dpdk_portno = netdev_get_dpdk_portno(netdev);
            rte_action_port->index = dpdk_portno;

            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_SWITCH_PORT;
            hw_action_batch[i].conf = rte_action_port;
            i++;
            break;
        }
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
            struct rte_flow_action_vlan_push *vlan_action =
                            xmalloc(sizeof *vlan_action);
            vlan_action->tpid = vlan->vlan_tpid;
            vlan_action->tag = vlan->vlan_tci & htons(~VLAN_CFI);
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_VLAN_PUSH;
            hw_action_batch[i].conf = vlan_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN: {
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_VLAN_POP;
            hw_action_batch[i].conf = NULL;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_SET_MASKED:
        case OVS_ACTION_ATTR_SET: {
            ret = dpdkhw_rte_set_action(nl_attr_get(a), hw_action_batch, &i);
            break;
        }

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            /* MPLS push is combination of PUSH + SET actions */
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
            struct rte_flow_action_mpls_push *mpls_push_action =
                        xmalloc(sizeof *mpls_push_action);
            mpls_push_action->ethertype = mpls->mpls_ethertype;
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_PUSH;
            hw_action_batch[i].conf = mpls_push_action;
            i++;

            struct rte_flow_action_mpls_set *mpls_set_action =
                        xmalloc(sizeof *mpls_set_action);
            mpls_set_action->hdr = mpls->mpls_lse;
            mpls_set_action->mask = 0xFFFFFFFF;

            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_SET;
            hw_action_batch[i].conf = mpls_set_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_POP_MPLS: {
            struct rte_flow_action_mpls_pop *mpls_pop_action =
                        xmalloc(sizeof *mpls_pop_action);
            mpls_pop_action->ethertype = nl_attr_get_be16(a);
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_POP;
            hw_action_batch[i].conf = mpls_pop_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_SAMPLE:
        case OVS_ACTION_ATTR_HASH:
        case OVS_ACTION_ATTR_UNSPEC:
        case OVS_ACTION_ATTR_TRUNC:
        case __OVS_ACTION_ATTR_MAX:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
            VLOG_DBG_RL(&rl, "TODO actions %u", type);
            ret = -EINVAL;
            break;
        default:
            VLOG_DBG_RL(&rl, "Unsupported action to offload %u", type);
            ret = -EINVAL;
            break;
        }
    }
    /* Add end action as a last action */
    hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_END;
    hw_action_batch[i].conf =  NULL;
    return ret;
}

