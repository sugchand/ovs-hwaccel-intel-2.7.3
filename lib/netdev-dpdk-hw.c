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
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <vdpo.h>
#include <timeval.h>

#include "dpif-netdev.h"
#include "openvswitch/vlog.h"
#include "netdev-dpdk-hw.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdkhw);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define DPDKHW_INIT_SUCCESS 0
#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_HWPORT_DPDK "ovs_dpdkhw"
#define DPDKHW_PORTNO_STR_SIZE ((sizeof(odp_port_t) << 1) + 1)

static int rte_dpdkhw_init = ENODEV;
/* One socket directory for all the switch devices */
static char *hw_vhost_sock_dir = NULL;
static struct ovs_mutex dpdkhw_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_mutex dpdkhw_flow_mutex OVS_ACQ_AFTER(dpdkhw_mutex) =
                                          OVS_MUTEX_INITIALIZER;

static int
netdev_dpdkhw_flow_put(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   const struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct offload_info *info OVS_UNUSED);

enum dpdkw_dev_type {
    DPDKHW_ETH_PORT = 0,
    DPDKHW_VHOST_PORT = 1
};

#define MAX_HW_DEV_NAME_LEN    128

#define MAX_HW_OFFLOAD_SWITCH_DEVICES 8
struct hw_switches {
    uint16_t num_devs; /* Number of hardware acceleration devices */
    struct dpdkhw_switch dpdkhw_switch[MAX_HW_OFFLOAD_SWITCH_DEVICES];
};
static struct hw_switches hw_switches;
struct dpdkhw_switch *get_hw_switch(uint16_t dev_id);

struct netdev_dpdkhw {
    struct netdev up;
    int max_packet_len;
    int mtu;
    uint16_t dev_id; /* unique id when multiple fpga co-exist on a board */
    uint16_t port_id; /* Port id in device, unique value in the device */
    uint8_t dpdk_port_id; /* The global port id used in DPDK. used for tx/rx */
    int numa_id; /* NUMA node where the hardware port resides */
    int socket_id; /* Socket-id to allocate memory for the port */
    enum dpdkw_dev_type type;
    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdkhw_mutex);
    struct dpdk_mp *dpdk_mp;
    struct netdev_stats stats;
    /* Protects stats */
    rte_spinlock_t stats_lock;

    rte_spinlock_t tx_lock;
    struct eth_addr hwaddr;
    struct rte_eth_link link;
    int requested_mtu;
    enum netdev_flags flags;
    struct shash_node *node; /* Pointer to the hashmap node */
    struct netdev_rxq *hw_rxq; /* Exception Rx queue */
    struct hmap ufid_to_flow_map; /* hashmap to store hardware flows */
    /* XXX : WILL ADD MORE FIELDS ACCORDING TO THE FPGA CONFIG OPTIONS */
};

