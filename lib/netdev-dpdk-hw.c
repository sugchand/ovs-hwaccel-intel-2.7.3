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


int
get_max_configured_hw_switch_cnt(void)
{
    return hw_switches.num_devs;
}

/* Returns hardware switch configuration for 'dev_id' */
struct dpdkhw_switch *
get_hw_switch(uint16_t dev_id)
{
    int i;
    struct dpdkhw_switch *hw_switch;
    for (i = 0; i < MAX_HW_OFFLOAD_SWITCH_DEVICES; i++) {
        hw_switch = &hw_switches.dpdkhw_switch[i];
        if (hw_switch->dev_id == dev_id) {
            return hw_switch;
        }
    }
    return NULL;
}

static int
get_unsigned_long(const char *str, int base)
{
    unsigned long num;
    char *end = NULL;

    errno = 0;

    num = strtoul(str, &end, base);
    if ((str[0] == '\0') || (end == NULL) || (*end != '\0') || (errno != 0))
        return -1;

    return num;

}

static void
set_switch_proto_bitmap(struct dpdkhw_switch *hw_switch)
{

    /* Set the protocol bitmap for the switch based on the hw support
     * TODO :: Must need to use a API from DPDK to get the protocol
     * support. For now use constant values
     */

    /* First byte
    L2_ETHERNET, 1<<0
    L2_VLAN, 1<<1

    L3_IP, 1<<2
    L3_IPV6, 1<<3
    L3_MPLS, 1<<4
    L3_ARP, 1<<5
    L3_RARP, 1<<6

    L4_TCP, 1<<7
    */
    hw_switch->avail_ptypes[0] = 0xFF;

    /* Second Byte
    L4_UDP,  1<<0
    L4_ICMP, 1<<1
    L4_SCTP, 1<<2
    L4_ICMPV6, 1<<3
    L5_VXLAN,  1<<4
    L5_NVGRE   1<<5
    */
    hw_switch->avail_ptypes[1] = 0x3F;

}
static void
add_hw_switch_device(char *pci_id)
{
    int i,j;
    struct dpdkhw_switch *hw_switch;
    char tmp_pci_no[MAX_HW_DEV_NAME_LEN];
    strncpy(tmp_pci_no, pci_id, MAX_HW_DEV_NAME_LEN-1);
    int num[4] = { 0, 0, 0, 0};
    if( hw_switches.num_devs >= MAX_HW_OFFLOAD_SWITCH_DEVICES) {
        VLOG_WARN("Cannot add more switch devices, max limit reached");
    }
    i = strlen(tmp_pci_no) - 1;
    j = 3;
    while (i > 0 && j >= 0) {
        while ((tmp_pci_no[i - 1] != ':' && tmp_pci_no[i - 1] != '.')
                && i > 0) {
            i--;
        }
        num[j--] = get_unsigned_long(&tmp_pci_no[i], 16);
        i--;
        if (i >= 0) {
            tmp_pci_no[i] = '\0';
        }
    }
    /* Cache the device information */
    hw_switch = &hw_switches.dpdkhw_switch[hw_switches.num_devs];
    hw_switch->dev_id = hw_switches.num_devs;
    strncpy(hw_switch->dev_name, pci_id, (sizeof hw_switch->dev_name) -1);
    hw_switch->pci_addr.domain = num[0];
    hw_switch->pci_addr.bus = num[1];
    hw_switch->pci_addr.devid = num[2];
    hw_switch->pci_addr.function = num[3];

    /* XXX : HACK/TODO::
     * Statically set the number of vhost and phy ports. This has to be
     * read from hardware
     */
    hw_switch->n_vhost_ports = 32;
    hw_switch->n_phy_ports = 2;
    hw_switch->switch_mode = FULL_ACCEL_EM_SWITCH;
    hw_switch->total_flow_cnt = 2000000;
    atomic_count_init(&hw_switch->n_flow_cnt, 0);
    hw_switch->hw_fns = &dpdkhw_full_em_switch_fns;
    set_switch_proto_bitmap(hw_switch);
    hw_switches.num_devs++;
    /* XXX :: Read hardware switch information from DPDK to populate
     * switch feature set.
     */
}

/*
 * Collect all the features of provided devices.
 * Returns false if failed to retrieve the device information.
 */
static bool
dpdkhw_get_switch_devices(const char *pci_ids)
{
   char *pci_dev;
   uint32_t len;
   int i;
   if (!pci_ids) {
        return false;
   }
   len = strlen(pci_ids);
   do {
       i = strcspn(pci_ids, ",");
       pci_dev = xmemdup0(pci_ids, i);
       if (!strlen(pci_dev)) {
           goto out;
       }
       add_hw_switch_device(pci_dev);
       i++;
       pci_ids += i; /* Read next PCI-ID */
       len -= i;
       free(pci_dev);
   } while(pci_ids && len);
out:
    return true;
}

/*
 * Setting the socket and numa node information for a dpdk hw port.
 * XXX :: The socket information is blindly decide based on the pci-id.
 * In future DPDK might offer APIs to know which socket the device(PF)
 * is belongs to.
 * Most cases pci_bus 00: is CPU1/socket0 and 80+ is CPU2/socket1
 */
static void
dpdkhw_switch_set_numa_node(struct dpdkhw_switch *hw_switch)
{
    if (hw_switch->pci_addr.bus >= 0x80) {
       hw_switch->socket_id = SOCKET1;
       hw_switch->numa_id = NUMA_NODE_1;
       return;
    }
    hw_switch->socket_id = SOCKET0;
    hw_switch->numa_id = NUMA_NODE_0;
}

static int
dpdkhw_switch_mp_configure(struct dpdkhw_switch *hw_switch)
{
    int mtu = ETHER_MTU; /* XXX :: Read from hw to change MTU if needed */
    uint32_t buf_size = dpdk_buf_size(mtu);
    struct dpdk_mp *mp;
    dpdkhw_switch_set_numa_node(hw_switch);
    mp = dpdk_mp_get_ext(hw_switch->socket_id, dpdk_framelen_to_mtu(buf_size));
    if (!mp) {
        VLOG_ERR("Insufficient memory to create memory pool for switchdev "
                 "%s, with MTU %d on socket %d\n",
                 hw_switch->dev_name, mtu, hw_switch->socket_id);
        return -ENOMEM;
    }
    else {
        dpdk_mp_put_ext(hw_switch->dpdk_mp);
        hw_switch->dpdk_mp = mp;
    }
    return 0;
}

/* Register VDPA engine for the switch device. */
static int
register_switch_engine(void)
{
    /* XXX :: TODO::
     * switch engine APIs are not supposed to expect any hardware type as a
     * input. Also Application doesnt wanted to keep track of engine pointers.
     * The engine need to be registered for each device. for now we do only
     * for one device.
     * This function should loop on 'hw_switches' and init engine for each
     * switch device.
     */
    {
        /* The function must be rewritten */
        int ret = 0;
        int engid = 0;
        struct dpdkhw_switch *hw_switch;
        uint32_t afuid = 0; /* It is not expected to be selected */
        struct rte_vdpo_hw_afu_device *afudev;
        int i;
        char str[MAX_HW_DEV_NAME_LEN];
        for (i = 0; i < hw_switches.num_devs; i++) {
            hw_switch = &hw_switches.dpdkhw_switch[i]; /*Only one device ??*/

            /* Configure the mempool for the switch device */
            ret = dpdkhw_switch_mp_configure(hw_switch);
            if (ret < 0) {
                return ret;
            }
            snprintf(str, sizeof str, "ovs-hw-switch-%d", i);
            afudev = rte_zmalloc_socket(str, sizeof *afudev,
                              RTE_CACHE_LINE_SIZE, hw_switch->socket_id);
            afudev->addr = hw_switch->pci_addr;
            afudev->afu_id = afuid;
            afudev->mempool = hw_switch->dpdk_mp->mp;
            engid = rte_vdpo_register_engine("fpga", afudev);
            if (engid >= 0) {
                /* valid engine id */
                hw_switch->hw_engid = engid;
                hw_switch->dev_info = afudev; /*device specific conf */
            }
            else {
                /* Return if one of afu init is failed */
                rte_free(afudev);
                return -EINVAL;
            }
        }
        return ret;
    }
}

/* Initilize OVS-DPDK to use hardware/FPGA pmd ports.
 * Any global OVS/DPDK/FPGA initialization can be done
 * here.
 */
void
dpdkhw_init(const struct smap *ovs_other_config)
{
    int ret;
    const char *pci_ids;
    pci_ids = smap_get(ovs_other_config, "dpdk-hw-offload-ids");
    hw_switches.num_devs = 0;
    if(!dpdkhw_get_switch_devices(pci_ids)) {
        VLOG_DBG("Failed to retrieve device info/No devices are provided");
        return;
    }
    VLOG_DBG("Initializing the hardware/FPGA ports.");
    netdev_dpdkhw_register();
    /* Initilize the hardware vhost socket directory */
    setup_vhost_dir("hw-vhost-sock-dir", ovs_other_config,
                    &hw_vhost_sock_dir);
    if (hw_vhost_sock_dir[strlen(hw_vhost_sock_dir) - 1] == '/' ) {
        hw_vhost_sock_dir[strlen(hw_vhost_sock_dir) - 1] = '\0';
    }
    ret = register_switch_engine();
    if (ret < 0) {
        VLOG_ERR("Failed to initialize the VDPA engine");
    }

    /*
     * XXX : Validate the hardware device init and set the flag
     * accordingly
     */
     rte_dpdkhw_init = DPDKHW_INIT_SUCCESS;
}
