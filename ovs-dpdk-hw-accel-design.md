# Hardware acceleration framework in OVS-DPDK

Real world telco deployments need support of accelerated devices along with
DPDK to meet their performance and scalability requirements.
In this proposal we are trying to integrate accelerated devices such as FPGA,
smart NICs into DPDK datatpath, so that customer can enjoy the best of both
worlds.

The proposal only covers the full acceleration support in OVS-DPDK. i.e the
following sections in this document assumes that the hardware/FPGA can do end
to end packet processing in hardware without any software intervention except
the initial device setup and flow installation.

## OVS-DPDK Acceleration device integration model
Following figure depicts how OVS-DPDK is integrated with heterogeneous
accelerated devices.

```
                         +--------------+                                  
                         |              |                                  
                         | OVS-VSWITCHD |                                  
                         |              |                                  
                         +-------^------+                                  
                                 |                                         
                                 v                                         
                   +------------------------------------------------------+
                   |                    OVS-DPDK datapath                 |
                   +------------------------------------------------------+
                   h | h |    h |    h | h |    h |        h | h |    h |  
                   w | w |    w |    w | w |    w |        w | w |    w |  
                   1 | 1 |    1 |    2 | 2 |    2 |        n | n |    n |  
                   p | p |    p |    p | p |    p |  ....  p | p |    p |  
   (representors)  o | o |... o |    o | o |... o |        o | o |... o |  
                   r | r |    r |    r | r |    r |        r | r |    r |  
                   t | t |    t |    t | t |    t |        t | t |    t |  
                   1 | 2 |    m |    1 | 2 |    m |        1 | 2 |    m |  
                   +------------------------------------------------------+
                   |                     DPDK                             |
                   |                                                      |
                   +------------------------------------------------------+
                            |          | |      |             |     |      
  (exception path)          |          | | ...  |             |     |      
                            |          | |      |             |     |      
                     +------------+  +------------+       +------------+   
                     | hw-1       |  | hw-2       |       | hw-n       |   
                     | +--------+ |  | +--------+ |  .... | +--------+ |   
                     | |  DP    | |  | |  DP    | |       | |  DP    | |   
                     | +----|---+ |  | +----|---+ |       | +----|---+ |   
                     +----/-|-\---+  +------------+       +----/-|-\---+   
                         /  |  \         /  |  \              /  |  \      
       (ports)          /   |   \       /   |   \            /   |   \     
                       /    |... \     /    |... \          /    |... \    
                      /     |     \   /     |     \        /     |     \   
                     p      p     p   p     p     p       p      p     p   
                     o      o     o   o     o     o       o      o     o   
                     r      r     r   r     r     r       r      r     r   
                     t      t     t   t     t     t       t      t     t   
                     1      2     m   1     2     m       1      2     m    

```

'hw-1, hw-2 .. hw-n' are either smart NIC/FPGA that can perform vswitch functions
in the hardware. These devices are exposed to OVS-DPDK datapath via DPDK APIs.
It is not necessary these devices offers same set of features, number of ports
and port types. Say for e.g. hw-1 may have 2 physical ports, 128 VFs and can do
wildcard matching on 5 tuples. whereas hw-2 has 4 physical ports, 32 vhost
ports (vhost backends) and can do only exact match on flow tuples. OVS must
aware about these underlying hardware differences to use them in right manner.

At very high level the integration of accelerated devices into OVS-DPDK
datapath has two phases.

* The initialization and management of accelerated devices.

* Handling of vswitch functions in the accelerated devices and its ports.

## Management of accelerated devices
To work with heterogeneous hardware acceleration devices, OVS must aware about
the hw datapaths and its associated ports, instead of just operate on netdev/
port level.

To achieve this model, In our implementation OVS need user to input the hardware
device ids at the init time as below. These parameters are similar to standard
init time DPDK parameters.

```
    ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-hw-offload-init=true
    ovs-vsctl --no-wait set Open_vSwitch . \
    other_config:dpdk-hw-offload-ids="0000:5e:00.0,0000:be:00.0"

```
In the above example "0000:5e:00.0,0000:be:00.0" are pci-ids of accelerated
devices.

In fact it is not the best possible way to represent a accelerated devices using
pci-ids, because hardware device may have one more pci-ids associated with it.
Until DPDK provide a standard mechanism to represent accelerated devices, we
have to use pci-ids.

OVS DPDK datapath can now initialize all the user input devices with its
relevant DPDK driver. As part of this initialization OVS collect all vswitch
related device information and update it in ovsdb.

There is one more optional configuration option to set the vhost socket
directory for hardware accelerated vhost ports.

```
ovs-vsctl --no-wait set Open_vSwitch . \
    other_config:hw-vhost-sock-dir="/usr/local/var/run/openvswitch"
```

The sockets are created at default location, if no vhost directory is explicitly
configured as above.

```
hw_offload table
_uuid                                dev_id features                              name       pci_id
------------------------------------ ------ ------------------------------------- ---------- --------------
5bfb8335-31bf-4d17-b0da-bc5a36a8c6c2 0      {n_phy_ports="2", n_vhost_ports="32"} "switch-0" "0000:5e:00.0"
458da6fe-1d2e-4e6b-9f8d-92b4b7794761 1      {n_phy_ports="2", n_vhost_ports="32"} "switch-1" "0000:be:00.0"

```

Currently this table provide only number of ports and its types in every device.
We may need to extend this table based on properties of different hardware
devices that are going to integrate with OVS-DPDK.

There are number of reasons why we need to populate this information in the
OVSDB. It let users to use slice of device in OVS as required, the management
can query these information whenever it needed. Also vswitchd can use these
information later for run time configuration and validations.

```
/* hardware accelerated device/hardware switch */
struct dpdkhw_switch {
    uint16_t dev_id;
    uint16_t hw_engid;
    int socket_id;
    int numa_id; /* Numa-id of the PF/hw-switch */
    char dev_name[MAX_HW_DEV_NAME_LEN];
    void *dev_info; /* Generic pointer to hold dpdk driver specific hw info */
    struct rte_pci_addr pci_addr;
    struct dpdk_mp *dpdk_mp; /* Mempool to use for default exception path */
    /** hardware switch properties populated based on DPDK get APIs **/
    enum hw_switch_mode switch_mode;
    /* Number of flows the switch can support */
    uint32_t total_flow_cnt;
    /* Number of flows installed in the hardware */
    atomic_count n_flow_cnt;
    /* Available protocol support in the hardware switch */
    uint8_t avail_ptypes[HW_PROTO_TYPE_NUM_BYTES];
    uint16_t n_vhost_ports;
    uint16_t n_phy_ports;
    const struct dpdkhw_switch_fns *hw_fns;
    /*TODO :: Extend more hardware properties */

};
```

Once the initialization is complete, 'dpdkhw_switch' structure will be populated
for each hardware device.

Note :: Current implementation populate many fields in 'dpdkhw_switch'
statically as DPDK doesnt have APIs to provide these information.

Once the OVS initialization is complete user can add accelerated ports to OVS
similar to normal ports. The accelerated ports not as same as standard dpdk
software ports. The implementation of these ports can vary for hardware to
hardware. In the above figure, the 'hw-1' has only single exception to report
unhandled packets where as hw-2 expose every ports as netdev to software. Now
its responsibility of DPDK driver(port representors) to
demutliplex exception path and expose them as representors to the OVS datapath.
DPDK driver enqueue the packets from exception ports into representor ports
based on the metadata present in the packets.

The proposal uses a new netdev type 'dpdkhw' for accelerated ports in OVS. The
new netdev for these ports have many advantages than extending the existing DPDK
netdevs.

* Most of the DPDK netdev functions are irrelevant for accelerated port
representors. It will introduce unnecessary validations in most of the netdev
functions to make sure its working fine in both normal and accelerated ports.
Considering the impact on existing netdev, its better to keep it as a separate
 from accelerated ports. Also accelerated ports have its own configuration
 parameters. Having a separate netdev allows easy management of these options.

* The new netdev made the device +port model integration easy.

* In future, we can move these netdevs easily to a NAPI model implementation
to reduce the pmd overhead on polling representor ports.

* Less hassle for upstreaming as no/less impact of existing netdevs.

In future we can refactor the code to move all the common functions to one
place to avoid some of duplicate functions.

Adding an accelerated port 32 in device 0 (the 'switch-0' in ovsdb table) can be
done with following command,

```
ovs-vsctl --timeout 10 add-port br0 dpdk32 -- set Interface dpdk32 type=dpdkhw options:device-id=0,port-id=32
```

A socket 'hw-vhost-user-0-32' is created in the vhost socket directory as part
of creating the vhost port 'dpdk32'. Qemu will use the socket afterwards to
connect to the hw datapath. The vhost socket names are created from device-id
and port-id(hw-vhost-user-{device-id}-{port-id}), so its easy to  infer the
socket-name for qemu parameters.

In some of hardware devices, resources are not equally shared across all the
ports in the device. This means OVS must allow user to choose a port in the device
to meet their requirements.

## Handling of vswitch functions in accelerated devices.
Once ports are added into OVS, flows can be programmed as normal. The proposal
defines a set of standard APIs to program the hardware devices. Currently APIs
are only defined for flow programming, but its possible to extend them for
other  hardware accelerations.

The APIs for flow programming are,

```
struct dpdkhw_switch_fns {
    /* hardware switch functions. These functions are intended to interact with
     * hardware device.
     */
    /* OVS validation function to check if an operation/flow can be offloaded to a
     * hardware device. Return 'FLOW_INSTALL_SUPPORTED' when hardware can do
     * the operation . Error code otherwise./
     */
    enum hw_switch_flow_install_err (*is_ovs_op_avial_in_hw)(
                                      struct netdev *, struct dpdkhw_switch *,
                                      struct match *, const struct nlattr *,
                                      size_t, const ovs_u128 *,
                                      struct offload_info *);
    /* Function to translate the OVS flow into hardware flow format.
     * Most hardware can understand the rte_flow format, hence this function
     * translate the OVS flow to rte_flow.
     */
    int (*ovs_flow_xlate)(struct match *, struct rte_flow_attr *,
                          struct rte_flow_batch *,
                          const struct offload_info *);
    /* Translate the OVS actions to hardware actions. Hardware can understand
     * rte_action,hence this function translate into the actions that hardware
     * can do */
    int (*ovs_actions_xlate)(struct rte_flow_action *, const struct nlattr *,
                             size_t, const struct offload_info *);
    /* Install a flow or operation into a hardware using DPDK rte_flow
     * and rte_action.
     */
    struct rte_flow *(*install_ovs_op)(struct netdev *, struct dpdkhw_switch *,
                                       const struct rte_flow_attr *,
                                       struct rte_flow_item *,
                                       struct rte_flow_action *,
                                       struct rte_flow_error *);
   /* Delete the installed op/flow from a hardware from OVS */
   int (*del_ovs_op)(struct netdev *, struct dpdkhw_switch *,
                     const ovs_u128 *);
};

```

Currently we have implemented all these functions to operate on an exact match
full offload device. Similarly we can have implementation for partial offload,
and full offload + wild card in the future.

rte_flow expects the flow installation on port basis, however these functions
are defined per device and it will be populated in 'dpdkhw_switch' at the time
of init.

Flow installation is triggered from dpif-netdev when an inport is hardware
accelerated. At high level these APIs are getting called as below for any flow
install/modify operation.

```


  (Find-Device-for-netdev)                                                  
            |                                                               
            |                                             -----             
            v                           NO                    |             
  (is-flow-offloadable)         ----------------------+       |             
  [device->is_ovs_op_avial_in_hw]                     |       |             
            |                                         |       |             
            |                                         |       |             
            v                                         |       |             
  (ovs-to-hw-flow-translate)          xlate-fail      |       |             
  [device->ovs_flow_xlate] -------------------------->|       |             
            |                                         |       |             
            |                                         |       |             
            |                                         |       |             
            v                                         |       |(Device APIs)
  (ovs-to-hw-action-translate)        xlate-fail      |       |             
  [device->ovs_actions_xlate] ----------------------->|       |             
            |                                         |       |             
            |                                         |       |             
            |                                         |       |             
            |                                         |       |             
            v                                         |       |             
  (Install-flow-in-hw)                                v       |             
  [device->install_ovs_op]   ---------------------->(END)     |             
                                                              |             
                                                         -----+             
```
For now the entire flow installation is happening in pmd thread context.
In future the flow installation will be handled by flow installer threads. To
avoid synchronization issues in flow installation, its better to introduce flow
installer thread per device. Having a 'device + port' model make it easy to
migrate to per device thread model.

To simplify and modularize the flow translation logic, the proposal is using a
flow translation framework. The framework translates the OVS 'match' to hw
specific rte_flow. Due to the implementation differences, each hardware need
slightly different translation logic from one to another. The framework uses
a protocol layered approach to translate the match fields. In future
a new protocol match support can be added easily by defining a new xlate
entry in 'flow_xlate_dic' and invoke it in the main translate function.
This framework helped a lot in our development to switch between various
hardware that are different in their flow matching capabilities.

To add a new protocol, say for e.g. GTP, an xlate entry can be defined as,

```
struct flow_xlate_dic GTP_FLOW_XLATE = {
            RTE_FLOW_ITEM_TYPE_VOID, /* GTP transalte*/
            do_gtp_flow_xlate
};
```

The function 'do_gtp_flow_xlate' only care about translating the gtp protocol
layer in the OVS match. Once the flow-xlate entry is defined it can be invoked
from main translate function as

```
DO_FLOW_XLATE(GTP_FLOW_XLATE, match, batch, NULL);
```
