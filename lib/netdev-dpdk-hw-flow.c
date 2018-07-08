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

