/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OF_DEVICE_NODE_H
#define _LINUX_OF_DEVICE_NODE_H

#include <linux/of.h>

int of_tpm_get_sml_parameters(struct device_node *np, u64 *base, u32 *size);

#endif /* _LINUX_OF_DEVICE_NODE_H */
