// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2012 IBM Corporation
 *
 * Author: Ashley Lai <ashleydlai@gmail.com>
 *         Nayna Jain <nayna@linux.vnet.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Read the event log created by the firmware on PPC64
 */

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/tpm.h>
#include <linux/tpm_eventlog.h>

#include "../tpm.h"
#include "common.h"

int tpm_read_log_of(struct tpm_chip *chip)
{
	struct device_node *np;
	struct tpm_bios_log *log;
	u32 size;
	u64 base;
	int ret;

	log = &chip->log;
	if (chip->dev.parent && chip->dev.parent->of_node)
		np = chip->dev.parent->of_node;
	else
		return -ENODEV;

	if (of_property_read_bool(np, "powered-while-suspended"))
		chip->flags |= TPM_CHIP_FLAG_ALWAYS_POWERED;

	ret = of_tpm_get_sml_parameters(np, &base, &size);
	if (ret < 0)
		return ret;

	if (size == 0) {
		dev_warn(&chip->dev, "%s: Event log area empty\n", __func__);
		return -EIO;
	}

	log->bios_event_log = kmemdup(__va(base), size, GFP_KERNEL);
	if (!log->bios_event_log)
		return -ENOMEM;

	log->bios_event_log_end = log->bios_event_log + size;

	if (chip->flags & TPM_CHIP_FLAG_TPM2)
		return EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
	return EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2;
}
