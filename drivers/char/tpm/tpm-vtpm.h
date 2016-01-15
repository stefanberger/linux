/*
 * Copyright (C) 2015 IBM Corporation
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Device driver for vTPM.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#ifndef __TPM_VTPM_H
#define __TPM_VTPM_H

#include "tpm.h"

#define VTPM_NUM_DEVICES TPM_NUM_DEVICES

struct vtpm_dev {
        struct kref kref;

        struct device *pdev;
        struct device dev;
        struct cdev cdev;

        struct tpm_chip *chip;

        u32 flags;

        int dev_num;
        char devname[VTPM_DEVNAME_MAX];

        long state;
#define STATE_OPENED_BIT   0

        spinlock_t buf_lock;         /* lock for buffers */

        wait_queue_head_t wq;

        size_t req_len;              /* length of queued TPM request */
        u8 req_buf[TPM_BUFSIZE];     /* request buffer */

        size_t resp_len;             /* length of queued TPM response */
        u8 resp_buf[TPM_BUFSIZE];    /* request buffer */

        struct list_head list;
};

struct file_priv {
        struct vtpm_dev *vtpm_dev;
};

#endif
