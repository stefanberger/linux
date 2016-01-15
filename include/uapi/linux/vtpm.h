/*
 * Definitions for the VTPM interface
 * Copyright (c) 2015, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _UAPI_LINUX_VTPM_H
#define _UAPI_LINUX_VTPM_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ioctls */
#define VTPM_TPM 0xa0

#define VTPM_DEVNAME_MAX   16

#define VTPM_DEV_PREFIX_SERVER "vtpms"  /* server-side device name prefix */
#define VTPM_DEV_PREFIX_CLIENT "vtpmc"  /* client-side device name prefix */

#define VTPM_DEV_NUM_INVALID  ~0

struct vtpm_new_pair {
        __u32 flags;         /* input */
        __u32 tpm_dev_num;   /* output */
        __u32 vtpm_dev_num;  /* output */
};

struct vtpm_pair {
        __u32 tpm_dev_num;   /* input or output */
        __u32 vtpm_dev_num;  /* input or output */
};

/* above flags */
#define VTPM_FLAG_TPM2           1  /* choose a TPM2; mainly for sysfs entries */
#define VTPM_FLAG_KEEP_DEVPAIR   2  /* keep the device pair once vTPM closes */
#define VTPM_FLAG_NO_SYSFS       4  /* do not register device in sysfs */
#define VTPM_FLAG_NO_LOG         8  /* no BIOS measurement files in sysfs */

/* create new TPM device pair */
#define VTPM_NEW_DEV         _IOW(VTPM_TPM, 0x00, struct vtpm_new_pair)
#define VTPM_DEL_DEV         _IOW(VTPM_TPM, 0x01, struct vtpm_pair)
#define VTPM_GET_TPMDEV      _IOW(VTPM_TPM, 0x02, struct vtpm_pair)
#define VTPM_GET_VTPMDEV     _IOW(VTPM_TPM, 0x03, struct vtpm_pair)

#endif /* _UAPI_LINUX_VTPM_H */
