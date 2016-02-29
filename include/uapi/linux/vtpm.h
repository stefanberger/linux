/*
 * Definitions for the VTPM interface
 * Copyright (c) 2015, 2016, IBM Corporation
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

struct vtpm_new_pair {
	__u32 flags;         /* input */
	__u32 tpm_dev_num;   /* output */
	__u32 fd;            /* output */
	__u32 major;         /* output */
	__u32 minor;         /* output */
};

/* above flags */
#define VTPM_FLAG_TPM2           1  /* emulator is TPM 2 */

/* all supported flags */
#define VTPM_FLAGS_ALL  (VTPM_FLAG_TPM2)

#define VTPM_TPM 0xa0

#define VTPM_NEW_DEV         _IOW(VTPM_TPM, 0x00, struct vtpm_new_pair)

#endif /* _UAPI_LINUX_VTPM_H */
