/*
 * Copyright (C) 2015, 2016 IBM Corporation
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

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/vtpm.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/poll.h>
#include <linux/compat.h>

#include "tpm.h"

#define VTPM_NUM_DEVICES TPM_NUM_DEVICES

struct vtpm_dev {
	struct tpm_chip *chip;

	u32 flags;                   /* public API flags */

	long state;
#define STATE_OPENED_BIT        0
#define STATE_WAIT_RESPONSE_BIT 1    /* waiting for emulator to give response */

	spinlock_t buf_lock;         /* lock for buffers */

	wait_queue_head_t wq;

	size_t req_len;              /* length of queued TPM request */
	size_t resp_len;             /* length of queued TPM response */
	u8 buffer[TPM_BUFSIZE];      /* request/response buffer */
};


static void vtpm_delete_device_pair(struct vtpm_dev *vtpm_dev);

/*
 * Functions related to 'server side'
 */

/**
 * vtpm_fops_read - Read TPM commands on 'server side'
 *
 * Return value:
 *	Number of bytes read or negative error code
 */
static ssize_t vtpm_fops_read(struct file *filp, char __user *buf,
			      size_t count, loff_t *off)
{
	struct vtpm_dev *vtpm_dev = filp->private_data;
	size_t len;
	int sig, rc;

	sig = wait_event_interruptible(vtpm_dev->wq, vtpm_dev->req_len != 0);
	if (sig)
		return -EINTR;

	spin_lock(&vtpm_dev->buf_lock);

	len = vtpm_dev->req_len;

	if (count < len) {
		spin_unlock(&vtpm_dev->buf_lock);
		pr_debug("Invalid size in recv: count=%zd, req_len=%zd\n",
			 count, len);
		return -EIO;
	}

	rc = copy_to_user(buf, vtpm_dev->buffer, len);
	memset(vtpm_dev->buffer, 0, len);
	vtpm_dev->req_len = 0;

	spin_unlock(&vtpm_dev->buf_lock);

	if (rc)
		return -EFAULT;

	set_bit(STATE_WAIT_RESPONSE_BIT, &vtpm_dev->state);

	return len;
}

/**
 * vtpm_fops_write - Write TPM responses on 'server side'
 *
 * Return value:
 *	Number of bytes read or negative error value
 */
static ssize_t vtpm_fops_write(struct file *filp, const char __user *buf,
			       size_t count, loff_t *off)
{
	struct vtpm_dev *vtpm_dev = filp->private_data;

	if (count > sizeof(vtpm_dev->buffer) ||
	    !test_bit(STATE_WAIT_RESPONSE_BIT, &vtpm_dev->state))
		return -EIO;

	clear_bit(STATE_WAIT_RESPONSE_BIT, &vtpm_dev->state);

	spin_lock(&vtpm_dev->buf_lock);

	vtpm_dev->req_len = 0;

	if (copy_from_user(vtpm_dev->buffer, buf, count)) {
		spin_unlock(&vtpm_dev->buf_lock);
		return -EFAULT;
	}

	vtpm_dev->resp_len = count;

	spin_unlock(&vtpm_dev->buf_lock);

	wake_up_interruptible(&vtpm_dev->wq);

	return count;
}

/*
 * vtpm_fops_poll: Poll status on 'server side'
 *
 * Return value:
 *      Poll flags
 */
static unsigned int vtpm_fops_poll(struct file *filp, poll_table *wait)
{
	struct vtpm_dev *vtpm_dev = filp->private_data;
	unsigned ret;

	poll_wait(filp, &vtpm_dev->wq, wait);

	ret = POLLOUT;
	if (vtpm_dev->req_len)
		ret |= POLLIN | POLLRDNORM;

	return ret;
}

/*
 * vtpm_fops_open - Open vTPM device on 'server side'
 *
 * Called when setting up the anonymous file descriptor
 */
static void vtpm_fops_open(struct file *filp)
{
	struct vtpm_dev *vtpm_dev = filp->private_data;

	set_bit(STATE_OPENED_BIT, &vtpm_dev->state);
}

/**
 * vtpm_fops_undo_open - counter-part to vtpm_fops_open
 *
 * Call to undo vtpm_fops_open
 */
static void vtpm_fops_undo_open(struct vtpm_dev *vtpm_dev)
{
	clear_bit(STATE_OPENED_BIT, &vtpm_dev->state);

	/* no more TPM responses -- wake up anyone waiting for them */
	wake_up_interruptible(&vtpm_dev->wq);
}

/*
 * vtpm_fops_release: Close 'server side'
 *
 * Return value:
 *      Always returns 0.
 */
static int vtpm_fops_release(struct inode *inode, struct file *filp)
{
	struct vtpm_dev *vtpm_dev = filp->private_data;

	filp->private_data = NULL;

	vtpm_delete_device_pair(vtpm_dev);

	return 0;
}

static const struct file_operations vtpm_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.read = vtpm_fops_read,
	.write = vtpm_fops_write,
	.poll = vtpm_fops_poll,
	.release = vtpm_fops_release,
};

/*
 * Functions invoked by the core TPM driver to send TPM commands to
 * 'server side' and receive responses from there.
 */

/*
 * Called when core TPM driver reads TPM responses from 'server side'
 *
 * Return value:
 *      Number of TPM response bytes read, negative error value otherwise
 */
static int vtpm_tpm_op_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct vtpm_dev *vtpm_dev = chip->vendor.priv;
	int sig;
	size_t len;

	if (!vtpm_dev)
		return -EIO;

	/* wait for response or responder gone */
	sig = wait_event_interruptible(vtpm_dev->wq,
		(vtpm_dev->resp_len != 0
		|| !test_bit(STATE_OPENED_BIT, &vtpm_dev->state)));

	if (sig)
		return -EINTR;

	/* process gone ? */
	if (!test_bit(STATE_OPENED_BIT, &vtpm_dev->state))
		return -EPIPE;

	spin_lock(&vtpm_dev->buf_lock);

	len = vtpm_dev->resp_len;
	if (count < len) {
		dev_err(&chip->dev,
			"Invalid size in recv: count=%zd, resp_len=%zd\n",
			count, len);
		len = -EIO;
		goto out;
	}

	memcpy(buf, vtpm_dev->buffer, len);
	vtpm_dev->resp_len = 0;

out:
	spin_unlock(&vtpm_dev->buf_lock);

	return len;
}

/*
 * Called when core TPM driver forwards TPM requests to 'server side'.
 *
 * Return value:
 *      0 in case of success, negative error value otherwise.
 */
static int vtpm_tpm_op_send(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct vtpm_dev *vtpm_dev = chip->vendor.priv;
	int rc = 0;

	if (!vtpm_dev)
		return -EIO;

	if (!test_bit(STATE_OPENED_BIT, &vtpm_dev->state))
		return -EPIPE;

	if (count > sizeof(vtpm_dev->buffer)) {
		dev_err(&chip->dev,
			"Invalid size in send: count=%zd, buffer size=%zd\n",
			count, sizeof(vtpm_dev->buffer));
		return -EIO;
	}

	spin_lock(&vtpm_dev->buf_lock);

	vtpm_dev->resp_len = 0;

	vtpm_dev->req_len = count;
	memcpy(vtpm_dev->buffer, buf, count);

	spin_unlock(&vtpm_dev->buf_lock);

	wake_up_interruptible(&vtpm_dev->wq);

	clear_bit(STATE_WAIT_RESPONSE_BIT, &vtpm_dev->state);

	return rc;
}

static void vtpm_tpm_op_cancel(struct tpm_chip *chip)
{
	/* not supported */
}

static u8 vtpm_tpm_op_status(struct tpm_chip *chip)
{
	return 0;
}

static bool vtpm_tpm_req_canceled(struct tpm_chip  *chip, u8 status)
{
	return (status == 0);
}

static const struct tpm_class_ops vtpm_tpm_ops = {
	.recv = vtpm_tpm_op_recv,
	.send = vtpm_tpm_op_send,
	.cancel = vtpm_tpm_op_cancel,
	.status = vtpm_tpm_op_status,
	.req_complete_mask = 0,
	.req_complete_val = 0,
	.req_canceled = vtpm_tpm_req_canceled,
};

/*
 * Code related to creation and deletion of device pairs
 */
static struct vtpm_dev *vtpm_create_vtpm_dev(void)
{
	struct vtpm_dev *vtpm_dev;
	struct tpm_chip *chip;
	int err;

	vtpm_dev = kzalloc(sizeof(*vtpm_dev), GFP_KERNEL);
	if (vtpm_dev == NULL)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&vtpm_dev->wq);
	spin_lock_init(&vtpm_dev->buf_lock);

	chip = tpm_chip_alloc(NULL, &vtpm_tpm_ops);
	if (IS_ERR(chip)) {
		err = PTR_ERR(chip);
		goto err_vtpm_dev_free;
	}
	chip->vendor.priv = vtpm_dev;
	chip->vendor.irq = 1;

	vtpm_dev->chip = chip;

	return vtpm_dev;

err_vtpm_dev_free:
	kfree(vtpm_dev);

	return ERR_PTR(err);
}

/*
 * Undo what has been done in vtpm_create_vtpm_dev
 */
static inline void vtpm_delete_vtpm_dev(struct vtpm_dev *vtpm_dev)
{
	put_device(&vtpm_dev->chip->dev); /* frees chip */
	kfree(vtpm_dev);
}

/*
 * Create a /dev/tpm%d and 'server side' file descriptor pair
 *
 * Return value:
 *      Returns file pointer on success, an error value otherwise
 */
static struct file *vtpm_create_device_pair(
				       struct vtpm_new_pair *vtpm_new_pair)
{
	struct vtpm_dev *vtpm_dev;
	int rc, fd;
	struct file *file;

	vtpm_dev = vtpm_create_vtpm_dev();
	if (IS_ERR(vtpm_dev))
		return ERR_CAST(vtpm_dev);

	vtpm_dev->flags = vtpm_new_pair->flags;

	/* setup an anonymous file for the server-side */
	fd = get_unused_fd_flags(O_RDWR);
	if (fd < 0) {
		rc = fd;
		goto err_delete_vtpm_dev;
	}

	file = anon_inode_getfile("[vtpms]", &vtpm_fops, vtpm_dev, O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		goto err_put_unused_fd;
	}

	/* from now on we can unwind with put_unused_fd() + fput() */
	/* simulate an open() on the server side */
	vtpm_fops_open(file);

	if (vtpm_dev->flags & VTPM_FLAG_TPM2)
		vtpm_dev->chip->flags |= TPM_CHIP_FLAG_TPM2;

	rc = tpm_chip_register(vtpm_dev->chip);
	if (rc)
		goto err_vtpm_fput;

	vtpm_new_pair->fd = fd;
	vtpm_new_pair->major = MAJOR(vtpm_dev->chip->dev.devt);
	vtpm_new_pair->minor = MINOR(vtpm_dev->chip->dev.devt);
	vtpm_new_pair->tpm_dev_num = vtpm_dev->chip->dev_num;

	return file;

err_vtpm_fput:
	put_unused_fd(fd);
	fput(file);

	return ERR_PTR(rc);

err_put_unused_fd:
	put_unused_fd(fd);

err_delete_vtpm_dev:
	vtpm_delete_vtpm_dev(vtpm_dev);

	return ERR_PTR(rc);
}

/*
 * Counter part to vtpm_create_device_pair.
 */
static void vtpm_delete_device_pair(struct vtpm_dev *vtpm_dev)
{
	tpm_chip_unregister(vtpm_dev->chip);

	vtpm_fops_undo_open(vtpm_dev);

	vtpm_delete_vtpm_dev(vtpm_dev);
}

/*
 * Code related to the control device /dev/vtpmx
 */

/*
 * vtpmx_fops_ioctl: ioctl on /dev/vtpmx
 *
 * Return value:
 *      Returns 0 on success, a negative error code otherwise.
 */
static long vtpmx_fops_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct vtpm_new_pair *vtpm_new_pair_p;
	struct vtpm_new_pair vtpm_new_pair;
	struct file *file;

	switch (ioctl) {
	case VTPM_NEW_DEV:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		vtpm_new_pair_p = argp;
		if (copy_from_user(&vtpm_new_pair, vtpm_new_pair_p,
				   sizeof(vtpm_new_pair)))
			return -EFAULT;
		file = vtpm_create_device_pair(&vtpm_new_pair);
		if (IS_ERR(file))
			return PTR_ERR(file);
		if (copy_to_user(vtpm_new_pair_p, &vtpm_new_pair,
				 sizeof(vtpm_new_pair))) {
			put_unused_fd(vtpm_new_pair.fd);
			fput(file);
			return -EFAULT;
		}

		fd_install(vtpm_new_pair.fd, file);
		return 0;

	default:
		return -EINVAL;
	}
}

#ifdef CONFIG_COMPAT
static long vtpmx_fops_compat_ioctl(struct file *f, unsigned int ioctl,
				    unsigned long arg)
{
	return vtpmx_fops_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vtpmx_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vtpmx_fops_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = vtpmx_fops_compat_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice vtpmx_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vtpmx",
	.fops = &vtpmx_fops,
};

static int vtpmx_init(void)
{
	return misc_register(&vtpmx_miscdev);
}

static void vtpmx_cleanup(void)
{
	misc_deregister(&vtpmx_miscdev);
}

static int __init vtpm_module_init(void)
{
	int rc;

	rc = vtpmx_init();
	if (rc) {
		pr_err("couldn't create vtpmx device\n");
		return rc;
	}

	return 0;
}

static void __exit vtpm_module_exit(void)
{
	vtpmx_cleanup();
}

module_init(vtpm_module_init);
module_exit(vtpm_module_exit);

MODULE_AUTHOR("Stefan Berger (stefanb@us.ibm.com)");
MODULE_DESCRIPTION("vTPM Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
