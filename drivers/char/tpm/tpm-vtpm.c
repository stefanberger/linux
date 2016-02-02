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
#include <linux/list.h>
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
	struct device dev;

	struct tpm_chip *chip;

	u32 flags;                   /* public API flags */

	int dev_num;

	long state;
#define STATE_OPENED_BIT   0
#define STATE_INIT_VTPM    1

	spinlock_t buf_lock;         /* lock for buffers */

	wait_queue_head_t wq;

	size_t req_len;              /* length of queued TPM request */
	u8 req_buf[TPM_BUFSIZE];     /* request buffer */

	size_t resp_len;             /* length of queued TPM response */
	u8 resp_buf[TPM_BUFSIZE];    /* response buffer */

	struct work_struct work;     /* task that retrieves TPM timeouts */

	struct list_head list;
};

static DECLARE_BITMAP(dev_mask, VTPM_NUM_DEVICES);
static LIST_HEAD(vtpm_list);
static DEFINE_SPINLOCK(driver_lock);

static struct class *vtpm_class;

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

	len = vtpm_dev->req_len;

	if (count < len) {
		dev_err(&vtpm_dev->dev,
			"Invalid size in recv: count=%zd, req_len=%zd\n",
			count, len);
		return -EIO;
	}

	spin_lock(&vtpm_dev->buf_lock);

	rc = copy_to_user(buf, vtpm_dev->req_buf, len);
	memset(vtpm_dev->req_buf, 0, len);
	vtpm_dev->req_len = 0;

	spin_unlock(&vtpm_dev->buf_lock);

	if (rc)
		return -EFAULT;

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

	if (count > sizeof(vtpm_dev->resp_buf))
		return -EIO;

	spin_lock(&vtpm_dev->buf_lock);

	vtpm_dev->req_len = 0;

	if (copy_from_user(vtpm_dev->resp_buf, buf, count)) {
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
	struct vtpm_dev *vtpm_dev = chip->priv;
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
		return -EIO;

	len = vtpm_dev->resp_len;
	if (count < len) {
		dev_err(&vtpm_dev->dev,
			"Invalid size in recv: count=%zd, resp_len=%zd\n",
			count, len);
		return -EIO;
	}

	spin_lock(&vtpm_dev->buf_lock);

	memcpy(buf, vtpm_dev->resp_buf, len);
	vtpm_dev->resp_len = 0;

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
	struct vtpm_dev *vtpm_dev = chip->priv;
	int rc = 0;

	if (!vtpm_dev)
		return -EIO;

	if (!test_bit(STATE_OPENED_BIT, &vtpm_dev->state))
		return -EINVAL;

	if (count > sizeof(vtpm_dev->req_buf)) {
		dev_err(&vtpm_dev->dev,
			"Invalid size in send: count=%zd, buffer size=%zd\n",
			count, sizeof(vtpm_dev->req_buf));
		return -EIO;
	}

	spin_lock(&vtpm_dev->buf_lock);

	vtpm_dev->resp_len = 0;

	vtpm_dev->req_len = count;
	memcpy(vtpm_dev->req_buf, buf, count);

	spin_unlock(&vtpm_dev->buf_lock);

	/* sync for first startup command */
	set_bit(STATE_INIT_VTPM, &vtpm_dev->state);

	wake_up_interruptible(&vtpm_dev->wq);

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
 * Code related to the startup of the TPM 2 and startup of TPM 1.2 +
 * retrieval of timeouts and durations.
 */

static void vtpm_dev_work(struct work_struct *work)
{
	struct vtpm_dev *vtpm_dev = container_of(work, struct vtpm_dev, work);

	if (vtpm_dev->flags & VTPM_FLAG_TPM2)
		tpm2_startup(vtpm_dev->chip, TPM2_SU_CLEAR);
	else {
		/* we must send TPM_Startup() first */
		tpm_startup(vtpm_dev->chip, TPM_ST_CLEAR);
		tpm_get_timeouts(vtpm_dev->chip);
	}
}

/*
 * vtpm_dev_start_work: Schedule the work for TPM 1.2 & 2 initialization
 */
static int vtpm_dev_start_work(struct vtpm_dev *vtpm_dev)
{
	int sig;

	INIT_WORK(&vtpm_dev->work, vtpm_dev_work);
	schedule_work(&vtpm_dev->work);

	/* make sure we send the 1st command before user space can */
	sig = wait_event_interruptible(vtpm_dev->wq,
		test_bit(STATE_INIT_VTPM, &vtpm_dev->state));
	if (sig) {
		cancel_work_sync(&vtpm_dev->work);
		return -EINTR;
	}
	return 0;
}

/*
 * vtpm_dev_stop_work: prevent the scheduled work from running
 */
static void vtpm_dev_stop_work(struct vtpm_dev *vtpm_dev)
{
	cancel_work_sync(&vtpm_dev->work);
}

/*
 * Code related to creation and deletion of device pairs
 */
static void vtpm_dev_release(struct device *dev)
{
	struct vtpm_dev *vtpm_dev = container_of(dev, struct vtpm_dev, dev);

	spin_lock(&driver_lock);
	clear_bit(vtpm_dev->dev_num, dev_mask);
	spin_unlock(&driver_lock);

	kfree(vtpm_dev);
}

static struct device_driver vtpm_driver = {
	.name = "tpm-vtpm",
	.owner = THIS_MODULE,
};

struct vtpm_dev *vtpm_create_vtpm_dev(void)
{
	struct vtpm_dev *vtpm_dev;
	int err;

	vtpm_dev = kzalloc(sizeof(*vtpm_dev), GFP_KERNEL);
	if (vtpm_dev == NULL)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&vtpm_dev->wq);
	spin_lock_init(&vtpm_dev->buf_lock);

	spin_lock(&driver_lock);
	vtpm_dev->dev_num = find_first_zero_bit(dev_mask, VTPM_NUM_DEVICES);

	if (vtpm_dev->dev_num >= VTPM_NUM_DEVICES) {
		spin_unlock(&driver_lock);
		kfree(vtpm_dev);
		return ERR_PTR(-ENOMEM);
	}

	/* device is needed for core TPM driver */
	vtpm_dev->dev.class = vtpm_class;
	vtpm_dev->dev.release = vtpm_dev_release;
	vtpm_dev->dev.driver = &vtpm_driver;
	dev_set_name(&vtpm_dev->dev, "vtpms%d", vtpm_dev->dev_num);

	err = device_register(&vtpm_dev->dev); /* does get_device */
	if (err) {
		spin_unlock(&driver_lock);
		kfree(vtpm_dev);
		return ERR_PTR(err);
	}

	set_bit(vtpm_dev->dev_num, dev_mask);

	spin_unlock(&driver_lock);

	return vtpm_dev;
}

/*
 * Undo what has been done in vtpm_create_vtpm_dev
 */
void vtpm_delete_vtpm_dev(struct vtpm_dev *vtpm_dev)
{
	device_unregister(&vtpm_dev->dev); /* does put_device */
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
	struct tpm_chip *chip;

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

	spin_lock(&driver_lock);
	list_add_rcu(&vtpm_dev->list, &vtpm_list);
	spin_unlock(&driver_lock);

	/* from now on we can unwind with put_unused_fd() + fput() */
	/* simulate an open() on the server side */
	vtpm_fops_open(file);

	chip = tpmm_chip_alloc(&vtpm_dev->dev, &vtpm_tpm_ops);
	if (IS_ERR(chip)) {
		rc = PTR_ERR(chip);
		goto err_vtpm_fput;
	}

	chip->priv = vtpm_dev;

	if (vtpm_dev->flags & VTPM_FLAG_TPM2)
		chip->flags |= TPM_CHIP_FLAG_TPM2;

	rc = tpm_chip_register(chip);
	if (rc) {
		tpm_chip_free(chip);
		goto err_vtpm_fput;
	}
	vtpm_dev->chip = chip;

	rc = vtpm_dev_start_work(vtpm_dev);
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
	vtpm_dev_stop_work(vtpm_dev);

	spin_lock(&driver_lock);
	list_del_rcu(&vtpm_dev->list);
	spin_unlock(&driver_lock);

	synchronize_rcu();

	if (vtpm_dev->chip)
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

	vtpm_class = class_create(THIS_MODULE, "vtpm");
	if (IS_ERR(vtpm_class)) {
		pr_err("couldn't create vtpm class\n");
		return PTR_ERR(vtpm_class);
	}

	rc = vtpmx_init();
	if (rc) {
		pr_err("couldn't create vtpmx device\n");
		goto err_vtpmx;
	}

	return 0;

err_vtpmx:
	class_destroy(vtpm_class);

	return rc;
}

static void __exit vtpm_module_exit(void)
{
	vtpmx_cleanup();
	class_destroy(vtpm_class);
}

module_init(vtpm_module_init);
module_exit(vtpm_module_exit);

MODULE_AUTHOR("Stefan Berger (stefanb@us.ibm.com)");
MODULE_DESCRIPTION("vTPM Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
