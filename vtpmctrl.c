/*
 * vtpmctrl.c -- Linux vTPM driver control program
 *
 * (c) Copyright IBM Corporation 2015.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <linux/vtpm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

void vtpmctrl_create_usage(const char *prgname)
{
	fprintf(stderr,
"Usage: %s create [options]\n"
"\n"
"Create a client server device pair."
"\n"
"The following options are supported\n"
"\n"
"-k|--keep    : Keep the device pair after the vTPM closes access to the\n"
"               device; by default the device is closed.\n"
"-h|--help    : Display this help screen and exit.\n"
"\n", prgname);
}

int vtpmctrl_create(int argc, char *argv[], const char *prgname)
{
	int fd, n;
	struct vtpm_new_pair vtpm_new_pair = {
		.flags = 0,
	};
	char tpmdev[VTPM_DEVNAME_MAX + 5];
	char vtpmdev[VTPM_DEVNAME_MAX + 5];
	const struct option longOpts[] = {
		{"keep",  no_argument, NULL, 'k'},
		{"help",  no_argument, NULL, 'h'},
		{NULL  ,  0,           0,    0  },
	};
	int option, li;

	while ((option = getopt_long(argc, argv, "kh", longOpts, &li)) >= 0) {
		switch (option) {
		case 'k':
			vtpm_new_pair.flags |= VTPM_FLAG_KEEP_DEVPAIR;
			break;
		case 'h':
			vtpmctrl_create_usage(prgname);
			return 0;
		default:
			vtpmctrl_create_usage(prgname);
			return 1;
		}
	}

	fd = open("/dev/vtpmx", O_RDWR);
	if (fd < 0) {
		perror("Could not open /dev/vtpmx");
		return 1;
	}

	n = ioctl(fd, VTPM_NEW_DEV, &vtpm_new_pair);
	if (n != 0) {
		perror("ioctl to create dev pair failed");
		close(fd);
		return 1;
	}

	snprintf(tpmdev, sizeof(tpmdev), "/dev/" VTPM_DEV_PREFIX_CLIENT"%u",
	         vtpm_new_pair.tpm_dev_num);
	snprintf(vtpmdev, sizeof(vtpmdev), "/dev/" VTPM_DEV_PREFIX_SERVER"%u",
	         vtpm_new_pair.vtpm_dev_num);

	printf("Created TPM device %s and vTPM device %s.\n",
	       tpmdev, vtpmdev);

	close(fd);

	return 0;
}

int copy_devname(char *dest, size_t size, const char *devname)
{
	int n;

	n = snprintf(dest, size, "%s", devname);
	if (n >= size) {
		fprintf(stderr, "Device name %s is too long.\n", devname);
		return 1;
	}

	return 0;
}

void vtpmctrl_destroy_usage(const char *prgname)
{
	fprintf(stderr,
"Usage: %s destroy <devicename> [options]\n"
"\n"
"Destroy a client server device pair by providing the name of one of\n"
"the devices.\n"
"\n"
"The following options are supported\n"
"\n"
"-h|--help    : Display this help screen and exit.\n"
"\n", prgname);
}

int fill_vtpm_pair(struct vtpm_pair *vtpm_pair, const char *devname)
{
	unsigned int offset = 0, num;
	int n;

	if (!strncmp("/dev/", devname, 5))
		offset = 5;

	if (!strncmp(&devname[offset], VTPM_DEV_PREFIX_SERVER,
	     strlen(VTPM_DEV_PREFIX_SERVER))) {
		offset += strlen(VTPM_DEV_PREFIX_SERVER);
		if (sscanf(&devname[offset], "%u", &num) != 1) {
			fprintf(stderr, "Could not parse %s as vTPM "
				"device.\n", devname);
			return -1;
		}
		vtpm_pair->tpm_dev_num = VTPM_DEV_NUM_INVALID;
		vtpm_pair->vtpm_dev_num = num;
		return 0;
	} else if (!strncmp(&devname[offset], VTPM_DEV_PREFIX_CLIENT,
			    strlen(VTPM_DEV_PREFIX_CLIENT))) {
		offset += strlen(VTPM_DEV_PREFIX_CLIENT);
		if (sscanf(&devname[offset], "%u", &num) != 1) {
			fprintf(stderr, "Could not parse %s as vTPM "
				"device.\n", devname);
			return -1;
		}
		vtpm_pair->tpm_dev_num = num;
		vtpm_pair->vtpm_dev_num = VTPM_DEV_NUM_INVALID;
		return 0;
	}
	fprintf(stderr , "Could not parse %s.\n", devname);

	return -1;
}

int vtpmctrl_destroy(int argc, char *argv[], const char *prgname)
{
	int fd = -1, n;
	struct vtpm_pair vtpm_pair;
	const char *devname;
	unsigned offset = 0;
	size_t size;
	const struct option longOpts[] = {
		{"help",  no_argument, NULL, 'h'},
		{NULL  ,  0,           0,    0  },
	};
	int option, li;

	while ((option = getopt_long(argc, argv, "h", longOpts, &li)) >= 0) {
		switch (option) {
		case 'h':
			vtpmctrl_destroy_usage(prgname);
			return 0;
		default:
			vtpmctrl_destroy_usage(prgname);
			return 1;
		}
	}

	if (argc < 2) {
		fprintf(stderr, "Missing device name parameter.\n");
		vtpmctrl_destroy_usage(prgname);
		goto err_exit;
	}

	devname = argv[1];

	fd = open("/dev/vtpmx", O_RDWR);
	if (fd < 0) {
		perror("Could not open /dev/vtpmx");
		goto err_exit;
	}

	if (fill_vtpm_pair(&vtpm_pair, devname) < 0)
		goto err_exit;

	n = ioctl(fd, VTPM_DEL_DEV, &vtpm_pair);
	if (n != 0) {
		fprintf(stderr, "Could not delete device pair.\n");
		goto err_exit;
	}

	fprintf(stdout, "Successfully deleted device pair.\n");

	close(fd);

	return 0;

err_exit:
	if (fd >= 0)
		close(fd);
	return 1;
}

void vtpmctrl_find_usage(const char *prgname)
{
	fprintf(stderr,
"Usage: %s find <devicename> [options]\n"
"\n"
"Given one device name, determine the name of the other one.\n"
"\n"
"The following options are supported\n"
"\n"
"-h|--help    : Display this help screen and exit.\n"
"\n", prgname);
}

int vtpmctrl_find(int argc, char *argv[], const char *prgname)
{
	int fd = -1, n;
	struct vtpm_pair vtpm_pair;
	const char *devname;
	unsigned offset = 0;
	size_t size;
	const struct option longOpts[] = {
		{"help",  no_argument, NULL, 'h'},
		{NULL  ,  0,           0,    0  },
	};
	int option, li;
	char tpmdev[VTPM_DEVNAME_MAX + 5];

	while ((option = getopt_long(argc, argv, "h", longOpts, &li)) >= 0) {
		switch (option) {
		case 'h':
			vtpmctrl_find_usage(prgname);
			return 0;

		default:
			vtpmctrl_find_usage(prgname);
			return 1;
		}
	}

	if (argc < 2) {
		fprintf(stderr, "Missing device name parameter.\n");
		vtpmctrl_destroy_usage(prgname);
		goto err_exit;
	}

	devname = argv[1];

	fd = open("/dev/vtpmx", O_RDWR);
	if (fd < 0) {
		perror("Could not open /dev/vtpmx");
		goto err_exit;
	}

	if (fill_vtpm_pair(&vtpm_pair, devname) < 0)
		goto err_exit;

	if (vtpm_pair.tpm_dev_num != VTPM_DEV_NUM_INVALID) {
		n = ioctl(fd, VTPM_GET_VTPMDEV, &vtpm_pair);
		if (n != 0) {
			fprintf(stderr, "Could not find the other device of the device pair.\n");
			goto err_exit;
		} else {
			snprintf(tpmdev, sizeof(tpmdev), "/dev/"VTPM_DEV_PREFIX_SERVER"%u",
				 vtpm_pair.vtpm_dev_num);
			fprintf(stdout, "The name of the vTPM device is: %s\n", tpmdev);
		}
	} else {
		n = ioctl(fd, VTPM_GET_TPMDEV, &vtpm_pair);
		if (n != 0) {
			fprintf(stderr, "Could not find the other device of the device pair.\n");
			goto err_exit;
		} else {
			snprintf(tpmdev, sizeof(tpmdev), "/dev/"VTPM_DEV_PREFIX_CLIENT"%u",
				 vtpm_pair.tpm_dev_num);
			fprintf(stdout, "The name of the TPM device is: %s\n", tpmdev);
		}
	}


	close(fd);

	return 0;

err_exit:
	if (fd >= 0)
		close(fd);
	return 1;
}

void main_usage(const char *prgname)
{
	fprintf(stdout,
"Usage: %s [command] [options]\n"
"\n"
"Control vTPM devices.\n"
"\n"
"The following commands are supported.\n"
"\n"
"create   : Create device pairs\n"
"destroy  : Destroy device pairs\n"
"find     : Find the names of device pairs\n"
"\n"
"Consult the help screens of the individual commands for supported options.\n"
"\n"
, prgname);
}

int main(int argc, char *argv[])
{

	if (argc < 2) {
		fprintf(stderr, "Missing command parameter.\n");
		return 1;
	}

	if (!strcmp(argv[1], "create")) {
		return vtpmctrl_create(argc - 1, &argv[1], argv[0]);
	} else if (!strcmp(argv[1], "destroy")) {
		return vtpmctrl_destroy(argc - 1, &argv[1], argv[0]);
	} else if (!strcmp(argv[1], "find")) {
		return vtpmctrl_find(argc - 1, &argv[1], argv[0]);
	} else {
		fprintf(stderr, "Unsupported command.\n\n");
		main_usage(argv[0]);
		return 1;
	}
}
