// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/tpm.h>

int of_tpm_get_sml_parameters(struct device_node *np, u64 *base, u32 *size)
{
	const u32 *sizep;
	const u64 *basep;

	sizep = of_get_property(np, "linux,sml-size", NULL);
	basep = of_get_property(np, "linux,sml-base", NULL);
	if (sizep == NULL && basep == NULL)
		return -ENODEV;
	if (sizep == NULL || basep == NULL)
		return -EIO;

	if (of_property_match_string(np, "compatible", "IBM,vtpm") < 0 &&
	    of_property_match_string(np, "compatible", "IBM,vtpm20") < 0) {
		*size = be32_to_cpup((__force __be32 *)sizep);
		*base = be64_to_cpup((__force __be64 *)basep);
	} else {
		*size = *sizep;
		*base = *basep;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(of_tpm_get_sml_parameters);
