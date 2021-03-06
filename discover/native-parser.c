/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "parser.h"
#include "params.h"
#include "paths.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *conf_filename = "/boot/petitboot.conf";

static struct boot_option *cur_opt;
static struct device *dev;
static const char *devpath;
static int device_added;

static int check_and_add_device(struct device *dev)
{
	if (!dev->icon_file)
		dev->icon_file = strdup(generic_icon_file(guess_device_type()));

	return !add_device(dev);
}

static int section(char *section_name)
{
	if (!device_added++ && !check_and_add_device(dev))
		return 0;

	if (cur_opt) {
		add_boot_option(cur_opt);
		free_boot_option(cur_opt);
	}

	cur_opt = malloc(sizeof(*cur_opt));
	memset(cur_opt, 0, sizeof(*cur_opt));
	return 1;
}


static void set_boot_option_parameter(struct boot_option *opt,
		const char *name, const char *value)
{
	if (streq(name, "name"))
		opt->name = strdup(value);

	else if (streq(name, "description"))
		opt->description = strdup(value);

	else if (streq(name, "image"))
		opt->boot_image_file = resolve_path(value, devpath);

	else if (streq(name, "icon"))
		opt->icon_file = resolve_path(value, devpath);

	else if (streq(name, "initrd"))
		opt->initrd_file =resolve_path(value, devpath);

	else if (streq(name, "args"))
		opt->boot_args = strdup(value);

	else
		fprintf(stderr, "Unknown parameter %s\n", name);
}

static void set_device_parameter(struct device *dev,
		const char *name, const char *value)
{
	if (streq(name, "name"))
		dev->name = strdup(value);

	else if (streq(name, "description"))
		dev->description = strdup(value);

	else if (streq(name, "icon"))
		dev->icon_file = resolve_path(value, devpath);
}

static int parameter(char *param_name, char *param_value)
{
	if (cur_opt)
		set_boot_option_parameter(cur_opt, param_name, param_value);
	else
		set_device_parameter(dev, param_name, param_value);
	return 1;
}


static int native_parse(const char *device)
{
	char *filepath;
	int rc;

	filepath = resolve_path(conf_filename, device);

	cur_opt = NULL;
	dev = malloc(sizeof(*dev));
	memset(dev, 0, sizeof(*dev));
	dev->id = strdup(device);

	rc = pm_process(filepath, section, parameter);
	if (!rc)
		return 0;

	if (cur_opt) {
		add_boot_option(cur_opt);
		free_boot_option(cur_opt);
	}

	cur_opt = NULL;

	free(filepath);

	return 1;
}

define_parser(native, native_parse);
