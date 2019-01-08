#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <i18n/i18n.h>

#include "log/log.h"
#include "talloc/talloc.h"
#include "types/types.h"
#include "parser-conf.h"
#include "parser-utils.h"
#include "resource.h"

struct uboot_state {
	struct discover_boot_option *d_opt;
	const char *image;
	const char *initrd;
	const char *dtb;
	const char *label;
};

static const char *uboot_path_fixup(struct discover_device *dev, const char *path)
{
	int len = strlen(dev->mount_path);

	if (!strncmp(path, dev->mount_path, len))
		return path + len + 1;

	return path;
}

static void uboot_finish(struct conf_context *conf)
{
	struct uboot_state *state = conf->parser_info;
	struct discover_boot_option *d_opt;
	struct boot_option *opt;


	if (!state->d_opt)
		return;

	d_opt = state->d_opt;
	opt = d_opt->option;
	assert(opt);
	assert(opt->name);
	assert(opt->boot_args);

	if (state->image) {
		d_opt->boot_image = create_devpath_resource(d_opt,
				conf->dc->device,
				uboot_path_fixup(conf->dc->device, state->image));

		/* FIXME: necessary? */
		char* args_sigfile_default = talloc_asprintf(d_opt,
				"%s.cmdline.sig", state->image);
		d_opt->args_sig_file = create_devpath_resource(d_opt,
				conf->dc->device, args_sigfile_default);
		talloc_free(args_sigfile_default);
	}

	if (state->initrd) {
		d_opt->initrd = create_devpath_resource(d_opt,
				conf->dc->device,
				uboot_path_fixup(conf->dc->device, state->initrd));
	}

	if (state->dtb) {
		d_opt->dtb = create_devpath_resource(d_opt,
				conf->dc->device,
				uboot_path_fixup(conf->dc->device, state->dtb));
	}

	if (state->label) {
		d_opt->option->id = talloc_asprintf(d_opt->option, "%s#%s",
				conf->dc->device->device->id, state->label);
		d_opt->option->name = talloc_strdup(d_opt->option, state->label);
	} else {
		d_opt->option->name = talloc_strdup(d_opt->option, "NOLABEL");
		d_opt->option->id = talloc_asprintf(d_opt->option, "%s@%p",
				conf->dc->device->device->id, d_opt);
	}

	opt->description = talloc_strdup(opt, "ODROID");

	conf_strip_str(opt->boot_args);
	conf_strip_str(opt->description);

	discover_context_add_boot_option(conf->dc, state->d_opt);
}

static void uboot_process_pair(struct conf_context *conf, const char *name,
		char *value)
{
	struct uboot_state *state = conf->parser_info;
	struct discover_boot_option *d_opt = state->d_opt;

	if (!name)
		return;

	/* image */
	if (streq(name, "IMAGE")) {
		if (!d_opt) {
			d_opt = discover_boot_option_create(conf->dc, conf->dc->device);
			state->d_opt = d_opt;
		}

		state->image = talloc_strdup(state, value);
		return;
	}

	/* initrd */
	if (streq(name, "INITRD")) {
		state->initrd = talloc_strdup(state, value);
		return;
	}

	/* device tree */
	if (streq(name, "DTB")) {
		state->dtb = talloc_strdup(state, value);
		return;
	}

	/* args */
	if (streq(name, "APPEND")) {
		if (d_opt->option->boot_args)
			d_opt->option->boot_args = talloc_asprintf_append(
					d_opt->option->boot_args, " %s", value);
		else
			d_opt->option->boot_args = talloc_strdup(d_opt->option, value);
		return;
	}

	/* label */
	if (streq(name, "LABEL")) {
		state->label = talloc_strdup(state, value);
		return;
	}

	pb_debug("%s: unknown name: %s\n", __func__, name);
}

static int uboot_request_file(struct discover_context *ctx,
		struct discover_device *dev, const char *filename,
		char **buf, int *len)
{
	int ret;
	int pipefd[2];
	char rbuf[1024];
	char *stream = NULL;
	int status;
	FILE *f;
	char *path = talloc_asprintf(ctx, "%s/%s", dev->mount_path, filename);

	if (access(path, R_OK) < 0)
		return -errno;

	ret = pipe(pipefd);
	if (ret < 0) {
		pb_debug("%s,%d -- Error to create a pipe", __func__, __LINE__);
		exit(-1);
	}

	ret = fork();
	if (ret < 0) {
		pb_debug("%s,%d -- Failed to fork", __func__, __LINE__);
		exit (-1);
	}

	if (ret == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);

		execl("/usr/bin/uboot-parser", "uboot-parser", path, NULL);
		_exit(1);
	}

	close(pipefd[1]);

	f = fdopen(pipefd[0], "r");
	while (fgets(rbuf, sizeof(rbuf), f))
		stream = talloc_asprintf_append(stream, "%s", rbuf);

	fclose(f);

	*buf = stream;
	*len = strlen(stream);

	wait(&status);

	return 0;
}

static const char *const uboot_conf_files[] = {
	"/boot.ini",
	"/boot.scr",
	NULL
};

static int uboot_parse(struct discover_context *dc)
{
	const char * const *filename;
	struct conf_context *conf;
	int len, rc;
	char *buf;

	/* Support block device boot only at present */
	if (dc->event)
		return -1;

	conf = talloc_zero(dc, struct conf_context);

	if (!conf)
		return -1;

	conf->dc = dc;
	conf->global_options = NULL;
	conf_init_global_options(conf);
	conf->get_pair = conf_get_pair_equal;
	conf->process_pair = uboot_process_pair;
	conf->finish = uboot_finish;
	conf->parser_info = talloc_zero(conf, struct uboot_state);

	for (filename = uboot_conf_files; *filename; filename++) {
		rc = uboot_request_file(dc, dc->device, *filename, &buf, &len);
		if (rc)
			continue;

		conf_parse_buf(conf, buf, len);
		device_handler_status_dev_info(dc->handler, dc->device,
				_("Parsed U-boot script from %s"),
				*filename);
		talloc_free(buf);
	}

	talloc_free(conf);
	return 0;
}

static struct parser uboot_parser = {
	.name			= "uboot",
	.parse			= uboot_parse,
	.resolve_resource	= resolve_devpath_resource,
};

register_parser(uboot_parser);
