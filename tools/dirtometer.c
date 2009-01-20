/*
 * dirtometer - Shows present and dirty chunks in a parcel's local cache
 *
 * Copyright (C) 2008 Carnegie Mellon University
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <glib.h>
#include "nexus.h"

#define CONFIG_GROUP "dirtometer"
#define NOUTPUTS 2

struct stat_values {
	long i[NOUTPUTS];
	double f;
};

struct stat_output {
	const char *tooltip;
	char *(*format)(struct stat_values *values, int which);
	gboolean (*changed)(struct stat_values *prev, struct stat_values *cur,
				int which);
	GtkWidget *ebox;
	GtkWidget *label;
};

struct stats {
	const char *heading;
	const char *attrs[NOUTPUTS];
	gboolean (*fetch)(struct stats *);
	struct stat_output output[NOUTPUTS];
	struct stat_values cur;
	struct stat_values prev;
};

struct pane {
	const char *config_key;
	const char *frame_label;
	const char *menu_label;
	gboolean initial;
	unsigned accel;
	GtkWidget *widget;
	GtkWidget *checkbox;
	int width;
	int height;
} panes[] = {
	{"show_stats",	"Statistics",	"Show statistics",	TRUE,	GDK_s},
	{"show_nexus",	"Nexus states",	"Show Nexus states",	FALSE,	GDK_n},
	{"show_bitmap",	"Chunk bitmap",	"Show chunk bitmap",	TRUE,	GDK_c},
	{NULL}
};

#define NEXUS_STATE(x) #x,
char *state_names[]={
	NEXUS_STATES
};
#undef NEXUS_STATE
#define NR_STATES ((int)(sizeof(state_names) / sizeof(state_names[0])))

GtkWidget *wd;
GtkWidget *img;
GtkWidget *state_lbl[NR_STATES];
GtkWidget *always_on_top;

const char *uuid;
const char *name;
const char *confdir;
const char *conffile;
const char *statsdir;

GKeyFile *config;
int state_fd;
char *states;
int numchunks;
int chunks_per_mb;
int img_width;
gboolean mapped;

void die(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "dirtometer: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

#define max(a, b) ((a) > (b) ? (a) : (b))

void read_config(void)
{
	GError *err = NULL;
	struct pane *pane;

	config = g_key_file_new();
	g_key_file_load_from_file(config, conffile, 0, NULL);

	g_key_file_get_integer(config, CONFIG_GROUP, "width", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_integer(config, CONFIG_GROUP, "width", 0);
	}

	g_key_file_get_integer(config, CONFIG_GROUP, "height", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_integer(config, CONFIG_GROUP, "height", 0);
	}

	g_key_file_get_boolean(config, CONFIG_GROUP, "keep_above", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_boolean(config, CONFIG_GROUP, "keep_above",
					TRUE);
	}

	for (pane = panes; pane->config_key != NULL; pane++) {
		g_key_file_get_boolean(config, CONFIG_GROUP, pane->config_key,
					&err);
		if (err) {
			g_clear_error(&err);
			g_key_file_set_boolean(config, CONFIG_GROUP,
					pane->config_key, pane->initial);
		}
	}
}

void write_config(void)
{
	GError *err = NULL;
	char *contents;
	gsize length;

	if (!g_file_test(confdir, G_FILE_TEST_IS_DIR) &&
				mkdir(confdir, 0777)) {
		fprintf(stderr, "Couldn't create directory %s\n", confdir);
		return;
	}
	contents = g_key_file_to_data(config, &length, &err);
	if (err) {
		fprintf(stderr, "Couldn't write config file: %s\n",
					err->message);
		g_clear_error(&err);
		return;
	}
	if (!g_file_set_contents(conffile, contents, length, &err))
		fprintf(stderr, "Couldn't write config file: %s\n",
					err->message);
	g_clear_error(&err);
	g_free(contents);
}

char *get_attr(const char *attr)
{
	char *path;
	char *data;
	gboolean ok;

	path = g_strdup_printf("%s/%s", statsdir, attr);
	ok = g_file_get_contents(path, &data, NULL, NULL);
	g_free(path);
	if (!ok)
		return NULL;
	g_strchomp(data);
	return data;
}

gboolean get_ints(struct stats *st)
{
	char *data;
	char *end;
	int i;
	gboolean success = TRUE;

	for (i = 0; i < NOUTPUTS; i++) {
		if (st->attrs[i] == NULL)
			continue;
		data = get_attr(st->attrs[i]);
		if (data == NULL)
			return FALSE;
		st->cur.i[i] = strtol(data, &end, 10);
		if (data[0] == 0 || end[0] != 0)
			success = FALSE;
		g_free(data);
	}
	return success;
}

gboolean get_float(struct stats *st)
{
	char *data;
	char *end;
	gboolean success = TRUE;

	data = get_attr(st->attrs[0]);
	if (data == NULL)
		return FALSE;
	st->cur.f = strtod(data, &end);
	if (data[0] == 0 || end[0] != 0)
		success = FALSE;
	g_free(data);
	return success;
}

gboolean get_chunkstats(struct stats *st)
{
	int i;

	st->cur.i[0] = 0;
	st->cur.i[1] = 0;
	for (i = 0; i < numchunks; i++) {
		if (states[i] & 0x4) {
			/* Accessed this session */
			st->cur.i[0]++;
		}
		if (states[i] & 0x8) {
			/* Dirtied this session */
			st->cur.i[1]++;
		}
	}
	return TRUE;
}

char *format_sectors(struct stat_values *values, int which)
{
	return g_strdup_printf("%.1f", 1.0 * values->i[which] / (1 << 11));
}

char *format_chunks(struct stat_values *values, int which)
{
	return g_strdup_printf("%.1f", 1.0 * values->i[which] /
						chunks_per_mb);
}

char *format_compression(struct stat_values *values, int which)
{
	return g_strdup_printf("%.1f%%", 100 - values->f);
}

char *format_hit_rate(struct stat_values *values, int which)
{
	long hits = values->i[0];
	long misses = values->i[1];
	return g_strdup_printf("%.1f%%", 100.0 * hits / (hits + misses));
}

gboolean int_changed(struct stat_values *prev, struct stat_values *cur,
				int which)
{
	return prev->i[which] != cur->i[which];
}

struct stats statistics[] = {
	{
		"Guest",
		{"sectors_read", "sectors_written"},
		get_ints,
		{{"Data read by guest OS this session (MB)",
			format_sectors, int_changed},
		{"Data written by guest OS this session (MB)",
			format_sectors, int_changed}}
	}, {
		"Nexus",
		{"chunk_reads", "chunk_writes"},
		get_ints,
		{{"Chunk data read by Nexus this session (MB)",
			format_chunks, int_changed},
		{"Chunk data written by Nexus this session (MB)",
			format_chunks, int_changed}}
	}, {
		"State",
		{NULL},
		get_chunkstats,
		{{"Chunks accessed this session (MB)",
			format_chunks, int_changed},
		{"Chunks dirtied this session (MB)",
			format_chunks, int_changed}}
	}, {
		"Savings",
		{"compression_ratio_pct"},
		get_float,
		{{NULL},
		{"Average compression savings from chunks written this session",
			format_compression, NULL}}
	}, {
		"Hit",
		{"cache_hits", "cache_misses"},
		get_ints,
		{{NULL},
		{"Nexus chunk cache hit rate",
			format_hit_rate, NULL}}
	}, {0}
};

void update_label(GtkLabel *lbl, const char *val)
{
	if (strcmp(gtk_label_get_label(lbl), val))
		gtk_label_set_label(lbl, val);
}

void stat_output_set_changed(struct stat_output *output, gboolean changed)
{
	const GdkColor busy = {
		.red = 65535,
		.green = 16384,
		.blue = 16384
	};
	GtkStyle *style;
	gboolean prev;

	style = gtk_widget_get_style(output->ebox);
	prev = gdk_color_equal(&busy, &style->bg[GTK_STATE_NORMAL]);
	if (prev != changed)
		gtk_widget_modify_bg(output->ebox, GTK_STATE_NORMAL,
					changed ? &busy : NULL);
}

void update_stat_valid(struct stats *st)
{
	struct stat_output *output;
	int i;
	char *str;
	gboolean changed;

	for (i = 0; i < NOUTPUTS; i++) {
		output = &st->output[i];
		if (output->format == NULL)
			continue;
		str = output->format(&st->cur, i);
		update_label(GTK_LABEL(output->label), str);
		g_free(str);
		if (output->changed != NULL) {
			changed = output->changed(&st->prev, &st->cur, i);
			stat_output_set_changed(output, changed);
		}
	}
}

void update_stat_invalid(struct stats *st)
{
	struct stat_output *output;
	int i;

	for (i = 0; i < NOUTPUTS; i++) {
		output = &st->output[i];
		if (output->changed != NULL)
			stat_output_set_changed(output, FALSE);
	}
}

void update_stats(void)
{
	struct stats *st;
	gboolean visible;

	visible = mapped && g_key_file_get_boolean(config, CONFIG_GROUP,
				"show_stats", NULL);
	for (st = statistics; st->heading != NULL; st++) {
		if (st->fetch(st)) {
			if (visible)
				update_stat_valid(st);
			st->prev = st->cur;
		} else {
			if (visible)
				update_stat_invalid(st);
		}
	}
}

void update_states(void)
{
	char *data;
	char **vals;
	int i;

	if (!mapped || !g_key_file_get_boolean(config, CONFIG_GROUP,
				"show_nexus", NULL))
		return;
	data = get_attr("states");
	if (data == NULL)
		return;
	vals = g_strsplit(data, " ", 0);
	if (g_strv_length(vals) == NR_STATES)
		for (i = 0; i < NR_STATES; i++)
			update_label(GTK_LABEL(state_lbl[i]), vals[i]);
	g_strfreev(vals);
	g_free(data);
}

void free_pixels(unsigned char *pixels, void *data)
{
	g_free(pixels);
}

int optimal_height(int width)
{
	return (numchunks + width - 1) / width;
}

void update_img(void)
{
	static char *prev_states;
	static int last_width;
	static int last_height;
	uint32_t *pixels;
	int numpixels;
	GdkPixbuf *pixbuf;
	int i;
	int height;
	int changed = 0;

	if (!mapped || !g_key_file_get_boolean(config, CONFIG_GROUP,
				"show_bitmap", NULL))
		return;
	if (img_width == 0)
		return;  /* need to wait for img_size_allocate() callback */
	if (prev_states == NULL)
		prev_states = g_malloc(numchunks);
	height = optimal_height(img_width);
	numpixels = height * img_width;
	pixels = g_malloc(4 * numpixels);
	for (i = 0; i < numchunks; i++) {
		if (states[i] != prev_states[i]) {
			prev_states[i] = states[i];
			changed = 1;
		}
		if (states[i] & 0x8) {
			/* Dirtied this session */
			pixels[i] = htonl(0xff0000ff);
		} else if (states[i] & 0x4) {
			/* Accessed this session */
			pixels[i] = htonl(0xffffffff);
		} else if (states[i] & 0x2) {
			/* Dirty */
			pixels[i] = htonl(0x800000ff);
		} else if (states[i] & 0x1) {
			/* Present */
			pixels[i] = htonl(0xa0a0a0ff);
		} else {
			/* Not present */
			pixels[i] = htonl(0x707070ff);
		}
	}
	for (i = numchunks; i < numpixels; i++)
		pixels[i] = 0;
	/* These calls are expensive for large buffers, so we only invoke them
	   if the image has changed */
	if (changed || img_width != last_width || height != last_height) {
		pixbuf = gdk_pixbuf_new_from_data((guchar *)pixels,
					GDK_COLORSPACE_RGB, TRUE, 8,
					img_width, height, img_width * 4,
					free_pixels, NULL);
		gtk_image_set_from_pixbuf(GTK_IMAGE(img), pixbuf);
		g_object_unref(pixbuf);
		last_width = img_width;
		last_height = height;
	} else {
		g_free(pixels);
	}
}

gboolean update_event(void *data)
{
	struct stat st;

	if (fstat(state_fd, &st))
		die("fstat failed");
	if (st.st_nlink == 0)
		gtk_main_quit();
	update_stats();
	update_states();
	update_img();
	return TRUE;
}

#define WINDOW_BORDER		2
#define IMG_MIN_WIDTH_PADDING	20
#define IMG_MIN_HEIGHT_PADDING	25
#define IMG_BORDER_WIDTH	16
#define IMG_HEIGHT_PADDING	5
/* Calculating the correct window size is difficult when the bitmap is enabled,
   because the height depends on the width and there's no straightforward way
   to calculate the width the bitmap itself will be assigned after frame and
   padding are included.  So we apply fudge factors. */
void resize_window(struct pane *added, struct pane *dropped)
{
	struct pane *pane;
	GtkRequisition label_req;
	GtkRequisition req;
	int min_width = 0;
	int min_height = 0;
	int width;
	int height;

	width = g_key_file_get_integer(config, CONFIG_GROUP, "width", NULL);
	height = g_key_file_get_integer(config, CONFIG_GROUP, "height", NULL);
	for (pane = panes; pane->config_key != NULL; pane++)
		if (!strcmp(pane->config_key, "show_bitmap"))
			gtk_widget_size_request(
					gtk_frame_get_label_widget(
					GTK_FRAME(pane->widget)), &label_req);

	/* Expand/contract the window if a pane was added/removed. */
	if (added != NULL) {
		if (!strcmp(added->config_key, "show_bitmap")) {
			height += optimal_height(width - IMG_BORDER_WIDTH)
						+ label_req.height
						+ IMG_HEIGHT_PADDING;
		} else {
			gtk_widget_size_request(added->widget, &req);
			height += req.height;
		}
	}
	if (dropped != NULL)
		height -= dropped->height;

	/* Calculate the minimum window size. */
	for (pane = panes; pane->config_key != NULL; pane++) {
		if (!g_key_file_get_boolean(config, CONFIG_GROUP,
					pane->config_key, NULL))
			continue;
		if (!strcmp(pane->config_key, "show_bitmap")) {
			min_width = max(min_width, label_req.width
						+ IMG_MIN_WIDTH_PADDING);
			min_height += label_req.height
						+ IMG_MIN_HEIGHT_PADDING;
		} else {
			gtk_widget_size_request(pane->widget, &req);
			min_width = max(min_width, req.width);
			min_height += req.height;
		}
	}
	min_width += 2 * WINDOW_BORDER;
	min_height += 2 * WINDOW_BORDER;

	/* Make sure the window size is at least the minimum. */
	if (width < min_width && g_key_file_get_boolean(config, CONFIG_GROUP,
				"show_bitmap", NULL)) {
		/* We need to recalculate the height so that we don't end up
		   with a bunch of empty rows at the bottom of the bitmap. */
		width = min_width;
		height = min_height - IMG_MIN_HEIGHT_PADDING +
				optimal_height(width - IMG_BORDER_WIDTH) +
				IMG_HEIGHT_PADDING;
	} else {
		width = max(min_width, width);
		height = max(min_height, height);
	}

	g_key_file_set_integer(config, CONFIG_GROUP, "width", width);
	g_key_file_set_integer(config, CONFIG_GROUP, "height", height);
	gtk_window_resize(GTK_WINDOW(wd), width, height);
	gtk_widget_set_size_request(wd, min_width, min_height);
}

gboolean configure(GtkWidget *widget, GdkEventConfigure *event, void *data)
{
	g_key_file_set_integer(config, CONFIG_GROUP, "width", event->width);
	g_key_file_set_integer(config, CONFIG_GROUP, "height", event->height);
	g_key_file_set_integer(config, CONFIG_GROUP, "x", event->x);
	g_key_file_set_integer(config, CONFIG_GROUP, "y", event->y);
	return FALSE;
}

gboolean map(GtkWidget *widget, GdkEvent *event, void *data)
{
	mapped = TRUE;
	update_event(NULL);
	return FALSE;
}

gboolean unmap(GtkWidget *widget, GdkEvent *event, void *data)
{
	mapped = FALSE;
	return FALSE;
}

gboolean destroy(GtkWidget *widget, GdkEvent *event, void *data)
{
	gtk_main_quit();
	return TRUE;
}

gboolean keypress(GtkWidget *widget, GdkEventKey *event, void *data)
{
	switch (event->keyval) {
	case GDK_Tab:
		/* GTK won't let us install an accelerator for this, so we
		   have to do it by hand. */
		gtk_widget_activate(always_on_top);
		return TRUE;
	default:
		return FALSE;
	}
}

void pane_size_allocate(GtkWidget *widget, GtkAllocation *alloc, void *data)
{
	struct pane *pane = data;

	pane->width = alloc->width;
	pane->height = alloc->height;
}

void img_size_allocate(GtkWidget *widget, GtkAllocation *alloc, void *data)
{
	img_width = alloc->width;
	update_img();
}

gboolean menu_popup(GtkWidget *widget, GdkEventButton *event, GtkWidget *menu)
{
	if (event->type != GDK_BUTTON_PRESS || event->button != 3)
		return FALSE;
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, event->button,
				event->time);
	return TRUE;
}

void update_pane_dimmers(void)
{
	struct pane *pane;
	int count = 0;

	for (pane = panes; pane->config_key != NULL; pane++)
		if (g_key_file_get_boolean(config, CONFIG_GROUP,
					pane->config_key, NULL))
			count++;
	for (pane = panes; pane->config_key != NULL; pane++) {
		if (count > 1) {
			gtk_widget_set_sensitive(pane->checkbox, TRUE);
		} else {
			if (g_key_file_get_boolean(config, CONFIG_GROUP,
						pane->config_key, NULL))
				gtk_widget_set_sensitive(pane->checkbox, FALSE);
			else
				gtk_widget_set_sensitive(pane->checkbox, TRUE);
		}
	}
}

gboolean menu_toggle_pane(GtkCheckMenuItem *item, void *data)
{
	struct pane *pane = data;
	gboolean newval;

	newval = gtk_check_menu_item_get_active(item);
	g_key_file_set_boolean(config, CONFIG_GROUP, pane->config_key, newval);
	if (newval) {
		gtk_widget_show(pane->widget);
		resize_window(pane, NULL);
	} else {
		gtk_widget_hide(pane->widget);
		resize_window(NULL, pane);
	}
	update_pane_dimmers();
	return TRUE;
}

gboolean menu_set_keep_above(GtkCheckMenuItem *item, void *data)
{
	gboolean newval;

	newval = gtk_check_menu_item_get_active(item);
	g_key_file_set_boolean(config, CONFIG_GROUP, "keep_above", newval);
	gtk_window_set_keep_above(GTK_WINDOW(wd), newval);
	return TRUE;
}

gboolean menu_quit(GtkMenuItem *item, void *data)
{
	gtk_main_quit();
	return TRUE;
}

void init_files(void)
{
	GError *err = NULL;
	char *path;
	char *linkdest;
	char **linkparts;
	char *val;
	char *end;

	path = g_strdup_printf("/dev/shm/openisr-chunkmap-%s", uuid);
	state_fd = open(path, O_RDONLY);
	if (state_fd == -1) {
		if (errno == ENOENT)
			die("Parcel %s is not currently running", uuid);
		else
			die("Couldn't open %s", path);
	}
	numchunks = lseek(state_fd, 0, SEEK_END);
	if (numchunks == -1)
		die("lseek failed");
	states = mmap(NULL, numchunks, PROT_READ, MAP_SHARED, state_fd, 0);
	if (states == MAP_FAILED)
		die("mmap failed");
	g_free(path);

	path = g_strdup_printf("/dev/disk/by-id/openisr-%s", uuid);
	linkdest = g_file_read_link(path, &err);
	if (err)
		die("Couldn't read link %s: %s", path, err->message);
	linkparts = g_strsplit(linkdest, "/", 0);
	statsdir = g_strdup_printf("/sys/class/openisr/%s",
				linkparts[g_strv_length(linkparts) - 1]);
	g_strfreev(linkparts);
	g_free(path);

	val = get_attr("chunk_size");
	if (val == NULL)
		die("Couldn't get parcel chunk size");
	chunks_per_mb = (1 << 20) / strtol(val, &end, 10);
	if (val[0] == 0 || end[0] != 0)
		die("Couldn't parse parcel chunk size");
	g_free(val);
}

GtkWidget *init_menu(GtkAccelGroup *accels)
{
	GtkWidget *menu;
	GtkWidget *item;
	struct pane *pane;

	menu = gtk_menu_new();

	for (pane = panes; pane->config_key != NULL; pane++) {
		item = gtk_check_menu_item_new_with_label(pane->menu_label);
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item),
					g_key_file_get_boolean(config,
					CONFIG_GROUP, pane->config_key, NULL));
		g_signal_connect(item, "toggled",
					G_CALLBACK(menu_toggle_pane), pane);
		gtk_widget_add_accelerator(item, "activate", accels,
					pane->accel, 0, GTK_ACCEL_VISIBLE);
		pane->checkbox = item;
		gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
	}
	update_pane_dimmers();

	item = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);

	item = gtk_check_menu_item_new_with_label("Keep window on top");
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item),
				g_key_file_get_boolean(config, CONFIG_GROUP,
				"keep_above", NULL));
	g_signal_connect(item, "toggled", G_CALLBACK(menu_set_keep_above),
				NULL);
	gtk_widget_add_accelerator(item, "activate", accels, GDK_Tab, 0,
				GTK_ACCEL_VISIBLE);
	always_on_top = item;
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);

	item = gtk_menu_item_new_with_label("Quit");
	g_signal_connect(item, "activate", G_CALLBACK(menu_quit), NULL);
	gtk_widget_add_accelerator(item, "activate", accels, GDK_Escape, 0,
				GTK_ACCEL_VISIBLE);
	gtk_widget_add_accelerator(item, "activate", accels, GDK_q, 0, 0);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);

	gtk_widget_show_all(menu);
	return menu;
}

GtkWidget *pane_widget(const char *config_key, GtkWidget *widget)
{
	struct pane *pane;
	GtkWidget *frame;

	for (pane = panes; pane->config_key != NULL; pane++) {
		if (!strcmp(config_key, pane->config_key)) {
			frame = gtk_frame_new(pane->frame_label);
			gtk_container_add(GTK_CONTAINER(frame), widget);
			pane->widget = frame;
			g_signal_connect(frame, "size-allocate",
						G_CALLBACK(pane_size_allocate),
						pane);
			return frame;
		}
	}
	return NULL;
}

const char img_tooltip[] =
"Red: Dirtied this session\n"
"White: Accessed this session\n"
"Dark red: Dirtied in previous session\n"
"Light gray: Accessed in previous session\n"
"Dark gray: Not present";

void init_window(void)
{
	GError *err1 = NULL;
	GError *err2 = NULL;
	GtkAccelGroup *accels;
	GtkWidget *vbox;
	GtkWidget *stats_table;
	GtkWidget *state_table;
	GtkWidget *lbl;
	GtkWidget *menu;
	GtkWidget *img_box;
	GtkTooltips *tips;
	struct stats *st;
	struct stat_output *output;
	struct pane *pane;
	char *title;
	int x;
	int y;
	int i;
	int j;

	title = g_strdup_printf("Dirtometer: %s", name);
	wd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(wd), title);
	g_free(title);
	gtk_container_set_border_width(GTK_CONTAINER(wd), WINDOW_BORDER);
	gtk_window_set_gravity(GTK_WINDOW(wd), GDK_GRAVITY_STATIC);
	accels = gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(wd), accels);
	menu = init_menu(accels);
	tips = gtk_tooltips_new();
	vbox = gtk_vbox_new(FALSE, 5);
	for (i = 0; statistics[i].heading != NULL; i++);
	stats_table = gtk_table_new(i, 3, TRUE);
	gtk_container_set_border_width(GTK_CONTAINER(stats_table), 2);
	state_table = gtk_table_new(NR_STATES, 2, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(state_table), 2);
	img = gtk_image_new();
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
	img_box = gtk_event_box_new();
	gtk_container_set_border_width(GTK_CONTAINER(img_box), 2);
	gtk_container_add(GTK_CONTAINER(img_box), img);
	gtk_tooltips_set_tip(tips, img_box, img_tooltip, NULL);
	gtk_container_add(GTK_CONTAINER(wd), vbox);
	gtk_box_pack_start(GTK_BOX(vbox), pane_widget("show_stats",
				stats_table), FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), pane_widget("show_nexus",
				state_table), FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(vbox), pane_widget("show_bitmap", img_box),
				TRUE, TRUE, 0);
	for (i = 0; statistics[i].heading != NULL; i++) {
		st = &statistics[i];
		lbl = gtk_label_new(st->heading);
		gtk_misc_set_alignment(GTK_MISC(lbl), 0, 0.5);
		gtk_table_attach(GTK_TABLE(stats_table), lbl, 0, 1, i, i + 1,
					GTK_FILL, 0, 0, 0);
		for (j = 0; j < NOUTPUTS; j++) {
			output = &st->output[j];
			if (output->format == NULL)
				continue;
			output->ebox = gtk_event_box_new();
			output->label = gtk_label_new("--");
			gtk_container_add(GTK_CONTAINER(output->ebox),
						output->label);
			gtk_misc_set_alignment(GTK_MISC(output->label), 1, 0.5);
			gtk_tooltips_set_tip(tips, output->ebox,
						output->tooltip, NULL);
			gtk_table_attach(GTK_TABLE(stats_table), output->ebox,
						j + 1, j + 2, i, i + 1,
						GTK_FILL, 0, 3, 2);
		}
	}
	for (i = 0; i < NR_STATES; i++) {
		lbl = gtk_label_new(state_names[i]);
		gtk_misc_set_alignment(GTK_MISC(lbl), 0, 0.5);
		gtk_table_attach(GTK_TABLE(state_table), lbl, 0, 1, i, i + 1,
					GTK_FILL, 0, 0, 0);
		lbl = gtk_label_new("--");
		gtk_label_set_width_chars(GTK_LABEL(lbl), 5);
		gtk_misc_set_alignment(GTK_MISC(lbl), 1, 0.5);
		gtk_table_attach(GTK_TABLE(state_table), lbl, 1, 2, i, i + 1,
					GTK_FILL, 0, 0, 2);
		state_lbl[i] = lbl;
	}
	gtk_widget_show_all(GTK_WIDGET(wd));
	/* Now re-hide the panes that are not enabled. */
	for (pane = panes; pane->config_key != NULL; pane++)
		if (!g_key_file_get_boolean(config, CONFIG_GROUP,
					pane->config_key, NULL))
			gtk_widget_hide(pane->widget);
	gtk_widget_add_events(wd, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(wd, "configure-event", G_CALLBACK(configure), wd);
	g_signal_connect(wd, "delete-event", G_CALLBACK(destroy), NULL);
	g_signal_connect(wd, "key-press-event", G_CALLBACK(keypress), wd);
	g_signal_connect(wd, "button-press-event", G_CALLBACK(menu_popup),
				menu);
	g_signal_connect(wd, "map-event", G_CALLBACK(map), NULL);
	g_signal_connect(wd, "unmap-event", G_CALLBACK(unmap), NULL);
	g_signal_connect(img, "size-allocate", G_CALLBACK(img_size_allocate),
				NULL);

	x = g_key_file_get_integer(config, CONFIG_GROUP, "x", &err1);
	y = g_key_file_get_integer(config, CONFIG_GROUP, "y", &err2);
	if (err1 == NULL && err2 == NULL)
		gtk_window_move(GTK_WINDOW(wd), x, y);
	g_clear_error(&err1);
	g_clear_error(&err2);
	gtk_window_set_keep_above(GTK_WINDOW(wd),
				g_key_file_get_boolean(config, CONFIG_GROUP,
				"keep_above", NULL));
	resize_window(NULL, NULL);
}

GOptionEntry options[] = {
	{"name", 'n', 0, G_OPTION_ARG_STRING, &name, "Parcel name", "NAME"},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

int main(int argc, char **argv)
{
	GError *err = NULL;

	if (!gtk_init_with_args(&argc, &argv, "<parcel-uuid>", options, NULL,
				&err))
		die("%s", err->message);
	if (argc != 2)
		die("Missing parcel UUID");
	uuid = argv[1];
	if (name == NULL)
		name = uuid;
	confdir = g_strdup_printf("%s/.isr/dirtometer", getenv("HOME"));
	conffile = g_strdup_printf("%s/%s", confdir, uuid);

	init_files();
	read_config();
	init_window();
	g_timeout_add(100, update_event, NULL);
	gtk_main();
	write_config();
	return 0;
}
