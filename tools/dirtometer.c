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

#define CONFIG_GROUP "dirtometer"

GtkWidget *wd;
GtkWidget *img;

const char *uuid;
const char *name;
const char *confdir;
const char *conffile;
const char *statsdir;

GKeyFile *config;
int state_fd;
char *states;
int numchunks;

struct stats {
	long sectors_read;
	long sectors_written;
	long chunk_reads;
	long chunk_writes;
	long cache_hits;
	long cache_misses;
} last_stats;

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

int optimal_height(void)
{
	int width;

	width = g_key_file_get_integer(config, CONFIG_GROUP, "width", NULL);
	return (numchunks + width - 1) / width;
}

void read_config(void)
{
	GError *err = NULL;

	config = g_key_file_new();
	g_key_file_load_from_file(config, conffile, 0, NULL);

	g_key_file_get_integer(config, CONFIG_GROUP, "width", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_integer(config, CONFIG_GROUP, "width", 200);
	}

	g_key_file_get_integer(config, CONFIG_GROUP, "height", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_integer(config, CONFIG_GROUP, "height",
					optimal_height());
	}

	g_key_file_get_boolean(config, CONFIG_GROUP, "keep_above", &err);
	if (err) {
		g_clear_error(&err);
		g_key_file_set_boolean(config, CONFIG_GROUP, "keep_above",
					TRUE);
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

long read_stat(char *attr)
{
	char *path;
	char *data;
	char *end;
	gboolean ok;
	long ret;

	path = g_strdup_printf("%s/%s", statsdir, attr);
	ok = g_file_get_contents(path, &data, NULL, NULL);
	g_free(path);
	if (!ok)
		return -1;
	g_strchomp(data);
	ret = strtol(data, &end, 10);
	if (data[0] == 0 || end[0] != 0)
		ret = -1;
	g_free(data);
	return ret;
}

void update_stats(void)
{
	struct stats cur_stats = {
		.sectors_read = read_stat("sectors_read"),
		.sectors_written = read_stat("sectors_written"),
		.chunk_reads = read_stat("chunk_reads"),
		.chunk_writes = read_stat("chunk_writes"),
		.cache_hits = read_stat("cache_hits"),
		.cache_misses = read_stat("cache_misses"),
	};

	printf("sectors %ld %ld chunks %ld %ld cache %ld %ld\n",
				cur_stats.sectors_read,
				cur_stats.sectors_written,
				cur_stats.chunk_reads,
				cur_stats.chunk_writes,
				cur_stats.cache_hits,
				cur_stats.cache_misses);
}

void free_pixels(unsigned char *pixels, void *data)
{
	g_free(pixels);
}

void update_img(void)
{
	uint32_t *pixels;
	int numpixels;
	GdkPixbuf *pixbuf;
	int i;
	int width;
	int height;

	width = g_key_file_get_integer(config, CONFIG_GROUP, "width", NULL);
	height = g_key_file_get_integer(config, CONFIG_GROUP, "height", NULL);

	numpixels = max(height * width, numchunks);
	pixels = g_malloc(4 * numpixels);
	for (i = 0; i < numchunks; i++) {
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
		pixels[i] = htonl(0x000000ff);
	pixbuf = gdk_pixbuf_new_from_data((guchar *)pixels, GDK_COLORSPACE_RGB,
				TRUE, 8, width, height,	width * 4, free_pixels,
				NULL);
	gtk_image_set_from_pixbuf(GTK_IMAGE(img), pixbuf);
	g_object_unref(pixbuf);
}

gboolean update_event(void *data)
{
	struct stat st;

	if (fstat(state_fd, &st))
		die("fstat failed");
	if (st.st_nlink == 0)
		gtk_main_quit();
	update_stats();
	update_img();
	return TRUE;
}

gboolean configure(GtkWidget *widget, GdkEventConfigure *event, void *data)
{
	g_key_file_set_integer(config, CONFIG_GROUP, "width", event->width);
	g_key_file_set_integer(config, CONFIG_GROUP, "height", event->height);
	g_key_file_set_integer(config, CONFIG_GROUP, "x", event->x);
	g_key_file_set_integer(config, CONFIG_GROUP, "y", event->y);
	update_img();
	return 0;
}

gboolean destroy(GtkWidget *widget, GdkEvent *event, void *data)
{
	gtk_main_quit();
	return TRUE;
}

gboolean keypress(GtkWidget *widget, GdkEventKey *event, void *data) {
	gboolean keep_above;

	switch (event->keyval) {
	case GDK_Escape:
	case GDK_q:
		gtk_main_quit();
		return TRUE;
	case GDK_space:
		gtk_window_resize(GTK_WINDOW(wd),
					g_key_file_get_integer(config,
					CONFIG_GROUP, "width", NULL),
					optimal_height());
		return TRUE;
	case GDK_Tab:
		keep_above = !g_key_file_get_boolean(config, CONFIG_GROUP,
					"keep_above", NULL);
		g_key_file_set_boolean(config, CONFIG_GROUP, "keep_above",
					keep_above);
		gtk_window_set_keep_above(GTK_WINDOW(wd), keep_above);
		return TRUE;
	default:
		return TRUE;
	}
}

void init_files(void)
{
	GError *err = NULL;
	char *path;
	char *linkdest;
	char **linkparts;

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
}

void init_window(void)
{
	GError *err1 = NULL;
	GError *err2 = NULL;
	char *title;
	int x;
	int y;
	GdkGeometry hints = {
		.min_width = 10,
		.min_height = 10,
	};

	title = g_strdup_printf("Dirtometer: %s", name);
	wd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(wd), title);
	g_free(title);
	gtk_window_set_gravity(GTK_WINDOW(wd), GDK_GRAVITY_STATIC);
	img = gtk_image_new();
	gtk_container_add(GTK_CONTAINER(wd), img);
	gtk_widget_show_all(GTK_WIDGET(wd));
	g_signal_connect(wd, "configure-event", G_CALLBACK(configure), wd);
	g_signal_connect(wd, "delete-event", G_CALLBACK(destroy), NULL);
	g_signal_connect(wd, "key-press-event", G_CALLBACK(keypress), wd);

	x = g_key_file_get_integer(config, CONFIG_GROUP, "x", &err1);
	y = g_key_file_get_integer(config, CONFIG_GROUP, "y", &err2);
	if (err1 == NULL && err2 == NULL)
		gtk_window_move(GTK_WINDOW(wd), x, y);
	g_clear_error(&err1);
	g_clear_error(&err2);
	gtk_window_set_keep_above(GTK_WINDOW(wd),
				g_key_file_get_boolean(config, CONFIG_GROUP,
				"keep_above", NULL));
	gtk_window_resize(GTK_WINDOW(wd), g_key_file_get_integer(config,
				CONFIG_GROUP, "width", NULL),
				g_key_file_get_integer(config, CONFIG_GROUP,
				"height", NULL));
	gtk_window_set_geometry_hints(GTK_WINDOW(wd), img, &hints,
				GDK_HINT_MIN_SIZE);
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
	update_stats();
	update_img();
	g_timeout_add(100, update_event, NULL);
	gtk_main();
	write_config();
	return 0;
}
