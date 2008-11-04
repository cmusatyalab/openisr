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

GtkWidget *wd;
GtkWidget *img;

const char *uuid;
const char *name;
const char *confdir;
const char *conffile;

int state_fd;
char *states;
uint64_t numchunks;
uint32_t *pixels;
uint64_t numpixels;

struct {
	int height;
	int width;
	int x;
	int y;
	gboolean keep_above;
} config = {
	.width = 200,
	.x = -1,
	.y = -1,
	.keep_above = TRUE,
};

void die(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

#define max(a, b) ((a) > (b) ? (a) : (b))

int optimal_height(void)
{
	return (numchunks + config.width - 1) / config.width;
}

void read_config(void)
{
	FILE *fp;
	char buf[256];
	char *bufp;
	size_t len;

	fp = fopen(conffile, "r");
	if (fp == NULL)
		return;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		len = strlen(buf);
		if (buf[len-1] == '\n')
			buf[len-1] = 0;
		bufp = buf;
		strsep(&bufp, "=");
		if (bufp == NULL) {
			fprintf(stderr, "Error parsing config file\n");
			break;
		}
		if (!strcmp("height", buf))
			config.height = atoi(bufp);
		else if (!strcmp("width", buf))
			config.width = atoi(bufp);
		else if (!strcmp("x", buf))
			config.x = atoi(bufp);
		else if (!strcmp("y", buf))
			config.y = atoi(bufp);
		else if (!strcmp("keep_above", buf))
			config.keep_above = atoi(bufp);
	}
	fclose(fp);
}

void write_config(void) {
	FILE *fp;
	struct stat st;

	if (stat(confdir, &st) || !S_ISDIR(st.st_mode)) {
		if (mkdir(confdir, 0777)) {
			fprintf(stderr, "Couldn't create directory %s\n",
						confdir);
			return;
		}
	}
	fp = fopen(conffile, "w");
	if (fp == NULL) {
		fprintf(stderr, "Couldn't write config file\n");
		return;
	}
	fprintf(fp, "width=%d\n", config.width);
	fprintf(fp, "height=%d\n", config.height);
	fprintf(fp, "x=%d\n", config.x);
	fprintf(fp, "y=%d\n", config.y);
	fprintf(fp, "keep_above=%d\n", config.keep_above);
	if (fclose(fp)) {
		fprintf(stderr, "Couldn't write config file\n");
		return;
	}
}

void update_img(void)
{
	GdkPixbuf *pixbuf;
	struct stat st;
	uint64_t i;

	if (fstat(state_fd, &st))
		die("fstat failed");
	if (st.st_nlink == 0)
		gtk_main_quit();

	if (numpixels < max(config.height * config.width, numchunks)) {
		numpixels = max(config.height * config.width, numchunks);
		pixels = g_realloc(pixels, 4 * numpixels);
	}
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
				TRUE, 8, config.width, config.height,
				config.width * 4, NULL, NULL);
	gtk_image_set_from_pixbuf(GTK_IMAGE(img), pixbuf);
	g_object_unref(pixbuf);
}

gboolean update_img_event(void *data)
{
	update_img();
	return TRUE;
}

gboolean configure(GtkWidget *widget, GdkEventConfigure *event, void *data)
{
	config.width = event->width;
	config.height = event->height;
	config.x = event->x;
	config.y = event->y;
	update_img();
	return 0;
}

gboolean destroy(GtkWidget *widget, GdkEvent *event, void *data)
{
	gtk_main_quit();
	return TRUE;
}

gboolean keypress(GtkWidget *widget, GdkEventKey *event, void *data) {
	switch (event->keyval) {
	case GDK_Escape:
	case GDK_q:
		gtk_main_quit();
		return TRUE;
	case GDK_space:
		gtk_window_resize(GTK_WINDOW(wd), config.width,
					optimal_height());
		return TRUE;
	case GDK_Tab:
		config.keep_above = !config.keep_above;
		gtk_window_set_keep_above(GTK_WINDOW(wd), config.keep_above);
		return TRUE;
	default:
		return TRUE;
	}
}

void init(void)
{
	char *file;
	int state_fd;
	char *title;
	GdkGeometry hints = {
		.min_width = 10,
		.min_height = 10,
	};

	file = g_strdup_printf("/dev/shm/openisr-chunkmap-%s", uuid);
	state_fd = open(file, O_RDONLY);
	if (state_fd == -1) {
		if (errno == ENOENT)
			die("Parcel %s is not currently running", uuid);
		else
			die("Couldn't open %s", file);
	}
	numchunks = lseek(state_fd, 0, SEEK_END);
	if (numchunks == -1)
		die("lseek failed");
	states = mmap(NULL, numchunks, PROT_READ, MAP_SHARED, state_fd, 0);
	if (states == MAP_FAILED)
		die("mmap failed");
	g_free(file);

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

	config.height = optimal_height();
	read_config();
	if (config.x >= 0 && config.y >= 0)
		gtk_window_move(GTK_WINDOW(wd), config.x, config.y);
	gtk_window_set_keep_above(GTK_WINDOW(wd), config.keep_above);
	gtk_window_resize(GTK_WINDOW(wd), config.width, config.height);
	gtk_window_set_geometry_hints(GTK_WINDOW(wd), img, &hints,
				GDK_HINT_MIN_SIZE);
}

const GOptionEntry options[] = {
	{"name", 'n', 0, G_OPTION_ARG_STRING, &name, "Parcel name", "NAME"},
	{0}
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

	init();
	update_img();
	g_timeout_add(100, update_img_event, NULL);
	gtk_main();
	write_config();
	return 0;
}
