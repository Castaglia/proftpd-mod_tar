/*
 * ProFTPD - mod_tar
 * Copyright (c) 2009-2012 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: mod_tar.c,v 1.7 2009/10/01 15:30:57 tj Exp tj $
 * $Libraries: -larchive -lz -lbz2 $
 */

#include "conf.h"
#include "privs.h"

#include <archive.h>
#include <archive_entry.h>

#define MOD_TAR_VERSION		"mod_tar/0.4"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030101
# error "ProFTPD 1.3.1rc1 or later required"
#endif

module tar_module;

/* Necessary prototype. */
static void tar_exit_ev(const void *, void *);

static int tar_engine = FALSE;
static int tar_logfd = -1;

static unsigned long tar_opts = 0UL;
#define TAR_OPT_DEREF_SYMLINKS		0x001

#define TAR_ARCHIVE_FL_USE_GZIP		0x001
#define TAR_ARCHIVE_FL_USE_BZIP2	0x002
#define TAR_ARCHIVE_FL_USE_USTAR	0x004
#define TAR_ARCHIVE_FL_USE_PAX		0x008
#define TAR_ARCHIVE_FL_USE_ZIP		0x010

static const char *tar_tmp_path = "./";
static char *tar_tmp_file = NULL;

struct archive_data {
  const char *path;
  pr_fh_t *fh;
};

static const char *trace_channel = "tar";

static int append_data(pool *p, struct archive *tar,
    struct archive_entry *entry, char *path, struct stat *st) {
  pool *tmp_pool;
  pr_fh_t *fh;
  void *buf;
  size_t buflen;
  int res;

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "unable to read '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  tmp_pool = make_sub_pool(p);

  /* Use a buffer size based on the filesystem blocksize, for better IO. */
  buflen = st->st_blksize;
  buf = palloc(tmp_pool, buflen);

  res = pr_fsio_read(fh, buf, buflen);
  while (res > 0) {
    pr_signals_handle();
    if (archive_write_data(tar, buf, res) < 0) {
      int xerrno;

      xerrno = archive_errno(tar);
      pr_trace_msg(trace_channel, 3, "error adding data to archive: %s",
        archive_error_string(tar));

      destroy_pool(tmp_pool);
      pr_fsio_close(fh);

      errno = xerrno;
      return -1;
    }
 
    res = pr_fsio_read(fh, buf, buflen);
  }

  destroy_pool(tmp_pool);
  pr_fsio_close(fh);  

  return 0;
}

static int append_file(pool *p, struct archive *tar,
    struct archive_entry *entry, char *real_name, char *save_name) {
  struct stat st;
  int res;

  if (!(tar_opts & TAR_OPT_DEREF_SYMLINKS)) {
    res = pr_fsio_lstat(real_name, &st);

  } else {
    res = pr_fsio_stat(real_name, &st);
  }

  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 9, "error stat'ing '%s': %s", real_name,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  archive_entry_clear(entry);
  archive_entry_copy_stat(entry, &st);
  archive_entry_copy_pathname(entry, save_name);

  if (S_ISLNK(st.st_mode)) {
    int i;
    char path[PR_TUNABLE_PATH_MAX+1];

    i = readlink(real_name, path, sizeof(path)-1);
    if (i == -1)
      return -1;

    if (i >= PR_TUNABLE_PATH_MAX) {
      i = PR_TUNABLE_PATH_MAX - 1;
    }

    path[i] = '\0';

    pr_trace_msg(trace_channel, 15,
      "setting destination path '%s' for symlink '%s'", path, real_name);
    archive_entry_set_symlink(entry, path);
  }
 
  res = archive_write_header(tar, entry);
  if (res != ARCHIVE_OK) {
    int xerrno;

    xerrno = archive_errno(tar);
    pr_trace_msg(trace_channel, 3, "error writing archive entry header: %s",
      archive_error_string(tar));

    errno = xerrno;
    return -1;
  }

  /* If it's a regular file, write the contents as well */
  if (S_ISREG(st.st_mode)) {
    if (append_data(p, tar, entry, real_name, &st) < 0) {
      return -1;
    }
  }

  res = archive_write_finish_entry(tar);
  if (res != ARCHIVE_OK) {
    int xerrno;

    xerrno = archive_errno(tar);
    pr_trace_msg(trace_channel, 3, "error finishing archive entry: %s",
      archive_error_string(tar));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int append_tree(pool *p, struct archive *tar,
    struct archive_entry *entry, char *real_dir, char *save_dir) {
  char real_path[PR_TUNABLE_PATH_MAX+1];
  char save_path[PR_TUNABLE_PATH_MAX+1];
  struct dirent *dent;
  DIR *dirh;
  struct stat st;
  int res;

  res = append_file(p, tar, entry, real_dir, save_dir);
  if (res < 0) {
    return -1;
  }

  dirh = opendir(real_dir);
  if (dirh == NULL) {
    if (errno == ENOTDIR) {
      return 0;
    }

    return -1;
  }

  while ((dent = readdir(dirh)) != NULL) {
    pr_signals_handle();

    if (strncmp(dent->d_name, ".", 2) == 0 ||
        strncmp(dent->d_name, "..", 3) == 0) {
      continue;
    }

    memset(real_path, '\0', sizeof(real_path));
    snprintf(real_path, sizeof(real_path)-1, "%s/%s", real_dir, dent->d_name);

    if (save_dir) {
      memset(save_path, '\0', sizeof(save_path));
      snprintf(save_path, sizeof(save_path)-1, "%s/%s", save_dir, dent->d_name);
    }

    if (!(tar_opts & TAR_OPT_DEREF_SYMLINKS)) {
      res = pr_fsio_lstat(real_path, &st);

    } else {
      res = pr_fsio_stat(real_path, &st);
    }

    if (res < 0) {
      int xerrno = errno;

      (void) closedir(dirh);

      errno = xerrno;
      return -1;
    }

    if (S_ISDIR(st.st_mode)) {
      res = append_tree(p, tar, entry, real_path,
        (save_dir ? save_path : NULL));
      if (res < 0) {
        int xerrno = errno;

        (void) closedir(dirh);
 
        errno = xerrno;
        return -1;
      }

      continue;
    }

    res = append_file(p, tar, entry, real_path, (save_dir ? save_path : NULL));
    if (res < 0) {
      int xerrno = errno;

      (void) closedir(dirh);

      errno = xerrno;
      return -1;
    }
  }

  closedir(dirh);
  return 0;
}

static int tar_archive_open_cb(struct archive *tar, void *user_data) {
  struct archive_data *tar_data;
  pr_fh_t *fh;

  tar_data = user_data;

  fh = pr_fsio_open(tar_data->path, O_WRONLY|O_CREAT);
  if (fh == NULL) {
    return ARCHIVE_FATAL;
  }

  /* Override the default 0666 mode that pr_fsio_open() uses. */
  if (pr_fsio_fchmod(fh, 0644) < 0) {
    pr_trace_msg(trace_channel, 3, "error setting mode on '%s' to 0644: %s",
      tar_data->path, strerror(errno));
  }

  tar_data->fh = fh;
  return ARCHIVE_OK;
}

static ssize_t tar_archive_write_cb(struct archive *tar, void *user_data,
    const void *buf, size_t buflen) {
  struct archive_data *tar_data;

  tar_data = user_data;
  return pr_fsio_write(tar_data->fh, buf, buflen);
}

static int tar_archive_close_cb(struct archive *tar, void *user_data) {
  struct archive_data *tar_data;
  int res;

  tar_data = user_data;

  res = pr_fsio_close(tar_data->fh);
  if (res < 0) {
    return ARCHIVE_FATAL;
  }

  tar_data->fh = NULL;
  return ARCHIVE_OK;
}

static int tar_create_archive(pool *p, char *dst_file, unsigned long blksize,
    char *src_path, char *src_dir, unsigned long flags) {
  struct archive_data *tar_data;
  struct archive *tar;
  struct archive_entry *entry;
  int res;

  tar = archive_write_new();
  if (tar == NULL) {
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error allocating new archive handle: %s", archive_error_string(tar));
    errno = archive_errno(tar);
    return -1;
  }

  /* Call archive_write_set_bytes_per_block() there, so that the optimal
   * block size for writing data out to the archive file is used.
   *
   * Sadly, the libarchive API uses an int for the block size, not an
   * unsigned long, size_t, or off_t.  Why even allow a signed data type
   * for that parameter?
   */
  archive_write_set_bytes_per_block(tar, blksize);

  if (flags & TAR_ARCHIVE_FL_USE_USTAR) {
    res = archive_write_set_format_ustar(tar);
    if (res != ARCHIVE_OK) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error configuring archive handle for ustar format: %s",
        archive_error_string(tar));
      errno = archive_errno(tar);
      return -1;
    }

  } else if (flags & TAR_ARCHIVE_FL_USE_ZIP) {
    res = archive_write_set_format_zip(tar);
    if (res != ARCHIVE_OK) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error configuring archive handle for zip format: %s",
        archive_error_string(tar));
      errno = archive_errno(tar);
      return -1;
    }
  }

  if (flags & TAR_ARCHIVE_FL_USE_GZIP) {
    res = archive_write_add_filter_gzip(tar);
    if (res != ARCHIVE_OK) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error configuring archive handle for gzip compression: %s",
        archive_error_string(tar));
      errno = archive_errno(tar);
      return -1;
    }

    pr_trace_msg(trace_channel, 9, "using gzip compression for '%s'", src_path);

  } else if (flags & TAR_ARCHIVE_FL_USE_BZIP2) {
    res = archive_write_add_filter_bzip2(tar);
    if (res != ARCHIVE_OK) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error configuring archive handle for bzip2 compression: %s",
        archive_error_string(tar));
      errno = archive_errno(tar);
      return -1;
    }

    pr_trace_msg(trace_channel, 9, "using bzip2 compression for '%s'",
      src_path);

  } else {
    res = archive_write_add_filter_none(tar);
    if (res != ARCHIVE_OK) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error configuring archive handle for no compression: %s",
        archive_error_string(tar));
      errno = archive_errno(tar);
      return -1;
    }
  }

  tar_data = palloc(p, sizeof(struct archive_data));
  tar_data->path = dst_file;

  /* Allocate a new archive_entry to use for adding all entries to the
   * archive.  This avoid creating/destroying an archive_entry object per
   * file.
   */
  entry = archive_entry_new();
  if (tar == NULL) {
    int xerrno;
 
    xerrno = archive_errno(tar);
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error allocating new archive entry handle: %s",
      archive_error_string(tar));
    archive_write_free(tar);

    errno = xerrno;
    return -1;
  }

  res = archive_write_open(tar, tar_data, tar_archive_open_cb,
    tar_archive_write_cb, tar_archive_close_cb);
  if (res != ARCHIVE_OK) {
    int xerrno;

    xerrno = archive_errno(tar);
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error opening archive handle for file '%s': %s", dst_file,
      archive_error_string(tar));
    archive_entry_free(entry);
    archive_write_free(tar);
    (void) unlink(dst_file);

    errno = xerrno;
    return -1;
  }

  if (append_tree(p, tar, entry, src_path, src_dir) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error appending '%s' to tar file: %s", src_path, strerror(xerrno));
    archive_entry_free(entry);
    (void) archive_write_close(tar);
    archive_write_free(tar);
    (void) unlink(dst_file);

    errno = xerrno;
    return -1;
  }

  archive_entry_free(entry);

  res = archive_write_close(tar);
  if (res < 0) {
    int xerrno;

    xerrno = archive_errno(tar);
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error writing tar file: %s", archive_error_string(tar));

    archive_write_free(tar);
    (void) unlink(dst_file);

    errno = xerrno;
    return -1;
  }

  archive_write_free(tar);
  return 0;
}

static char *tar_get_ext_tar(char *path, size_t path_len) {
  if (path_len < 4) {
    return NULL;
  }

  if (path[path_len-4] == '.') {
    if ((path[path_len-3] == 'T' || path[path_len-3] == 't') &&
        (path[path_len-2] == 'A' || path[path_len-2] == 'a') &&
        (path[path_len-1] == 'R' || path[path_len-1] == 'r')) {

      return &path[path_len-4];
    }
  }

  return NULL;
}

static char *tar_get_ext_tgz(char *path, size_t path_len) {
  if (path_len < 4) {
    return NULL;
  }

  if (path[path_len-4] == '.') {
    if ((path[path_len-3] == 'T' || path[path_len-3] == 't') &&
        (path[path_len-2] == 'G' || path[path_len-2] == 'g') &&
        (path[path_len-1] == 'Z' || path[path_len-1] == 'z')) {

      return &path[path_len-4];
    }
  }

  return NULL;
}

static char *tar_get_ext_targz(char *path, size_t path_len) {
  if (path_len < 7) {
    return NULL;
  }

  if (path[path_len-7] == '.') {
    if ((path[path_len-6] == 'T' || path[path_len-6] == 't') &&
        (path[path_len-5] == 'A' || path[path_len-5] == 'a') &&
        (path[path_len-4] == 'R' || path[path_len-4] == 'r') &&
        path[path_len-3] == '.' &&
        (path[path_len-2] == 'G' || path[path_len-2] == 'g') &&
        (path[path_len-1] == 'z' || path[path_len-1] == 'z')) {

      return &path[path_len-7];
    }

    return NULL;
  }

  return NULL;
}

static char *tar_get_ext_tbz2(char *path, size_t path_len) {
  if (path_len < 5) {
    return NULL;
  }

  if (path[path_len-5] == '.') {
    if ((path[path_len-4] == 'T' || path[path_len-4] == 't') &&
        (path[path_len-3] == 'B' || path[path_len-3] == 'b') &&
        (path[path_len-2] == 'Z' || path[path_len-2] == 'z') &&
        path[path_len-1] == '2') {

      return &path[path_len-5];
    }
  }

  return NULL;
}

static char *tar_get_ext_tarbz2(char *path, size_t path_len) {
  if (path_len < 8) {
    return NULL;
  }

  if (path[path_len-8] == '.') {
    if ((path[path_len-7] == 'T' || path[path_len-7] == 't') &&
        (path[path_len-6] == 'A' || path[path_len-6] == 'a') &&
        (path[path_len-5] == 'R' || path[path_len-5] == 'r') &&
        path[path_len-4] == '.' &&
        (path[path_len-3] == 'B' || path[path_len-3] == 'b') &&
        (path[path_len-2] == 'z' || path[path_len-2] == 'z') &&
        path[path_len-1] == '2') {

      return &path[path_len-8];
    }
  }

  return NULL;
}

static char *tar_get_ext_zip(char *path, size_t path_len) {
  if (path_len < 4) {
    return NULL;
  }

  if (path[path_len-4] == '.') {
    if ((path[path_len-3] == 'Z' || path[path_len-3] == 'z') &&
        (path[path_len-2] == 'I' || path[path_len-2] == 'i') &&
        (path[path_len-1] == 'P' || path[path_len-1] == 'p')) {

      return &path[path_len-4];
    }
  }

  return NULL;
}

static char *tar_get_flags(char *path, size_t path_len, unsigned long *flags) {
  char *ptr;

  ptr = tar_get_ext_tar(path, path_len);
  if (ptr != NULL) {
    *flags |= TAR_ARCHIVE_FL_USE_USTAR;

  } else {
    ptr = tar_get_ext_tgz(path, path_len);
    if (ptr != NULL) {
      *flags |= TAR_ARCHIVE_FL_USE_USTAR;
      *flags |= TAR_ARCHIVE_FL_USE_GZIP;

    } else {
      ptr = tar_get_ext_targz(path, path_len);
      if (ptr != NULL) {
        *flags |= TAR_ARCHIVE_FL_USE_USTAR;
        *flags |= TAR_ARCHIVE_FL_USE_GZIP;

      } else {
        ptr = tar_get_ext_tbz2(path, path_len);
        if (ptr != NULL) {
          *flags |= TAR_ARCHIVE_FL_USE_USTAR;
          *flags |= TAR_ARCHIVE_FL_USE_BZIP2;

        } else {
          ptr = tar_get_ext_tarbz2(path, path_len);
          if (ptr != NULL) {
            *flags |= TAR_ARCHIVE_FL_USE_USTAR;
            *flags |= TAR_ARCHIVE_FL_USE_BZIP2;

          } else {
            ptr = tar_get_ext_zip(path, path_len);
            if (ptr != NULL) {
              *flags |= TAR_ARCHIVE_FL_USE_ZIP;
            }
          }
        }
      }
    }
  }

  if (*flags == 0) {
    return NULL;
  }

  return ptr;
}

/* Configuration handlers
 */

/* usage: TarEnable on|off */
MODRET set_tarenable(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: TarEngine on|off */
MODRET set_tarengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* usage: TarLog path|"none" */
MODRET set_tarlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: TarOptions opt1 opt2 ... */
MODRET set_taroptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "FollowSymlinks") == 0 ||
        strcmp(cmd->argv[i], "dereference") == 0) {
      opts |= TAR_OPT_DEREF_SYMLINKS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown TarOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: TarTempPath path */
MODRET set_tartemppath(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET tar_post_pass(cmd_rec *cmd) {
  config_rec *c;

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TarEngine", FALSE);
  if (c) {
    int enable_tar = *((int *) c->argv[0]);

    if (enable_tar) {
      tar_engine = TRUE;
    }
  }

  if (tar_engine) {
    pr_event_register(&tar_module, "core.exit", tar_exit_ev, NULL);

    c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TarOptions", FALSE);
    while (c != NULL) {
      unsigned long opts;

      pr_signals_handle();

      opts = *((unsigned long *) c->argv[0]);
      tar_opts |= opts;

      c = find_config_next(c, c->next, CONF_PARAM, "TarOptions", FALSE);
    }

    c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TarTempPath", FALSE);
    if (c) {
      tar_tmp_path = dir_canonical_path(session.pool, c->argv[0]);

      if (session.chroot_path) {
        size_t chroot_len;

        chroot_len = strlen(session.chroot_path);
        if (strncmp(tar_tmp_path, session.chroot_path, chroot_len) == 0) {
          tar_tmp_path += chroot_len;
        }
      }

      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "using '%s' as the staging directory for temporary .tar files",
        tar_tmp_path);
    }
  }

  return PR_DECLINED(cmd);
}

MODRET tar_pre_retr(cmd_rec *cmd) {
  char *path, *tmp;
  size_t path_len;

  if (tar_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  path = pr_fs_decode_path(cmd->tmp_pool, cmd->arg);

  /* If dir_realpath() returns non-NULL here, then the requested path
   * exists; we should not try to handle it in that case.
   */
  tmp = dir_realpath(cmd->tmp_pool, path);
  if (tmp != NULL) {
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "path '%s' already exists, skipping", tmp);
    return PR_DECLINED(cmd);
  }

  /* Check if the requested path ends in ".tar", ".tar.gz", ".tgz",
   * or ".tar.bz2".  If it does, check if the name leading up to that
   * extension is a directory.  If both of these conditions are met, we can
   * proceed.
   */

  path_len = strlen(path);
  if (path_len > 4) {
    char *dir, *notar_file, *ptr, *tar_file;
    int fd, res;
    struct stat st;
    config_rec *d;
    unsigned long flags = 0UL;

    ptr = tar_get_flags(path, path_len, &flags);
    if (ptr == NULL) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "no .tar file extension found in '%s'", path);
      return PR_DECLINED(cmd);
    }
 
    *ptr = '\0';

    path = dir_realpath(cmd->tmp_pool, path);

    res = dir_exists(path);
    if (res == 0) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "'%s' is not a directory, ignoring", path);
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    /* Check for a "$dir/.notar" file, for backward compatibility with
     * wu-ftpd.
     */
    notar_file = pdircat(cmd->tmp_pool, path, ".notar", NULL);

    if (file_exists(notar_file)) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "'%s' present, skipping tar file of '%s' directory", notar_file,
        path);
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    /* Check for "TarEnable off" for this directory.  Make sure we check
     * for any possible .ftpaccess files in the target directory which
     * may contain a TarEnable configuration.
     */
    if (pr_fsio_lstat(path, &st) == 0) {
      build_dyn_config(cmd->pool, path, &st, TRUE);
    }

    d = dir_match_path(cmd->tmp_pool, path);
    if (d) {
      config_rec *c;

      c = find_config(d->subset, CONF_PARAM, "TarEnable", FALSE);
      if (c) {
        int tar_enable;

        tar_enable = *((int *) c->argv[0]);
        if (tar_enable == FALSE) {
          (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
            "'TarEnable off' found, skipping tar file of '%s' directory", path);
          *ptr = '.';
          return PR_DECLINED(cmd);
        }
      }

    } else {
      pr_trace_msg(trace_channel, 9,
        "no <Directory> match found for '%s'", path);
    }

    dir = strrchr(path, '/');
    if (dir == NULL) {
      dir = path;

    } else {
      dir++;
    }

    tar_file = pdircat(cmd->pool, tar_tmp_path, "XXXXXX", NULL);

    fd = mkstemp(tar_file);
    if (fd < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error creating temporary filename using mkstemp: %s",
        strerror(xerrno));
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    (void) fstat(fd, &st);
    close(fd);

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "writing temporary .tar file to '%s'", tar_file);

    /* Create the tar file. */
    res = tar_create_archive(cmd->tmp_pool, tar_file,
      (unsigned long) st.st_blksize, path, dir, flags);
    if (res < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error creating tar file '%s' from directory '%s': %s",
        tar_file, path, strerror(xerrno));
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    /* Stash this temporary filename. */
    if (pr_table_add(cmd->notes, pstrdup(cmd->pool, "mod_tar.tar-file"),
       tar_file, 0) < 0) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error stashing tar file in notes: %s", strerror(errno));
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    /* We also make a copy of the temporary filename elsewhere, in case
     * the client dies unexpectedly.
     */
    tar_tmp_file = pstrdup(session.pool, tar_file);

    /* And stash a copy of the originally requested directory. */
    if (pr_table_add(cmd->notes, pstrdup(cmd->pool, "mod_tar.orig-path"),
        pstrdup(cmd->pool, path), 0) < 0) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error stashing original path in notes: %s", strerror(errno));
      *ptr = '.';
      return PR_DECLINED(cmd);
    }

    *ptr = '.';

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "replaced 'RETR %s' with 'RETR %s'", cmd->arg, tar_file);
    cmd->arg = tar_file;
  }

  return PR_DECLINED(cmd);
}

MODRET tar_log_retr(cmd_rec *cmd) {
  char *path;

  if (tar_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  path = pr_table_get(cmd->notes, "mod_tar.tar-file", NULL);
  if (path != NULL) {
    if (unlink(path) < 0) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error deleting '%s': %s", path, strerror(errno));

    } else {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "deleted tar file '%s'", path);
      tar_tmp_file = NULL;
    }
  }

  path = pr_table_get(cmd->notes, "mod_tar.orig-path", NULL);
  if (path != NULL) {
    /* Replace session.xfer.path, so that the TransferLog/ExtendedLogs
     * show the originally requested path, not the temporary filename
     * generated by mod_tar.
     */
    session.xfer.path = path;
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void tar_exit_ev(const void *event_data, void *user_data) {
  /* Clean up any temporary tar files which we might have left around because
   * the client exited uncleanly.
   */
  if (tar_tmp_file != NULL) {
    if (unlink(tar_tmp_file) < 0) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error deleting '%s': %s", tar_tmp_file, strerror(errno));

    } else {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "deleted tar file '%s'", tar_tmp_file);
      tar_tmp_file = NULL;
    }
  }
}

/* Initialization functions
 */

static int tar_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "TarLog", FALSE);
  if (c &&
      strncasecmp((char *) c->argv[0], "none", 5) != 0) {
    int res, xerrno;
    char *path;

    path = c->argv[0];

    PRIVS_ROOT
    res = pr_log_openfile(path, &tar_logfd, 0660);
    xerrno = errno;
    PRIVS_RELINQUISH

    switch (res) {
      case 0:
        break;

      case -1:
        pr_log_debug(DEBUG1, MOD_TAR_VERSION ": unable to open TarLog '%s': %s",
         path, strerror(xerrno));
        break;

      case PR_LOG_SYMLINK:
        pr_log_debug(DEBUG1, MOD_TAR_VERSION ": unable to open TarLog '%s': %s",
         path, "is a symlink");
        break;

      case PR_LOG_WRITABLE_DIR:
        pr_log_debug(DEBUG1, MOD_TAR_VERSION ": unable to open TarLog '%s': %s",
         path, "parent directory is world-writable");
        break;
    }
  }

  return 0;
}

static int tar_init(void) {
  pr_log_debug(DEBUG0, MOD_TAR_VERSION ": using libarchive %s",
    archive_version_string());
  return 0;
}

/* Module API tables
 */

static conftable tar_conftab[] = {
  { "TarEnable",	set_tarenable,		NULL },
  { "TarEngine",	set_tarengine,		NULL },
  { "TarLog",		set_tarlog,		NULL },
  { "TarOptions",	set_taroptions,		NULL },
  { "TarTempPath",	set_tartemppath,	NULL },
  { NULL }
};

static cmdtable tar_cmdtab[] = {
  { POST_CMD,		C_PASS, G_NONE, tar_post_pass,	FALSE,  FALSE },
  { PRE_CMD,		C_RETR,	G_NONE,	tar_pre_retr,	FALSE,	FALSE },
  { LOG_CMD,		C_RETR,	G_NONE,	tar_log_retr,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_RETR,	G_NONE,	tar_log_retr,	FALSE,	FALSE },
};

module tar_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "tar",

  /* Module config handler table */
  tar_conftab,

  /* Module command handler table */
  tar_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module init function */
  tar_init,

  /* Session init function */
  tar_sess_init,

  /* Module version */
  MOD_TAR_VERSION
};
