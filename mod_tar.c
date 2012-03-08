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
 * $Libraries: -ltar -lz -lbz2 $
 */

#include "conf.h"
#include "privs.h"

#include <libtar.h>
#include <zlib.h>
#include <bzlib.h>

#define MOD_TAR_VERSION		"mod_tar/0.3.3"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030101
# error "ProFTPD 1.3.1rc1 or later required"
#endif

module tar_module;

static int tar_engine = FALSE;
static int tar_logfd = -1;

static unsigned long tar_opts = 0UL;
#define TAR_OPT_DEREF_SYMLINKS		0x001

static const char *tar_tmp_path = "./";

static char *tar_tmp_file = NULL;

/* These are re-implementation of the tar_append_file() and tar_append_tree()
 * functions found in libtar.  We needed to implement them ourselves in order
 * to support options such as "deference", so that mod_tar's .tar files
 * follow symlinks (libtar's default behavior, hardcoded, is to NOT follow
 * symlink).
 */

struct tar_dev {
  dev_t td_dev;
  libtar_hash_t *td_h;
};
typedef struct tar_dev tar_dev_t;

struct tar_ino {
  ino_t ti_ino;
  char ti_name[MAXPATHLEN];
};
typedef struct tar_ino tar_ino_t;

static const char *trace_channel = "tar";

/* Necessary prototype */
static void tar_exit_ev(const void *, void *);

static int append_file(TAR *t, char *real_name, char *save_name) {
  struct stat st;
  int i, res;
  libtar_hashptr_t hp;
  tar_dev_t *td = NULL;
  tar_ino_t *ti = NULL;
  char path[PR_TUNABLE_PATH_MAX+1];

  if (!(tar_opts & TAR_OPT_DEREF_SYMLINKS)) {
    res = lstat(real_name, &st);

  } else {
    res = stat(real_name, &st);
  }

  if (res != 0)
    return -1;

  /* set header block */
  memset(&(t->th_buf), 0, sizeof(struct tar_header));
  th_set_from_stat(t, &st);

  /* set the header path */
  th_set_path(t, (save_name ? save_name : real_name));

  /* check if it's a hardlink */
  libtar_hashptr_reset(&hp);

  res = libtar_hash_getkey(t->h, &hp, &(st.st_dev),
    (libtar_matchfunc_t) dev_match);
  if (res != 0) {
    td = (tar_dev_t *) libtar_hashptr_data(&hp);

  } else {
    td = (tar_dev_t *) calloc(1, sizeof(tar_dev_t));
    if (td == NULL)
      return -1;

    td->td_dev = st.st_dev;
    td->td_h = libtar_hash_new(256, (libtar_hashfunc_t) ino_hash);

    if (td->td_h == NULL) {
      free(td);
      return -1;
    }

    if (libtar_hash_add(t->h, td) == -1) {
      libtar_hash_free(td->td_h, free);
      free(td);
      return -1;
    }
  }

  libtar_hashptr_reset(&hp);

  res = libtar_hash_getkey(td->td_h, &hp, &(st.st_ino),
    (libtar_matchfunc_t) ino_match);
  if (res != 0) {
    ti = (tar_ino_t *) libtar_hashptr_data(&hp);
    t->th_buf.typeflag = LNKTYPE;
    th_set_link(t, ti->ti_name);

  } else {
    ti = (tar_ino_t *)calloc(1, sizeof(tar_ino_t));
    if (ti == NULL)
      return -1;

    ti->ti_ino = st.st_ino;
    snprintf(ti->ti_name, sizeof(ti->ti_name), "%s",
      save_name ? save_name : real_name);
    libtar_hash_add(td->td_h, ti);
  }

  /* check if it's a symlink */
  if (TH_ISSYM(t)) {
    i = readlink(real_name, path, sizeof(path));
    if (i == -1)
      return -1;

    if (i >= PR_TUNABLE_PATH_MAX)
      i = PR_TUNABLE_PATH_MAX - 1;

    path[i] = '\0';
    th_set_link(t, path);
  }

  /* print file info */
  if (t->options & TAR_VERBOSE)
    th_print_long_ls(t);

  /* write header */
  res = th_write(t);
  if (res != 0)
    return -1;

  /* if it's a regular file, write the contents as well */
  if (TH_ISREG(t) &&
      tar_append_regfile(t, real_name) != 0)
    return -1;

  return 0;
}

static int append_tree(TAR *t, char *real_dir, char *save_dir) {
  char real_path[PR_TUNABLE_PATH_MAX+1];
  char save_path[PR_TUNABLE_PATH_MAX+1];
  struct dirent *dent;
  DIR *dirh;
  struct stat st;
  int res;

  res = append_file(t, real_dir, save_dir);
  if (res != 0)
    return -1;

  dirh = opendir(real_dir);
  if (dirh == NULL) {
    if (errno == ENOTDIR)
      return 0;

    return -1;
  }

  while ((dent = readdir(dirh)) != NULL) {
    pr_signals_handle();

    if (strcmp(dent->d_name, ".") == 0 ||
        strcmp(dent->d_name, "..") == 0)
      continue;

    memset(real_path, '\0', sizeof(real_path));
    snprintf(real_path, sizeof(real_path)-1, "%s/%s", real_dir, dent->d_name);

    if (save_dir) {
      memset(save_path, '\0', sizeof(save_path));
      snprintf(save_path, sizeof(save_path)-1, "%s/%s", save_dir, dent->d_name);
    }

    if (!(tar_opts & TAR_OPT_DEREF_SYMLINKS)) {
      res = lstat(real_path, &st);

    } else {
      res = stat(real_path, &st);
    }

    if (res != 0)
      return -1;

    if (S_ISDIR(st.st_mode)) {
      res = append_tree(t, real_path, (save_dir ? save_path : NULL));
      if (res != 0)
        return -1;

      continue;
    }

    res = append_file(t, real_path, (save_dir ? save_path : NULL));
    if (res != 0)
      return -1;
  }

  closedir(dirh);
  return 0;
}

static int tar_create_tar(tartype_t *type, char *dst_file, char *src_path,
    char *src_dir) {
  TAR *tar;

  if (tar_open(&tar, dst_file, type, O_WRONLY|O_CREAT, 0644, 0) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "unable to open '%s' as tar file: %s", dst_file, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (append_tree(tar, src_path, src_dir) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error appending '%s' to tar file: %s", src_path, strerror(xerrno));
    tar_close(tar);

    errno = xerrno;
    return -1;
  }

  if (tar_append_eof(tar) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error appending EOF to tar file: %s", strerror(xerrno));
    tar_close(tar);

    errno = xerrno;
    return -1;
  }

  if (tar_close(tar) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "error writing tar file: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int tar_bzopen(const char *path, int flags, mode_t mode) {
  int fd;
  BZFILE *bzf;

  fd = open(path, flags, mode);
  if (fd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "unable to open '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (flags & O_CREAT) {
    if (fchmod(fd, mode) < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error setting mode %04o on '%s': %s", mode, path, strerror(xerrno));

      close(fd);
      errno = xerrno;
      return -1;
    }
  }

  bzf = BZ2_bzdopen(fd, "wb");
  if (bzf == NULL) {
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "unable to open bzlib stream on '%s': Not enough memory", path);
    close(fd);
    errno = EPERM;
    return -1;
  }

  /* XXX I don't like doing this, returning a pointer in the space of
   * an int, but unfortunately it is the interface defined by libtar.
   */
  return (int) bzf;
}

static int tar_gzopen(const char *path, int flags, mode_t mode) {
  int fd;
  gzFile gzf;

  fd = open(path, flags, mode);
  if (fd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "unable to open '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (flags & O_CREAT) {
    if (fchmod(fd, mode) < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "error setting mode %04o on '%s': %s", mode, path, strerror(xerrno));

      close(fd);
      errno = xerrno;
      return -1;
    }
  }

  gzf = gzdopen(fd, "wb");
  if (gzf == NULL) {
    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "unable to open zlib stream on '%s': Not enough memory", path);
    close(fd);
    errno = EPERM;
    return -1;
  }

  /* XXX I don't like doing this, returning a pointer in the space of
   * an int, but unfortunately it is the interface defined by libtar.
   */
  return (int) gzf;
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

    return NULL;
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

    return NULL;
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

    return NULL;
  }

  return NULL;
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
    if (c) {
      tar_opts = *((unsigned long *) c->argv[0]);
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

  if (!tar_engine)
    return PR_DECLINED(cmd);

  if (cmd->argc < 2)
    return PR_DECLINED(cmd);

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
    int fd, res, use_tar = FALSE, use_gz = FALSE, use_bz2 = FALSE;
    struct stat st;
    config_rec *d;

    ptr = tar_get_ext_tar(path, path_len);
    if (ptr)
      use_tar = TRUE;

    if (ptr == NULL) {
      ptr = tar_get_ext_tgz(path, path_len);
      if (ptr)
        use_gz = TRUE;
    }

    if (ptr == NULL) {
      ptr = tar_get_ext_targz(path, path_len);
      if (ptr)
        use_gz = TRUE;
    }

    if (ptr == NULL) {
      ptr = tar_get_ext_tarbz2(path, path_len);
      if (ptr)
        use_bz2 = TRUE;
    }

    if (ptr == NULL) {
      (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
        "no .tar file extension found in '%s'", path);
      return PR_DECLINED(cmd);
    }
 
    *ptr = '\0';

    path = dir_realpath(cmd->tmp_pool, path);

    res = dir_exists(path);
    if (!res) {
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
        if (!tar_enable) {
          (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
            "TarEnable off found, skipping tar file of '%s' directory", path);
          *ptr = '.';
          return PR_DECLINED(cmd);
        }
      }
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

    close(fd);

    (void) pr_log_writefile(tar_logfd, MOD_TAR_VERSION,
      "writing temporary .tar file to '%s'", tar_file);

    /* Create the tar file. */
    if (use_tar) {
      res = tar_create_tar(NULL, tar_file, path, dir);

    } else if (use_gz) {
      tartype_t gz_type = {
        (openfunc_t) tar_gzopen,
        (closefunc_t) gzclose,
        (readfunc_t) gzread,
        (writefunc_t) gzwrite
      };

      res = tar_create_tar(&gz_type, tar_file, path, dir);

    } else if (use_bz2) {
      tartype_t bz2_type = {
        (openfunc_t) tar_bzopen,
        (closefunc_t) BZ2_bzclose,
        (readfunc_t) BZ2_bzread,
        (writefunc_t) BZ2_bzwrite
      };

      res = tar_create_tar(&bz2_type, tar_file, path, dir);
    }

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

  if (!tar_engine)
    return PR_DECLINED(cmd);

  path = pr_table_get(cmd->notes, "mod_tar.tar-file", NULL);
  if (path) {
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
  if (path) {
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
  pr_log_debug(DEBUG0, MOD_TAR_VERSION ": using libtar %s", libtar_version);
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
