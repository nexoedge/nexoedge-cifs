/* 
 * Nexoedge SMB/CIFS VFS module.
 *
 * Copyright (C) Helen Chan 2019-2025
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "offload_token.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

#include <fcntl.h> /* O_XX flags */
#include <sys/types.h> /* utime() */
#include <utime.h> /* utime() */

#include <ncloud/client.h> /* nCloud client */

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * please make sure that you remove all skel_XXX() functions you don't
 * want to implement!! The passthrough operations are not
 * neccessary in a real module.
 *
 * --metze
 */

#define NCLOUD_BLOCK_SIZE (1 << 10)
#define NCLOUD_CACHE_DIR  ".cache"
#define NCLOUD_STORAGE_CLASS "STANDARD"
#define NCLOUD_BUF_SIZE_FACTOR (2)
#define NCLOUD_WRITE_TRACK_AHEAD_SIZE ((unsigned long int) 64 * 1 << 20)
#define NCLOUD_READ_BUF_MIN_SIZE ((unsigned long int) 16 * 1 << 20)
#define NCLOUD_DEFAULT_PORT (59001)
#define NCLOUD_DEFAULT_IP "127.0.0.1"

struct ncloud_data {
    char cwd[PATH_MAX];
    unsigned long int append_size;
    ncloud_conn_t conn;

    int namespace_id;
    bool cached_write;
    bool cached_read;
    int max_split_ahead;
    const char *storage_class;
    const char *zmq_ip;
    int zmq_port;
    time_t buffer_flush_timeout;
};

struct ncloud_buf {
    char *buf;
    unsigned long int size;
    union {
        unsigned long int length;
        unsigned long int offset;
    };
    unsigned long int starting_offset;
    time_t last_flush_ts;
    bool dirty;
};

struct ncloud_file_status {
    unsigned long int *written_bytes;
    unsigned long int read_size;
    bool truncate_to_zero;
    bool flush_on_close;
    bool is_sync;
    struct {
        struct ncloud_buf read;
        struct ncloud_buf write;
    } buf;
    struct {
        struct timeval open;
        double memcpy_time;
        double check_write_time;
    } perf;
    FILE *cache_fd;
};

/**
 * helper functions
 **/

static double get_duration(struct timeval start, struct timeval end) {
    return end.tv_usec * 1.0 / 1e6 - start.tv_usec * 1.0 / 1e6 + end.tv_sec - start.tv_sec;
}

/* cifs interface metadata */
static int ncloud_create_directory(char *parent, char *path, mode_t mode);
static int ncloud_update_meta_record(vfs_handle_struct *handle, char* pwd, char *cwd, bool create_empty_cache);
static void ncloud_add_to_list(name_compare_entry **list);
static int ncloud_get_filemeta(vfs_handle_struct *handle, char *fname, SMB_STRUCT_STAT *st, bool has_dir);
static int ncloud_operate_on_directory(vfs_handle_struct *handle, char *pwd, char *ndir, int op, char *odir);
static int ncloud_clean_up(vfs_handle_struct *handle);
static int ncloud_get_meta_entry_name(vfs_handle_struct *handle, const struct smb_filename *name, char *filepath);
static int _ncloud_rename_meta_entry(char *spath, char *dpath);
static int ncloud_rename_meta_entry(vfs_handle_struct *handle, const struct smb_filename *sname, const struct smb_filename *dname);

/* file-releted */
static int ncloud_rename_backend_file(vfs_handle_struct *handle, char *spath, char *dpath);
static unsigned long int ncloud_get_append_size(vfs_handle_struct *handle, const char *storage_class);
static unsigned long int ncloud_get_read_size(vfs_handle_struct *handle, const struct files_struct *fsp);
static ssize_t ncloud_check_and_write_if_needed(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t n, const void *data);
static ssize_t ncloud_check_and_read_if_needed(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t n, void *data);

static void ncloud_init_buf(struct ncloud_buf *buf) {
    if (buf == 0)
        return;

    buf->buf = 0;
    buf->offset = 0;
    buf->starting_offset = 0;
    buf->dirty = false;
    buf->last_flush_ts = 0;
}

static void ncloud_reinit_buf(struct ncloud_buf *buf) {
    if (buf == 0)
        return;

    buf->offset = 0;
    buf->starting_offset = 0;
    buf->dirty = false;
    buf->last_flush_ts = 0;
}

static int ncloud_init_file_status(struct ncloud_data *ncloud_handle, files_struct *fsp, struct ncloud_file_status *status) {
    if (fsp == 0 || status == 0) {
        errno = EINVAL;
        return -1;
    }

    int max_split_ahead = ncloud_handle->max_split_ahead;

    status->read_size = 0;
    /* buffer */
    ncloud_init_buf(&status->buf.read);
    ncloud_init_buf(&status->buf.write);
    status->flush_on_close = false;
    /* file access status */
    status->truncate_to_zero = false;
    status->is_sync = false;
    /* split tracking indices */
    status->written_bytes = talloc_array(fsp, unsigned long int, max_split_ahead);
    if (status->written_bytes == NULL) {
        errno = ENOMEM;
        return -1;
    }
    for (int i = 0; i < max_split_ahead; i++)
        status->written_bytes[i] = 0;
    /* open time */
    gettimeofday(&status->perf.open, NULL);
    status->perf.memcpy_time = 0.0;
    status->cache_fd = NULL;
}

static void ncloud_reinit_buffers(struct ncloud_file_status *status) {
    ncloud_reinit_buf(&status->buf.read);
    ncloud_reinit_buf(&status->buf.write);
}

static int ncloud_create_directory(char *parent, char *path, mode_t mode) {
    char dpath[PATH_MAX];
    /* check if the path contains at least one directory */
    char *end_idx = strchr(path, '/'), *next_idx = NULL;
    if (end_idx == NULL)
        return 0;
    /* create the levels of directories */
    do {
        /* probe if there is a next level of directory to create */
        next_idx = strchr(end_idx + 1, '/');
        snprintf(dpath, PATH_MAX, "%s/%.*s", parent, (int)(end_idx - path), path);
        DEBUG(4, ("[NCLOUD] Create directory %s\n", dpath));
        /* create the current level directory if not exists */
        struct stat sb;
        int ret = stat(dpath, &sb);
        if (ret == -1 && errno == ENOENT) {
            if (mkdir(dpath, mode) != 0) {
                if (errno != EEXIST)
                    return -1;
                /* update the permission if already exists */
                //chmod(dpath, mode);
            }
            DEBUG(3, ("[NCLOUD] Created directory %s\n", dpath));
        } else if (ret == 0 && S_ISDIR(sb.st_mode)) {
            chmod(dpath, mode);
        } else if (ret == -1 || !S_ISDIR(sb.st_mode)) {
            return -1;
        }
        end_idx = next_idx;
    } while (end_idx != NULL);
    return 0;
}

static int ncloud_update_meta_record(vfs_handle_struct *handle, char* pwd, char *cwd, bool create_empty_cache) {
    /* get the list of files */
    request_t req;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    set_get_file_list_request(&req, ncloud_handle->namespace_id, cwd);
    send_request(&ncloud_handle->conn, &req);

    char filepath[PATH_MAX];

    /* create meta directory */
    size_t pathlen = strlen(pwd) + 1;
    if (pathlen + 1 > PATH_MAX) {
        DEBUG(1, ("[NCLOUD] Failed to create metadata directory, name too long\n"));
        request_t_release(&req);
        errno = ENAMETOOLONG;
        return -1;
    }
    /* process the file list */
    for (unsigned int i = 0; i < req.file_list.total; i++) {
        pathlen = strlen(req.file_list.list[i].fname) + strlen(pwd) + 1;
        if (pathlen + 1 > PATH_MAX) {
            DEBUG(1, ("[NCLOUD] The name of file %s is too long for the OS\n", req.file_list.list[i].fname)); 
            continue;
        }
        if (ncloud_create_directory(pwd, req.file_list.list[i].fname, 0777) != 0) {
            DEBUG(1, ("[NCLOUD] Failed to create directory for file record %s\n", req.file_list.list[i].fname));
            continue;
        }
        snprintf(filepath, PATH_MAX, "%s/%s", pwd, req.file_list.list[i].fname);
        DEBUG(4, ("[NCLOUD] File %s (%lu)\n", req.file_list.list[i].fname, req.file_list.list[i].fsize));
        FILE *f = 0;
        /* only add/update the record if information is out-dated */
        snprintf(filepath, PATH_MAX, "%s/%s", pwd, req.file_list.list[i].fname);
        SMB_STRUCT_STAT sbuf;
        int meta_found = ncloud_get_filemeta(handle, req.file_list.list[i].fname, &sbuf, /* has_dir */ true);
        if (
                access(filepath, F_OK) == -1 ||
                meta_found == -1 ||
                sbuf.st_ex_size != req.file_list.list[i].fsize ||
                sbuf.st_ex_ctime.tv_sec != req.file_list.list[i].ctime ||
                sbuf.st_ex_atime.tv_sec != req.file_list.list[i].atime ||
                sbuf.st_ex_mtime.tv_sec != req.file_list.list[i].mtime
        ) {
            DEBUG(3, (
                    "[NCLOUD] Create entry for file %s access %d meta found %d size %d ctime %d atime %d mtime %d\n"
                    , req.file_list.list[i].fname
                    , access(filepath, F_OK)
                    , meta_found == -1
                    , sbuf.st_ex_size != req.file_list.list[i].fsize
                    , sbuf.st_ex_ctime.tv_sec != req.file_list.list[i].ctime
                    , sbuf.st_ex_atime.tv_sec != req.file_list.list[i].atime
                    , sbuf.st_ex_mtime.tv_sec != req.file_list.list[i].mtime
            ));
            f = fopen(filepath, "w");
            if (f) {
                fprintf(f, "%lu;%lu;%lu;%lu",
                    req.file_list.list[i].fsize,
                    req.file_list.list[i].ctime,
                    req.file_list.list[i].atime,
                    req.file_list.list[i].mtime
                );
                fclose(f);
            } else {
                DEBUG(1, ("[NCLOUD] Failed to create entry for file %s\n", req.file_list.list[i].fname));
            }
        }
    }
    int total = req.file_list.total;
    /* release the file list */
    request_t_release(&req);
    return total;
}

/* hide the system folders (and files) */
static void ncloud_add_to_list(name_compare_entry **list) {
       size_t i, count = 0;
       name_compare_entry *new_list = 0;
       name_compare_entry *cur_list = 0;

       cur_list = *list;

       if (cur_list) {
               for (i = 0, count = 0; cur_list[i].name; i ++, count ++) {
                       if (strstr_m(cur_list[i].name, NCLOUD_CACHE_DIR))
                               return;
               }
       }

       if (!(new_list = SMB_CALLOC_ARRAY(name_compare_entry, count + 2)))
               return;

       for (i = 0; i < count; i ++) {
               new_list[i].name    = SMB_STRDUP(cur_list[i].name);
               new_list[i].is_wild = cur_list[i].is_wild;
       }

       new_list[i].name    = SMB_STRDUP(NCLOUD_CACHE_DIR);
       new_list[i].is_wild = False;

       free_namearray(*list);

       *list = new_list;
       new_list = 0;
       cur_list = 0;
}



static int ncloud_get_filemeta(vfs_handle_struct *handle, char *fname, SMB_STRUCT_STAT *st, bool has_dir) {
    char filepath[PATH_MAX];
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    int pathlen = strlen(handle->conn->connectpath) + strlen(fname) + 1;
    if (pathlen + 1 <= PATH_MAX) {
        /* get the file size from the metadata file */
        if (has_dir) {
            snprintf(filepath, PATH_MAX, "%s/%s", handle->conn->connectpath, fname);
        } else {
            snprintf(filepath, PATH_MAX, "%s/%s/%s", handle->conn->connectpath, ncloud_handle->cwd, fname);
        }
        DEBUG(3, ("[NCLOUD] get file meta on path %s (cwd = %s) has_dir = %d\n", fname, ncloud_handle->cwd, has_dir));
        FILE *f = fopen(filepath, "r");
        if (f != NULL) {
            bool okay = fscanf(f, "%lu;%lu;%lu;%lu", 
                &st->st_ex_size,
                &st->st_ex_ctime.tv_sec,
                &st->st_ex_atime.tv_sec,
                &st->st_ex_mtime.tv_sec
            ) == 4;
            if (okay) {
                st->st_ex_blksize = NCLOUD_BLOCK_SIZE;
                st->st_ex_blocks = (st->st_ex_size + NCLOUD_BLOCK_SIZE - 1) / st->st_ex_blksize;
                st->st_ex_ctime.tv_nsec = 0;
                st->st_ex_atime.tv_nsec = 0;
                st->st_ex_mtime.tv_nsec = 0;
            }
            fclose(f);
            return okay? 0 : -1;
        }
    } else {
        errno = ENAMETOOLONG;
        return -1;
    }
    return -1;
}

static int ncloud_operate_on_directory(vfs_handle_struct *handle, char *pwd, char *ndir, int op, char *odir) {
    char filepath[PATH_MAX], dfilepath[PATH_MAX];
    bool ret = 0;

    snprintf(filepath, PATH_MAX, "%s/%s", pwd, ndir);
    DIR *dir = opendir(filepath);

    struct dirent *item = 0;
    if (dir != NULL) {
        while((item = readdir(dir)) != NULL) {
            /** 
             * skip if the entry is
             * (1) is neither a regular file nor directory
             * (2) is "."
             * (3) is ".."
             **/
            if (
                (!(item->d_type & DT_REG) && !(item->d_type & DT_DIR)) ||
                ISDOT(item->d_name) ||
                ISDOTDOT(item->d_name)
            ) {
                continue;
            }
            snprintf(filepath, PATH_MAX, "%s/%s/%s", pwd, ndir, item->d_name);
            if (item->d_type & DT_DIR) {
                switch (op) {
                case 0: /* delete */
                    DEBUG(4, ("{NCLOUD] Clean up directory %s\n", filepath));
                    /* handle directory (recursively) , skip the first '/' */
                    ncloud_operate_on_directory(handle, "", &filepath[1], op, odir);
                    /* remove the empty directory */
                    if (rmdir(filepath) != 0)
                        DEBUG(3, ("[NCLOUD] Failed to rmdir %s, %s, %d\n", filepath, strerror(errno), errno));
                    break;

                case 1: /* rename */
                    snprintf(dfilepath, PATH_MAX, "%s/%s/%s", pwd, ndir, item->d_name);
                    snprintf(filepath, PATH_MAX, "%s/%s/%s", pwd, odir, item->d_name);
                    ncloud_operate_on_directory(handle, pwd, &dfilepath[strlen(pwd) + 1], op, &filepath[strlen(pwd) + 1]);
                    break;

                default:
                    break;
                }
            } else {
                switch (op) {
                case 0: /* delete */
                    /* remove the file */
                    if (unlink(filepath) != 0)
                        DEBUG(3, ("[NCLOUD] Failed to unlink %s, %s, %d\n", filepath, strerror(errno), errno));
                        break;

                case 1: /* rename */
                    snprintf(filepath, PATH_MAX, "%s/%s", odir, item->d_name);
                    snprintf(dfilepath, PATH_MAX, "%s/%s", ndir, item->d_name);
                    ret = ncloud_rename_backend_file(handle, filepath, dfilepath);
                    break;

                default:
                    break;
                }
            }
        }
        closedir(dir);
    } else {
        DEBUG(3, ("[NCLOUD] Failed to operate on directory %s\n", filepath));
    }

    return ret;
}

static int ncloud_clean_up(vfs_handle_struct *handle) {
    DEBUG(4, ("[NCLOUD] clean up\n"));
    /* TODO flush cache */
    /* remove cache entries (and metadata entries within the same folder) */
    char filepath[PATH_MAX];
    int pathlen = 0; 
    ncloud_operate_on_directory(handle, "", &handle->conn->connectpath[1], 0 /* delete */, NULL);
}

static int ncloud_get_meta_entry_name(vfs_handle_struct *handle, const struct smb_filename *name, char *filepath) {
    return snprintf(filepath, PATH_MAX, "%s/%s", handle->conn->connectpath, name->base_name);
}

static int _ncloud_rename_meta_entry(char *spath, char *dpath) {
    if (rename(spath, dpath) != 0) {
        DEBUG(2, ("[NCLOUD] Failed to rename metadata entry\n"));
        return -1;
    }
    return 0;
}

static int ncloud_rename_meta_entry(vfs_handle_struct *handle, const struct smb_filename *sname, const struct smb_filename *dname) {
    char spath[PATH_MAX], dpath[PATH_MAX];
    ncloud_get_meta_entry_name(handle, sname, spath);
    ncloud_get_meta_entry_name(handle, dname, dpath);
    return _ncloud_rename_meta_entry(spath, dpath);
}

static int ncloud_rename_backend_file(vfs_handle_struct *handle, char *spath, char *dpath) {
    request_t req;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    if (set_file_rename_request(&req, spath, dpath, ncloud_handle->namespace_id) == -1) {
        DEBUG(1, ("[NCLOUD] Failed to set file rename request %s %s\n", spath, dpath));
        errno = EINVAL;
        return -1;
    }
    ncloud_conn_t *conn = &ncloud_handle->conn;
    if (send_request(conn, &req) == -1) {
        DEBUG(1, ("[NCLOUD] Failed to rename file %s %s, target exists\n", spath, dpath));
        request_t_release(&req);
        errno = EEXIST;
        return -1;
    }
    request_t_release(&req);
    return 0;
}


static unsigned long int ncloud_get_append_size(vfs_handle_struct *handle, const char * storage_class) {
    unsigned long int size = 0;
    request_t req;
    ncloud_conn_t *conn = &((struct ncloud_data *) handle->data)->conn;
    if (set_get_append_size_request(&req, storage_class) == -1 || send_request(conn, &req) == -1) {
        DEBUG(1, ("[NCLOUD] Failed to get the append size\n"));
    } else {
        size = req.file.length;
    }
    request_t_release(&req);
    return size;
}

static unsigned long int ncloud_get_read_size(vfs_handle_struct *handle, const struct files_struct *fsp) {
    unsigned long int size = 0;
    request_t req;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    ncloud_conn_t *conn = &ncloud_handle->conn;
    if (!fsp || !fsp->fsp_name || set_get_read_size_request(&req, fsp->fsp_name->base_name, ncloud_handle->namespace_id) == -1 || send_request(conn, &req) == -1) {
        DEBUG(2, ("[NCLOUD] Failed to get the read size for file %s\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)"));
        req.file.length = 0;
    }
    size = req.file.length;
    request_t_release(&req);
    return size;
}

static bool ncloud_open_cache_file(vfs_handle_struct *handle, struct files_struct *fsp, bool is_read) {
    char cache_path[PATH_MAX], *idx = cache_path + strlen(fsp->conn->connectpath) + strlen(NCLOUD_CACHE_DIR) + 3;
    snprintf(cache_path, PATH_MAX, "%s/%s/%s", handle->conn->connectpath, NCLOUD_CACHE_DIR, smb_fname_str_dbg(fsp->fsp_name));
    while (1) {
        idx = strstr(idx, "/");
        if (idx == NULL)
            break;
        *idx = '\n';
    }
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 
    file_status->cache_fd = fopen(cache_path, "r+");
    /* if a cache file needs to be read, it should already exist. So, only create a new one for write */
    if (file_status->cache_fd == NULL && !is_read) {
        DEBUG(2, ("[NCLOUD] Cache file (%s) not exists, create one instead\n", cache_path));
        file_status->cache_fd = fopen(cache_path, "w+");
    }
    if (file_status->cache_fd == NULL) {
        DEBUG(1, ("[NCLOUD] Failed to open the cache file (%s), %s\n", cache_path, strerror(errno)));
        return false;
    }
    return true;
}

/**
 * Write/Read data to cache file, returns n on success, 0 on failure
 */
static ssize_t ncloud_access_cache_file(vfs_handle_struct *handle, struct files_struct *fsp, void *data, size_t n, off_t offset, bool is_read) { 
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 

    /* open file on first read / write */
    if (file_status->cache_fd == NULL && !ncloud_open_cache_file(handle, fsp, /* is_read */ is_read)) {
        DEBUG(1, ("[NCLOUD] Failed to get the cache file of file %s ready for %s\n", smb_fname_str_dbg(fsp->fsp_name), is_read? "read" : "write"));
        return -1;
    }

    /* seek to target offset before write */
    if (fseek(file_status->cache_fd, offset, SEEK_SET) != 0) {
        DEBUG(1, ("[NCLOUD] Failed to seek to proper offset %ld before %s\n", offset, is_read? "read" : "write"));
        return -1;
    }

    /* write until all bytes are out */
    int accessed_bytes = 0;
    while (accessed_bytes != -1 && accessed_bytes < n) {
        if (is_read)
            accessed_bytes += fread(data + accessed_bytes, 1, n - accessed_bytes, file_status->cache_fd);
        else
            accessed_bytes += fwrite(data + accessed_bytes, 1, n - accessed_bytes, file_status->cache_fd);
    }
    /* flush after write */
    if (accessed_bytes != -1 && !is_read)
        fflush(file_status->cache_fd);

    /* report error */
    if (accessed_bytes == -1) {
        DEBUG(1, ("[NCLOUD] Failed to write to cache file at offset %ld and length %ld (err = %s)\n", offset, n, strerror(errno)));
        return -1;
    } else {
        DEBUG(3, ("[NCLOUD] Write to cache file at offset %ld and length %ld (err = %s)\n", offset, n, strerror(errno)));
    }
    return n;
}

static ssize_t ncloud_write_cache_file(vfs_handle_struct *handle, struct files_struct *fsp, const void *data, size_t n, off_t offset) { 
    return ncloud_access_cache_file(handle, fsp, (void *) data, n, offset, /* is_read */ false);
}

static ssize_t ncloud_read_cache_file(vfs_handle_struct *handle, struct files_struct *fsp, void *data, size_t n, off_t offset) {
    return ncloud_access_cache_file(handle, fsp, data, n, offset, /* is_read */ true);
}

static bool ncloud_close_cache_file(vfs_handle_struct *handle, struct files_struct *fsp) {
    char cache_path[PATH_MAX], *idx = cache_path + strlen(fsp->conn->connectpath) + strlen(NCLOUD_CACHE_DIR) + 3;
    snprintf(cache_path, PATH_MAX, "%s/%s/%s", handle->conn->connectpath, NCLOUD_CACHE_DIR, smb_fname_str_dbg(fsp->fsp_name));
    while (1) {
        idx = strstr(idx, "/");
        if (idx == NULL)
            break;
        *idx = '\n';
    }
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 
    if (file_status->cache_fd) {
        /* close the disk cache file */
        fclose(file_status->cache_fd);
        file_status->cache_fd = NULL;
        /* remove the disk cache file (cleanup and reduce inode usage) */
        unlink(cache_path);
    }
    return true;
}

static ssize_t ncloud_overwrite_file(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t length, const void *data) {
        /* send the updated data */
        request_t req;
        struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
        struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 
        ncloud_conn_t *conn = &ncloud_handle->conn;

        if (set_buffered_file_overwrite_request(
                &req
                , fsp->fsp_name->base_name
                , (unsigned char *) data
                , offset
                , length
                , ncloud_handle->namespace_id
            ) == -1
            || send_request(conn, &req) != offset + length
        ) {
            request_t_release(&req);
            DEBUG(1, ("[NCLOUD] Failed to send overwrite request for file %s at %ld,%ld\n", fsp->fsp_name->base_name, offset, length));
            return -1;
        }

        /* release resources */
        request_t_release(&req);

        return length;
}

static ssize_t ncloud_overwrite_file_with_zeros(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t length) {
        unsigned char *zero_buf = (unsigned char *) talloc_zero_size(fsp, length);
        if (zero_buf == 0) {
            DEBUG(1, ("[NCLOUD] Failed to allocate zero buf of length %lu for overwrite request on file %s at %ld\n", length, fsp->fsp_name->base_name, offset));
            return -1;
        }
        ssize_t ret = ncloud_overwrite_file(handle, fsp, offset, length, zero_buf);
        talloc_free(zero_buf);
        return ret;
}

static ssize_t ncloud_check_and_write_if_needed(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t n, const void *data) {
    /**
     * append if the write is across splits of the expected append size
     * (call write if the starting offset of append is 0)
     * NOTE: if n == 0, flush all cached/buffered data
     **/
    ssize_t ret = n;

    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    const unsigned char *storage_class = ncloud_handle->storage_class;

    /* append size */
    unsigned long int append_size = 0;
    if (handle != 0) 
        append_size = ncloud_handle->append_size;
    if (append_size == 0)
        append_size = ncloud_get_append_size(handle, storage_class);
    /* do not proceed if failed to get the append size (avoid division error) */
    if (append_size == 0) {
        DEBUG(1, ("[NCLOUD] Failed to get the append size\n"));
        return -1;
    } else {
        ncloud_handle->append_size = append_size;
    }

    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 

    if (file_status == NULL) {
        DEBUG(1, ("[NCLOUD] status of file %s is NULL\n", fsp->fsp_name->base_name));
        errno = EINVAL;
        return -1;
    }

    /* check if the file size is updated (and move the offset forward accordingly) */
    if (file_status->written_bytes[0] == 0) {
        DEBUG(4, ("[NCLOUD] b4 update write buffer offset of file %s from %lu, append size=%lu, size=%lu\n", fsp->fsp_name->base_name, file_status->buf.write.starting_offset, append_size, fsp->fsp_name->st.st_ex_size));
        ncloud_get_filemeta(handle, fsp->fsp_name->base_name, &fsp->fsp_name->st, /* has_dir */ true);
        DEBUG(4, ("[NCLOUD] update write buffer offset of file %s to %lu, append size=%lu, size=%lu\n", fsp->fsp_name->base_name, file_status->buf.write.starting_offset, append_size, fsp->fsp_name->st.st_ex_size));
    }

    /* local file-ending offset for write */
    unsigned long int last_write_offset = file_status->buf.write.starting_offset;
    /* remote file-ending offset for append */
    int st_split_idx = (offset - last_write_offset) / append_size;

    bool write_beyond_next_stripe = offset >= last_write_offset;
    bool last_stripe_not_full = fsp->fsp_name->st.st_ex_size < last_write_offset;
    bool need_gap_filling = write_beyond_next_stripe && last_stripe_not_full;

    /* fill up the last stripe before append if needed */
    if (n > 0 && need_gap_filling) {
        unsigned long int length_to_fill = last_write_offset - fsp->fsp_name->st.st_ex_size;
        DEBUG(1, ("[NCLOUD] Fill last stripe with zeros for file %s at %lu of length %lu (next stripe offset = %lu, file size = %lu, %x)\n", fsp->fsp_name->base_name, offset, length_to_fill, last_write_offset, fsp->fsp_name->st.st_ex_size, fsp));
        if (ncloud_overwrite_file_with_zeros(handle, fsp, offset, length_to_fill) != length_to_fill) {
                return -1;
        }
        if (last_write_offset > fsp->fsp_name->st.st_ex_size) {
            fsp->fsp_name->st.st_ex_size = last_write_offset;
        }
    }

    /* overwrite (after some append, or inside a newly opened existing file) */
    /* 
     * write is considered as an overwrite if
     * not a flush and current write position is before the last write position of the file stream (i.e., the operation seeks backwards and writes)
     */
    if (!file_status->truncate_to_zero && n > 0 && offset < last_write_offset) {
        /* TODO wrap the procedure into ncloud_handle_overwrite(); */
        /* Important: assuming n is always less than aligned_length (data stripe size) */
        /* handle combination of overwrite and append, by only overwriting up to last_write_offset */

        /* only overwrite up to the next stripe */
        size_t length_to_overwrite = n;
        if (offset + length_to_overwrite > last_write_offset) {
                length_to_overwrite = last_write_offset - offset;
        }

        DEBUG(3, ("Overwrite range %s (last_write_ofs=%lu, ofs=%ld, n=%ld->to-write=%ld, fsize=%lu)\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)", last_write_offset, offset, n, length_to_overwrite, fsp->fsp_name->st.st_ex_size));

        if (ncloud_overwrite_file(handle, fsp, offset, length_to_overwrite, data) != length_to_overwrite) {
            return -1;
        }

        /* invalidate read cache if overwrite modifies data in its range */
        if (file_status->buf.read.starting_offset < offset + length_to_overwrite &&
                file_status->buf.read.starting_offset + file_status->buf.read.length > offset) {
                file_status->buf.read.length = 0;
        }

        /* adjust read size and file size if overwrite passes the current file size */
        if (offset + length_to_overwrite > fsp->fsp_name->st.st_ex_size) {
                fsp->fsp_name->st.st_ex_size = offset + length_to_overwrite;
                if (file_status->read_size < append_size)
                        file_status->read_size = ncloud_get_read_size(handle, fsp);
        }

        /* return if overwrite only */
        if (length_to_overwrite >= n)
            return n;

        /* adjust for append */
        ///* TODO handle overlapping with previously buffered but yet flushed data */
        ///* update the write (or now append) buffer starting offset if not allocated */
        //if (file_status->buf.write.starting_offset == 0 && (offset + length_to_overwrite) % append_size == 0 && offset + length_to_overwrite > fsp->fsp_name->st.st_ex_size) {
        //    last_write_offset = offset + length_to_overwrite;
        //    file_status->buf.write.starting_offset = last_write_offset;
        //    fsp->fsp_name->st.st_ex_size = last_write_offset;
        //}
        /* update the starting split index w.r.t. write buffer starting offset */
        st_split_idx = (offset + length_to_overwrite - last_write_offset) / append_size;
        /* update the append range w.r.t. write buffer */
        n -= length_to_overwrite;
        offset += length_to_overwrite;
        data += length_to_overwrite;
    }

    unsigned long int buffer_ending_offset = last_write_offset + file_status->buf.write.size;
    unsigned long int last_touched_offset = offset + n;
    if (last_touched_offset > buffer_ending_offset) {
            n = buffer_ending_offset - offset;
            ret -= last_touched_offset - buffer_ending_offset;
    }

    int ed_split_idx = n == 0? st_split_idx : (offset + n - last_write_offset - 1) / append_size;

    /* check if current write is behind the buffer */
    int max_split_ahead = ncloud_handle->max_split_ahead;
    if (st_split_idx >= max_split_ahead || ed_split_idx >= max_split_ahead) {
        DEBUG(1, ("Not enough splits index to track fragmented writes (%d-%d)\n", st_split_idx, ed_split_idx));
        return -1;
    }

    /* TODO use cached data for overwrite if available */
    /* allocate write buffer if not exists and this is not a flush (which has no new data coming in) */
    if (!ncloud_handle->cached_write && file_status->buf.write.buf == NULL && n > 0) {
        file_status->buf.write.buf = talloc_size(fsp, file_status->buf.write.size);
        if (file_status->buf.write.buf == NULL) {
            DEBUG(1, ("[NCLOUD] not enough memory for buffering splits of size %luB\n", file_status->buf.write.size));
            /* fall back to disk cache if memory is not enough */
            ncloud_handle->cached_write = 1;
            /* write to disk cache before processing */
            if (ncloud_write_cache_file(handle, fsp, data, n, offset) == -1) {
                DEBUG(1, ("[NCLOUD] Failed to fall back to cached write mode for file %s\n", fsp->fsp_name->base_name));
                return -1;
            }
        }
        DEBUG(2, ("[NCLOUD] allocate memory for buffering splits of size %luB for file %s\n", file_status->buf.write.size, fsp->fsp_name->base_name));
    }

    /*
    DEBUG(2, ("[NCLOUD] Write data at %ld size %ld into splits %d-%d write_buf = %p data = %p\n", offset, n, st_split_idx, ed_split_idx, file_status->buf.write.buf, data));
    */

    /* TODO handle overlapping with previously buffered but yet flushed data */
    /* copy data if buffered */
    struct timeval start, end;
    gettimeofday(&start, NULL);
    /* here we assume n is always smaller than NCLOUD_WRITE_TRACK_AHEAD_SIZE */
    if (!ncloud_handle->cached_write && n > 0)
        memcpy(file_status->buf.write.buf + (offset - last_write_offset), data, n);
    gettimeofday(&end, NULL);
    file_status->perf.memcpy_time += get_duration(start, end);
    
    /* update the number of bytes written to split */
    for (int i = st_split_idx; i <= ed_split_idx; i++) {
        unsigned long int split_st = last_write_offset + i * append_size;
        unsigned long int split_ed = last_write_offset + (i + 1) * append_size;
        unsigned long int split_last_write_ofs = split_st + file_status->written_bytes[i];
        char *split_buf = file_status->buf.write.buf + i * append_size;
        /* use split_last_write_ofs to calculate the amount of data change (delta), to avoid double counting overwrites */
        unsigned long int delta = 0;
        if (offset >= split_st) {
            /* first split */
            if (offset + n <= split_ed) {
                /* within the split */
                delta += offset + n - split_last_write_ofs;
            } else {
                /* starting split */
                delta += split_ed - split_last_write_ofs;
            }
        } else {
            /* middle / ending splits */
            if (offset + n <= split_ed) {
                /* ending splits */
                delta += offset + n - split_last_write_ofs;
            } else {
                /* middle (full) splits */
                delta += split_ed - split_last_write_ofs;
            }
        }
        if (delta <= append_size)
            file_status->written_bytes[i] += delta;
        /* try to ensure the written bytes is exactly one split... */
        if (file_status->written_bytes[i] > append_size)
            file_status->written_bytes[i] = append_size;
        /*
        if (i == 0 || i == 1)
            DEBUG(4, ("Split[%d] now has %lu B (ofs = %ld, n = %ld)\n", i, file_status->written_bytes[i], offset, n));
        */
    }

    /* send out the split and adjust the next pointer once fully written */
    int full_split_count = 0;
    unsigned long int len = 0;
    for (; full_split_count < max_split_ahead; full_split_count++) {
        /* skip empty or partially filled splits */
        if (file_status->written_bytes[full_split_count] != append_size) {
            /* count all remains in if n == 0 */
            if (n == 0 && file_status->written_bytes[full_split_count] > 0) {
                len += file_status->written_bytes[full_split_count];
                full_split_count++;
            }
            break;
        }
        /* accumulate full splits */
        len += file_status->written_bytes[full_split_count];
    }

    /* check if there is data behind the written data */
    bool move_buffer_data = false;
    for (int i = full_split_count; i < max_split_ahead; i++)
        if (file_status->written_bytes[i] > 0) {
            move_buffer_data = true;
            break;
        }

    bool is_flush_empty_file = last_write_offset == 0 && n == 0 && file_status->read_size == 0 && len == 0;
    if (len > 0 || is_flush_empty_file) {
        request_t req;
        unsigned long int ofs = last_write_offset;
        char empty_buf[1];

        char *cache_path = talloc_asprintf(talloc_tos(), "%s/%s/%s", fsp->conn->connectpath, NCLOUD_CACHE_DIR, smb_fname_str_dbg(fsp->fsp_name)); 
        char *idx = cache_path + strlen(fsp->conn->connectpath) + strlen(NCLOUD_CACHE_DIR) + 3; 
        while (1) {
            idx = strstr(idx, "/");
            if (idx == NULL)
                break;
            *idx = '\n';
        }
        ncloud_conn_t *conn = &ncloud_handle->conn;

        /* create the empty cache file for write */
        if (ncloud_handle->cached_write && is_flush_empty_file) {
            ncloud_open_cache_file(handle, fsp, /* is_read */ false);
        }

	int namespace_id = ncloud_handle->namespace_id;

        struct timeval start;
        gettimeofday(&start, NULL);
        if (ofs == 0) { /* write / overwrite (first split of file) */
            DEBUG(3, ("[NCLOUD] Write to file %s from offset %lu with size %lu\n", fsp->fsp_name->base_name, ofs, len));
            if (
                ( /* buffered write */
                    !ncloud_handle->cached_write &&
                    set_buffered_file_write_request(&req, fsp->fsp_name->base_name, len, len > 0? file_status->buf.write.buf : empty_buf, storage_class, namespace_id) == -1
                ) ||
                ( /* cached write */
                    ncloud_handle->cached_write &&
                    set_cached_file_write_request(&req, fsp->fsp_name->base_name, len, cache_path, storage_class, namespace_id) == -1 
                ) ||
                /* send write request */
                send_request(conn, &req) != len 
            ) {
                DEBUG(1, ("[NCLOUD] Failed to write file with size %lu\n", len));
                ret = -1;
            }
            file_status->read_size = ncloud_get_read_size(handle, fsp);
            ncloud_update_meta_record(handle, handle->conn->connectpath, fsp->fsp_name->base_name, true);
            fsp->fsp_name->st.st_ex_size = len;
        } else { /* append */
            DEBUG(3, ("[NCLOUD] Append to file %s from offset %lu with size %lu\n", fsp->fsp_name->base_name, ofs, len));
            if (
                ( /* buffered append */
                    !ncloud_handle->cached_write &&
                    set_buffered_file_append_request(&req, fsp->fsp_name->base_name, len > 0? file_status->buf.write.buf : empty_buf, ofs, len, namespace_id) == -1
                ) ||
                ( /* cached append */
                    ncloud_handle->cached_write &&
                    set_cached_file_append_request(&req, fsp->fsp_name->base_name, cache_path, ofs, len, namespace_id) == -1 
                ) ||
                /* send append request */
                send_request(conn, &req) != ofs + len
            ) {
                DEBUG(1, ("[NCLOUD] Failed to append file from offset %lu with size %lu\n", ofs, len));
                ret = -1;
            }
            ncloud_update_meta_record(handle, handle->conn->connectpath, fsp->fsp_name->base_name, true);
            if (ofs + len > fsp->fsp_name->st.st_ex_size)
                fsp->fsp_name->st.st_ex_size = ofs + len;
        }
        struct timeval end;
        gettimeofday(&end, NULL);
        double duration = get_duration(start, end);
        DEBUG(3, 
            ("[NCLOUD] write / append / overwrite completes speed = %.3f MB/s, size %.fMB in duration %.3f seconds\n", 
                len * 1.0 / (1 << 20) / duration, len * 1.0 / (1 << 20), duration
            )
        );

        TALLOC_FREE(cache_path);
        request_t_release(&req);
        DEBUG(4, ("[NCLOUD] Send %d splits\n", full_split_count));

        gettimeofday(&start, NULL);
        /* update the last write offset */
        file_status->buf.write.starting_offset += len;
        for (int i = 0; len > 0 && i < max_split_ahead; i++) {
            if (i < max_split_ahead - full_split_count) {
                file_status->written_bytes[i] = file_status->written_bytes[i + full_split_count];
                if (file_status->written_bytes[i] > 0 && !ncloud_handle->cached_write)
                    memcpy(
                        file_status->buf.write.buf + i * append_size, 
                        file_status->buf.write.buf + (i + full_split_count) * append_size, 
                        append_size
                    );
            } else {
                file_status->written_bytes[i] = 0;
            }
        }
        /* update the buffer only if there is data behind the written ones */
        /*
        if (len > 0 && !ncloud_handle->cached_write && move_buffer_data) {
            memmove(
                file_status->buf.write.buf,
                file_status->buf.write.buf + append_size * full_split_count, 
                append_size * (max_split_ahead - full_split_count)
            );
        }
        */
        gettimeofday(&end, NULL);
        file_status->perf.memcpy_time += get_duration(start, end);
    }

    return ret;
}

static bool ncloud_alloc_or_expand_read_buf(vfs_handle_struct *handle, struct files_struct *fsp) {
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp);
    unsigned long int buf_size = 0;

    if (file_status->read_size > NCLOUD_READ_BUF_MIN_SIZE) {
        buf_size = file_status->read_size * NCLOUD_BUF_SIZE_FACTOR;
        //file_status->buf.read.size = file_status->read_size * NCLOUD_BUF_SIZE_FACTOR;
    } else {
        //file_status->buf.read.size = NCLOUD_READ_BUF_MIN_SIZE * NCLOUD_BUF_SIZE_FACTOR;
        buf_size = NCLOUD_READ_BUF_MIN_SIZE * NCLOUD_BUF_SIZE_FACTOR;
    } 

    /* return directly if no change on buffer size is needed */
    if (buf_size == file_status->buf.read.size)
        return true;
    /* assigned new buffer size */
    file_status->buf.read.size = buf_size;
    /* free old buffer */
    if (file_status->buf.read.buf)
        talloc_free(file_status->buf.read.buf);
    /* allocate new buffer */
    file_status->buf.read.buf = talloc_size(fsp, file_status->buf.read.size);
    if (file_status->buf.read.buf == NULL) {
        DEBUG(2, ("[NCLOUD] Not enough memory for read buffer of size %lu (read size = %lu), switch to cached mode\n", file_status->buf.read.size, file_status->read_size));
        file_status->buf.read.size = 0;
        //ncloud_handle->cached_read = 1;
        return false;
    }
    /* reset length of data in new buffer to 0 */
    file_status->buf.read.length = 0;
    return true;
}

static ssize_t ncloud_check_and_read_if_needed(vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, size_t n, void *data) {
     /* TODO support random read */

    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp);

    unsigned long int append_size = ncloud_handle->append_size;
    int namespace_id = ncloud_handle->namespace_id;
    bool cached_read = ncloud_handle->cached_read;

    size_t bytes_read = 0;

    /* read passed EOF */
    if (offset > fsp->fsp_name->st.st_ex_size) {
        return 0;
    }

    /* try read from read cache */
    unsigned long int buffer_st = file_status->buf.read.starting_offset;
    unsigned long int buffer_ed = file_status->buf.read.starting_offset + file_status->buf.read.length;
    DEBUG(3, ("[NCLOUD] buffer (%lu,%lu) of file %s\n", buffer_st, buffer_ed, smb_fname_str_dbg(fsp->fsp_name)));
    /* track how many bytes copied for buffered data, and how many bytes are available for cached data */

    if (offset >= buffer_st && offset + n <= buffer_ed) {
        /* full content hit in buffer */
        if (!cached_read) {
            memcpy(data, file_status->buf.read.buf + offset - buffer_st, n);
        }
        bytes_read += n;
    } else if (offset >= buffer_st && offset < buffer_ed) {
        /* part of the content (at the front) is in buffer */
        unsigned long int len = buffer_ed - offset;
        if (!cached_read) {
            memcpy(data, file_status->buf.read.buf + (offset - buffer_st), len);
        }
        bytes_read += len;
    }

    if (bytes_read == n) {
        return bytes_read;
    }

    char *cache_path = talloc_asprintf(talloc_tos(), "%s/%s/%s", fsp->conn->connectpath, NCLOUD_CACHE_DIR, smb_fname_str_dbg(fsp->fsp_name)); 
    char *idx = cache_path + strlen(fsp->conn->connectpath) + strlen(NCLOUD_CACHE_DIR) + 3;
    while (1) {
        idx = strstr(idx, "/");
        if (idx == NULL)
            break;
        *idx = '\n';
    }
    ncloud_conn_t *conn = &ncloud_handle->conn;

    /* check append size */
    if (append_size == 0)
        append_size = ncloud_get_append_size(handle, ncloud_handle->storage_class);
    /* update read unit size */
    if (file_status->read_size <= 0) {
        /* read size */
        file_status->read_size = ncloud_get_read_size(handle, fsp);
        /* file does not exists?? */
        if (file_status->read_size <= 0)
            return -1;
    }
    /* allocate or expend buffer if not exists */
    if (!cached_read) {
        if (!ncloud_alloc_or_expand_read_buf(handle, fsp)) {
            return -1;
        }
    }

    /* find the starting stripe and ending stripe in the read range */
    unsigned long int read_size = file_status->read_size;
    int start_idx = (offset + bytes_read) / read_size;
    int end_idx = (offset + n) / read_size;

    /* read in a loop until getting all data */
    while (bytes_read < n) {
        request_t req;

        unsigned long int request_read_size = (end_idx - start_idx) * read_size;
        if (request_read_size == 0)
            request_read_size = read_size;

        if (!cached_read && request_read_size > file_status->buf.read.size)
            request_read_size = file_status->buf.read.size;

        /* read from nCloud */
        if (
            ( /* request read into buffer for buffered read */
                !cached_read &&
                set_buffered_file_partial_read_request(
                    &req,
                    fsp->fsp_name->base_name,
                    file_status->buf.read.buf,
                    start_idx * read_size,
                    request_read_size,
                    namespace_id
                ) == -1
            ) ||
            ( /* request read into cache for cached read */
                cached_read &&
                set_cached_file_partial_read_request(
                    &req,
                    fsp->fsp_name->base_name,
                    cache_path,
                    start_idx * read_size,
                    request_read_size,
                    namespace_id
                ) == -1
            )
        ) {
            DEBUG(1, ("[NCLOUD] Failed to set read file %s request on (%lu, %lu)\n", smb_fname_str_dbg(fsp->fsp_name), start_idx * read_size, request_read_size));
            request_t_release(&req);
            break;
        }
            
        if (send_request(conn, &req) == -1) {
            DEBUG(1, ("[NCLOUD] Failed to read file\n"));
            request_t_release(&req);
            break;
        } else {
            DEBUG(2, ("[NCLOUD] Read %lu bytes of file %s (%lu,%lu) from backend \n", req.file.size, smb_fname_str_dbg(fsp->fsp_name), start_idx * read_size, request_read_size));
            /* no more incoming data */
            if (req.file.size == 0) {
                request_t_release(&req);
                break;
            }
        }

        /* copy the data for buffered read */
        unsigned long int run_bytes_read = start_idx * read_size + (request_read_size > req.file.size? req.file.size : request_read_size) - (offset + bytes_read);
        if (run_bytes_read > n - bytes_read)
            run_bytes_read = n - bytes_read;
        /* adjust the number of bytes to copy and stop reading from backend if the number of bytes read is less than expected */
        if (req.file.size < request_read_size) {
            n = bytes_read + run_bytes_read;
        }
        if (!cached_read && run_bytes_read > 0) {
            memcpy(
                data + bytes_read,
                req.file.data + (offset + bytes_read - start_idx * read_size),
                run_bytes_read
            );
        }
        bytes_read += run_bytes_read;
        /* update buffer info */
        file_status->buf.read.starting_offset = start_idx * read_size;
        file_status->buf.read.length = req.file.size;
        start_idx += request_read_size / read_size;

        request_t_release(&req);
    }

    TALLOC_FREE(cache_path);

    return bytes_read;
}


/**
 * forward declarations
 **/

static int ncloud_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t offset);

static int ncloud_unlink(vfs_handle_struct *handle, const struct smb_filename *smb_fname);

/**
 * start of vfs functions
 **/

static int ncloud_connect(vfs_handle_struct *handle, const char *service,
            const char *user)
{
    int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

    /* make sure the directory is empty on start */
    /*ncloud_operate_on_directory("", &handle->conn->connectpath[1], 0, NULL);*/
    /* information */
    struct ncloud_data *ncloud_handle = (struct ncloud_data*) talloc(handle->conn, struct ncloud_data);
    if (ncloud_handle == NULL) {
        SMB_VFS_NEXT_DISCONNECT(handle);
        DEBUG(1, ("[NCLOUD] Not enough memory for ncloud_data\n"));
        errno = ENOMEM;
        return -1;
    }
    handle->data = ncloud_handle;
        
    ncloud_handle->zmq_port = lp_parm_int(SNUM(handle->conn), "ncloud", "port", NCLOUD_DEFAULT_PORT);
    ncloud_handle->zmq_ip = lp_parm_const_string(SNUM(handle->conn), "ncloud", "ip", NCLOUD_DEFAULT_IP);
    ncloud_handle->buffer_flush_timeout = lp_parm_int(SNUM(handle->conn), "ncloud", "buffer_flush_timeout", 15);
    ncloud_conn_t_init(ncloud_handle->zmq_ip, ncloud_handle->zmq_port, &ncloud_handle->conn, 1);

    /* get parameters */
    ncloud_handle->namespace_id = lp_parm_int(SNUM(handle->conn), "ncloud", "namespace_id", UNKNOWN_NAMESPACE_ID);
    ncloud_handle->storage_class = lp_parm_const_string(SNUM(handle->conn), "ncloud", "storage_class", NCLOUD_STORAGE_CLASS);
    ncloud_handle->cached_read = lp_parm_int(SNUM(handle->conn), "ncloud", "has_external_read_cache", 0);
    ncloud_handle->cached_write = lp_parm_int(SNUM(handle->conn), "ncloud", "has_external_write_cache", 0);
    /* get the expected append size */
    ncloud_handle->append_size = ncloud_get_append_size(handle, ncloud_handle->storage_class);
    if (ncloud_handle->append_size == 0) {
        SMB_VFS_NEXT_DISCONNECT(handle);
        DEBUG(1, ("[NCLOUD] Failed to get the append size on init\n"));
        errno = ENETDOWN;
        return -1;
    }
    /* guess the best-fitting split index length */
    int max_split_ahead = lp_parm_int(SNUM(handle->conn), "ncloud", "max_split_ahead", NCLOUD_WRITE_TRACK_AHEAD_SIZE / ncloud_handle->append_size);
    if (max_split_ahead < 2)
        max_split_ahead = 2;

    ncloud_handle->max_split_ahead = max_split_ahead;


    /* update file metadata */
    if (ret == 0) ncloud_update_meta_record(handle, handle->conn->connectpath, "/", true);

    /* create the cache directory */
    char cache_path[PATH_MAX];
    snprintf(cache_path, PATH_MAX, "%s/%s", handle->conn->connectpath, NCLOUD_CACHE_DIR);
    mkdir(cache_path, 0777);

    return ret;
}

static void ncloud_disconnect(vfs_handle_struct *handle)
{
    /*ncloud_clean_up(handle);*/
    SMB_VFS_NEXT_DISCONNECT(handle);
    ncloud_conn_t_release(&((struct ncloud_data *) handle->data)->conn);
}

static void ncloud_get_stats(vfs_handle_struct *handle, uint64_t bsize, uint64_t *dfree, uint64_t *dsize, uint64_t *fcount, uint64_t *flimit) {
    /* get the storage usage from ncloud */
    request_t req;
    set_get_storage_capacity_request(&req);
    ncloud_conn_t *conn = &((struct ncloud_data *) handle->data)->conn;
    send_request(conn, &req);
    /* disk free space (in blocks) */
    if (dfree)
        *dfree = req.stats.capacity > req.stats.usage? (req.stats.capacity - req.stats.usage) / bsize : 0;
    /* disk usage space (in blocks) */
    if (dsize)
        *dsize = req.stats.capacity / bsize;
    /* file count */
    if (fcount)
        *fcount = req.stats.file_count;
    /* max number of files */
    if (fcount)
        *flimit = req.stats.file_limit;
    /* release the resources */
    request_t_release(&req);
}

static uint64_t ncloud_disk_free(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                uint64_t *bsize,
                uint64_t *dfree,
                uint64_t *dsize)
{
    
    /* storage size in 1KiB */
    *bsize = NCLOUD_BLOCK_SIZE;
    ncloud_get_stats(handle, *bsize, dfree, dsize, 0, 0);
    return *dfree;
}

static int ncloud_get_quota(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                enum SMB_QUOTA_TYPE qtype,
                unid_t id,
                SMB_DISK_QUOTA *dq)
{
    errno = ENOSYS;
    return -1;
}

static int ncloud_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
              unid_t id, SMB_DISK_QUOTA *dq)
{
    errno = ENOSYS;
    return -1;
}

static int ncloud_get_shadow_copy_data(vfs_handle_struct *handle,
                     files_struct *fsp,
                     struct shadow_copy_data *shadow_copy_data,
                     bool labels)
{
    errno = ENOSYS;
    return -1;
}

static int ncloud_statvfs(struct vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            struct vfs_statvfs_struct *statbuf)
{
    int ret = SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
    uint64_t block_size = NCLOUD_BLOCK_SIZE;

    ncloud_get_stats(handle, block_size, &statbuf->BlocksAvail, &statbuf->TotalBlocks, &statbuf->FreeFileNodes, &statbuf->TotalFileNodes);
    /* other parameters */
    statbuf->UserBlocksAvail = statbuf->BlocksAvail;
    statbuf->OptimalTransferSize = 8 << 10;

    return 0;
}

static uint32_t ncloud_fs_capabilities(struct vfs_handle_struct *handle,
                     enum timestamp_set_resolution *p_ts_res)
{
    return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);
}

static NTSTATUS ncloud_get_dfs_referrals(struct vfs_handle_struct *handle,
                       struct dfs_GetDFSReferral *r)
{
    return SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
}

static DIR *ncloud_opendir(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            const char *mask,
            uint32_t attr)
{
    int baselen = strlen(handle->conn->connectpath);
    /* mark the current directory */
    char *cwd = ((struct ncloud_data*) handle->data)->cwd;
    char *handlecwd = handle->conn->cwd_fname->base_name;
    if (strlen(handlecwd) > baselen && strncmp(handle->conn->connectpath, handlecwd, baselen) == 0)
        snprintf(cwd, PATH_MAX, "%s/", handlecwd + baselen + 1);
    if (strcmp(cwd, "./") == 0 || strcmp(cwd, "") == 0)
        snprintf(cwd, PATH_MAX, "/");
    DEBUG(3, ("opendir %s %s %s\n", smb_fname? smb_fname->base_name : "(NIL)", handlecwd, cwd));
    /* update meta */
    bool update_dir_meta_on_open = lp_parm_int(SNUM(handle->conn), "ncloud", "update_dir_meta_on_open", 0);
    if (update_dir_meta_on_open) { ncloud_update_meta_record(handle, handle->conn->connectpath, cwd, false); }
    /* list the directory as usual */
    DIR *ret = SMB_VFS_NEXT_OPENDIR(handle, smb_fname, mask, attr);

    if (ret) {
        /* hide the cache directory */
        ncloud_add_to_list(&handle->conn->hide_list);
        ncloud_add_to_list(&handle->conn->veto_list);
    }

    return ret;
}

static NTSTATUS ncloud_snap_check_path(struct vfs_handle_struct *handle,
                     TALLOC_CTX *mem_ctx,
                     const char *service_path,
                     char **base_volume)
{
    return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ncloud_snap_create(struct vfs_handle_struct *handle,
                 TALLOC_CTX *mem_ctx,
                 const char *base_volume,
                 time_t *tstamp,
                 bool rw,
                 char **base_path,
                 char **snap_path)
{
    return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ncloud_snap_delete(struct vfs_handle_struct *handle,
                 TALLOC_CTX *mem_ctx,
                 char *base_path,
                 char *snap_path)
{
    return NT_STATUS_NOT_SUPPORTED;
}

static DIR *ncloud_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
               const char *mask, uint32_t attr)
{
    /* mark the current directory */
    int baselen = strlen(handle->conn->connectpath);
    char *cwd = ((struct ncloud_data*) handle->data)->cwd;
    if (fsp && fsp->fsp_name)
        snprintf(cwd, PATH_MAX, "%s/", fsp->fsp_name->base_name);
    if (strcmp(cwd, "./") == 0 || strcmp(cwd, "") == 0)
        snprintf(cwd, PATH_MAX, "/");
    DEBUG(3, ("fdopendir cwd = %s, fname = %s\n", cwd, fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)"));
    /* update metadata */
    bool update_dir_meta_on_open = lp_parm_int(SNUM(handle->conn), "ncloud", "update_dir_meta_on_open", 0);
    if (update_dir_meta_on_open) { ncloud_update_meta_record(handle, handle->conn->connectpath, cwd, false); }
    /* list the directory as usual */
    DIR *ret = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);

    if (ret) {
        /* hide the cache directory */
        ncloud_add_to_list(&handle->conn->hide_list);
        ncloud_add_to_list(&handle->conn->veto_list);
    }


    return ret;
}

static struct dirent *ncloud_readdir(vfs_handle_struct *handle,
                   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
    struct dirent *p = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
    DEBUG(3, ("Read directory %s\n", p? p->d_name : "(NIL)"));
    /* if this is a regular file (not directory) */
    if (
        p != NULL &&
        sbuf != NULL &&
        S_ISREG(sbuf->st_ex_mode) &&
        !S_ISDIR(sbuf->st_ex_mode) &&
        !ISDOT(p->d_name) &&
        !ISDOTDOT(p->d_name) 
    ) {
        /* if it has a metadata entry (fully written file), display the size in the metadata record */
        SMB_STRUCT_STAT sbuf_tmp = *sbuf;
        if (ncloud_get_filemeta(handle, p->d_name, &sbuf_tmp, /* has_dir */ false) == 0)
            *sbuf = sbuf_tmp;
    }
    return p;
}

static void ncloud_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
    SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
}

static long ncloud_telldir(vfs_handle_struct *handle, DIR *dirp)
{
    return SMB_VFS_NEXT_TELLDIR(handle, dirp);
}

static void ncloud_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
    SMB_VFS_NEXT_REWINDDIR(handle, dirp);
}

static int ncloud_rmdir(vfs_handle_struct *handle,
        const struct smb_filename *smb_fname);

static int ncloud_mkdir(vfs_handle_struct *handle,
        const struct smb_filename *smb_fname,
        mode_t mode)
{
    /* support directories */
    int ret = SMB_VFS_NEXT_MKDIR(handle, smb_fname, mode);
    return ret;
}

static int ncloud_rmdir(vfs_handle_struct *handle,
        const struct smb_filename *smb_fname)
{
    /* support directories */
    int ret = SMB_VFS_NEXT_RMDIR(handle, smb_fname);
    return ret;
}

static int ncloud_closedir(vfs_handle_struct *handle, DIR *dir)
{
    DEBUG(3, ("closedir\n"));
    ((struct ncloud_data *) handle->data)->cwd[0] = 0;
    return SMB_VFS_NEXT_CLOSEDIR(handle, dir);
}

static int ncloud_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
             files_struct *fsp, int flags, mode_t mode)
{
    /* update the file metadata record upon open */
    int baselen = strlen(handle->conn->connectpath);
    char *handlecwd = handle->conn->cwd_fname->base_name;
    char path[PATH_MAX];
    if (strlen(handlecwd) > baselen && strncmp(handle->conn->connectpath, handlecwd, baselen) == 0)
        snprintf(path, PATH_MAX, "%s/%s", handlecwd + baselen + 1, smb_fname->base_name);
    else
        snprintf(path, PATH_MAX, "%s", smb_fname->base_name);
    //DEBUG(4, ("[NCLOUD] cwd=%s, name=%s, combined=%s, %x\n", handle->conn->cwd_fname->base_name, smb_fname->base_name, path, fsp));
    ncloud_get_filemeta(handle, path, &fsp->fsp_name->st, /* has_dir */ true);
    bool update_dir_meta_on_open = lp_parm_int(SNUM(handle->conn), "ncloud", "update_dir_meta_on_open", 0);
    bool is_dir = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
    if (!is_dir || update_dir_meta_on_open) {
        DEBUG(3, 
            ("[NCLOUD] Open %s/%s, update metadata now\n", handle->conn->connectpath, path));
        ncloud_update_meta_record(handle, handle->conn->connectpath, path, true);
        ncloud_get_filemeta(handle, path, &fsp->fsp_name->st, /* has_dir */ true);
    }

    int ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

    if (ret < 0)
        return ret;

    struct ncloud_file_status *file_status = 
        (struct ncloud_file_status *) VFS_ADD_FSP_EXTENSION(
                handle, fsp, struct ncloud_file_status, NULL
        );

    bool is_append = flags & O_APPEND;
    bool is_write = flags & O_WRONLY || flags & O_RDWR;
    bool is_read = !(flags & O_WRONLY) || flags & O_RDWR;
    bool is_sync = flags & O_SYNC || flags & O_DSYNC;
    bool is_trunc = flags & O_TRUNC;

    DEBUG(2, 
            ("[NCLOUD] Open %s read=%s write=%s append=%s sync=%s trunc=%s flags=%x(%x) mode=%x isReg=%d isDir=%d (%d) size=%lu, %x\n"
            , smb_fname->base_name
            , BOOLSTR(is_read)
            , BOOLSTR(is_write)
            , BOOLSTR(is_append)
            , BOOLSTR(is_sync)
            , BOOLSTR(is_trunc)
            , flags
            , smb_fname->flags
            , mode
            , S_ISREG(fsp->fsp_name->st.st_ex_mode)
            , is_dir
            , fsp->is_directory
            , fsp && fsp->fsp_name? fsp->fsp_name->st.st_ex_size : -1
            , fsp
            )
    );

    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;

    if (ncloud_init_file_status(ncloud_handle, fsp, file_status) == -1) {
        SMB_VFS_NEXT_CLOSE(handle, fsp);
        return -1;
    }
    /* setup buffers for regular files if no cache */
    if (fsp && fsp->fsp_name && smb_fname) {
        unsigned long int append_size = ncloud_handle->append_size;
        /* write buffer */
        if (!ncloud_handle->cached_write) {
            file_status->buf.write.size = append_size * ncloud_handle->max_split_ahead;
        }
        file_status->buf.write.starting_offset = (fsp->fsp_name->st.st_ex_size + append_size - 1) / append_size * append_size;
        file_status->truncate_to_zero = is_trunc;
        file_status->is_sync = is_sync;
        DEBUG(3, ("[NCLOUD] Open completed; fd=%d, last_write_offset=%lu, size=%lu, %x\n", ret, file_status->buf.write.starting_offset, fsp->fsp_name->st.st_ex_size, fsp));
    }

    /*
    DEBUG(3, ("[NCLOUD] Open ends = %d\n", ret));
    */
    return ret;
}

static NTSTATUS ncloud_create_file(struct vfs_handle_struct *handle,
                 struct smb_request *req,
                 uint16_t root_dir_fid,
                 struct smb_filename *smb_fname,
                 uint32_t access_mask,
                 uint32_t share_access,
                 uint32_t create_disposition,
                 uint32_t create_options,
                 uint32_t file_attributes,
                 uint32_t oplock_request,
                 struct smb2_lease *lease,
                 uint64_t allocation_size,
                 uint32_t private_flags,
                 struct security_descriptor *sd,
                 struct ea_list *ea_list,
                 files_struct ** result, int *pinfo,
                 const struct smb2_create_blobs *in_context_blobs,
                 struct smb2_create_blobs *out_context_blobs)
{
    NTSTATUS status = SMB_VFS_NEXT_CREATE_FILE(handle,
                    req,
                    root_dir_fid,
                    smb_fname,
                    access_mask,
                    share_access,
                    create_disposition,
                    create_options,
                    file_attributes,
                    oplock_request,
                    lease,
                    allocation_size,
                    private_flags,
                    sd, ea_list, result, pinfo,
                    in_context_blobs, out_context_blobs);
    DEBUG(2, ("CREATE file %s %d\n", smb_fname->base_name, status.v));
    return status;
}

static int ncloud_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
    DEBUG(2, 
        ("[NCLOUD] Close write=%s read=%s name=%s size=%lu cpath=%s opath=%s cwd=%s delete=%d idelete=%d is_dir=%d\n"
        , BOOLSTR(fsp->can_write)
        , BOOLSTR(fsp->can_read)
        , smb_fname_str_dbg(fsp->fsp_name)
        , fsp->fsp_name->st.st_ex_size
        , fsp->conn->connectpath
        , fsp->conn->origpath
        , smb_fname_str_dbg(fsp->conn->cwd_fname)
        , fsp->delete_on_close
        , fsp->initial_delete_on_close
        , fsp->is_directory
    ));

    int ret = 0;
    request_t req;
    char *cache_path = 0;
    bool isWrite = !fsp->is_directory && fsp->can_write;
    bool isRead = !fsp->is_directory && fsp->can_read;
    /* flush file data for writable files */
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp);
    /* once the file is marked as 'delete on close', skip flushing the remaining data in buffer */
    file_status->flush_on_close = file_status->flush_on_close || fsp->delete_on_close || fsp->initial_delete_on_close;
    /* if the file is to be deleted on close, there is no need to write it back */
    bool written_to_backend = file_status->flush_on_close;

    ret = SMB_VFS_NEXT_CLOSE(handle, fsp);
    
    if (isWrite && !written_to_backend) {
        struct timeval start, end;
        gettimeofday(&start, NULL);
        written_to_backend = ncloud_check_and_write_if_needed(handle, fsp, file_status->buf.write.starting_offset, 0, 0) != -1;
        gettimeofday(&end, NULL);
        file_status->perf.check_write_time += get_duration(start, end);
        /* clear cache (TODO check number of opened fd */
        gettimeofday(&end, NULL);
        double duration = get_duration(file_status->perf.open, end);
        DEBUG(3, ("[NCLOUD] Opened file %s for %.3f (%.3f memcpy, %.3f check write) seconds\n", smb_fname_str_dbg(fsp->fsp_name), duration, file_status->perf.memcpy_time, file_status->perf.check_write_time));
    }
    ncloud_close_cache_file(handle, fsp);

    DEBUG(2, ("[NCLOUD] Close complete (%d)\n", fsp->fh? fsp->fh->fd : 0));

    /* clean up the file record if upload fails */
    if (isWrite && !written_to_backend) {
        DEBUG(1, ("Failed to write file %s to backend\n", fsp->fsp_name->base_name));
        ncloud_unlink(handle, fsp->fsp_name);
        errno = ENOSPC;
        ret = -1;
    } else if (isWrite) {
        ncloud_update_meta_record(handle, handle->conn->connectpath, fsp->fsp_name->base_name, true);
    }

    return ret;
}

static ssize_t ncloud_pread(vfs_handle_struct *handle, files_struct *fsp,
              void *data, size_t n, off_t offset)
{
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    DEBUG(3, ("pread offset = %lu size = %lu\n", offset, n));
    /* pass non-file read back to VFS */ 
    if (fsp->is_directory)
        return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
    /* get data from nCloud if needed */
    ssize_t bytes_read = ncloud_check_and_read_if_needed(handle, fsp, offset, n, data);
    if (bytes_read < 0 && fsp->fsp_name->st.st_ex_size > 0)
        return -1;
    /* nothing can be read from empty files */
    if (fsp->fsp_name->st.st_ex_size == 0)
        bytes_read = 0;
    /* read from disk if needed */
    return ncloud_handle->cached_read && bytes_read > 0? ncloud_read_cache_file(handle, fsp, data, bytes_read, offset): bytes_read;
}

struct ncloud_pread_state {
    ssize_t ret;
    struct vfs_aio_state vfs_aio_state;
    off_t offset;
    size_t n;
    struct files_struct *fsp;
};

static void ncloud_pread_done(struct tevent_req *subreq);

static struct tevent_req *ncloud_pread_send(struct vfs_handle_struct *handle,
                      TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct files_struct *fsp,
                      void *data, size_t n, off_t offset)
{
    struct tevent_req *req, *subreq;
    struct ncloud_pread_state *state;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;

    DEBUG(3, ("pread send offset = %lu size = %lu\n", offset, n));
    /** 
     * get file content before read
     * TODO fix error message
     * TODO stream file content instead (avoid timeout)
     **/

    req = tevent_req_create(mem_ctx, &state, struct ncloud_pread_state);
    if (req == NULL) {
        return NULL;
    }

    if (!fsp->is_directory) {
        ssize_t bytes_read = ncloud_check_and_read_if_needed(handle, fsp, offset, n, data);
        if (bytes_read < 0 && fsp->fsp_name->st.st_ex_size > 0) {
            state->ret = 0;
            tevent_req_error(req, EACCES);
        } else {
            if (fsp->fsp_name->st.st_ex_size == 0)
                bytes_read = 0;
            /* read into buffer, and finish the request and set the return value */
            if (ncloud_handle->cached_read && bytes_read > 0)
                state->ret = ncloud_read_cache_file(handle, fsp, data, bytes_read, offset);
            else
                state->ret = bytes_read;
            tevent_req_done(req);
        }
    } else {
        subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
                         n, offset);
        if (tevent_req_nomem(subreq, req)) {
            return tevent_req_post(req, ev);
        }
        tevent_req_set_callback(subreq, ncloud_pread_done, req);
        return req;
    }
    return tevent_req_post(req, ev);
}

static void ncloud_pread_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
        tevent_req_callback_data(subreq, struct tevent_req);
    struct ncloud_pread_state *state =
        tevent_req_data(req, struct ncloud_pread_state);

    state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
    TALLOC_FREE(subreq);
    tevent_req_done(req);
    DEBUG(3, ("pread done %lu %d\n", state->ret, state->vfs_aio_state.error));
}

static ssize_t skel_pread_recv(struct tevent_req *req,
                   struct vfs_aio_state *vfs_aio_state)
{
    struct ncloud_pread_state *state =
        tevent_req_data(req, struct ncloud_pread_state);

    DEBUG(3, ("pread recv ret = %lu %d %d\n", state->ret, vfs_aio_state->error, state->vfs_aio_state.error));

    if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
        return -1;
    }
    *vfs_aio_state = state->vfs_aio_state;
    return state->ret;
}

static ssize_t ncloud_pwrite(vfs_handle_struct *handle, files_struct *fsp,
               const void *data, size_t n, off_t offset)
{
    ssize_t ret = 0;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 

    if (ncloud_handle->cached_write) {
        //ret = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
        ret = ncloud_write_cache_file(handle, fsp, data, n, offset);
    }

    DEBUG(3, ("pwrite offset = %lu size = %lu\n", offset, n));
    struct timeval start, end;
    gettimeofday(&start, NULL);
    if (ncloud_check_and_write_if_needed(handle, fsp, offset, n, data) != n)
        ret = -1;
    else
        ret = n;
    gettimeofday(&end, NULL);
    file_status->perf.check_write_time += get_duration(start, end);

    return ret;
}

struct ncloud_pwrite_state {
    ssize_t ret;
    struct vfs_aio_state vfs_aio_state;
    off_t offset;
    size_t n;
    const void *data;
    struct files_struct *fsp;
    struct vfs_handle_struct *handle;
};

static struct tevent_req *ncloud_pwrite_send(struct vfs_handle_struct *handle,
                       TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct files_struct *fsp,
                       const void *data,
                       size_t n, off_t offset)
{
    struct tevent_req *req, *subreq;
    struct ncloud_pwrite_state *state;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;

    DEBUG(3, ("pwrite %s send offset = %lu size = %ld\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)", offset, n));
    req = tevent_req_create(mem_ctx, &state, struct ncloud_pwrite_state);
    if (req == NULL) {
        return NULL;
    }

    /* information for forwarding the data to backend after local cache is written */
    state->offset = offset;
    state->n = n;
    state->fsp = fsp;
    state->handle = handle;
    state->data = data;

    /*
    if (ncloud_handle->cached_write) {
        subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
                          n, offset);
    } else {
    */
    /* write data to cache file first */
    if (ncloud_handle->cached_write)
        ncloud_write_cache_file(handle, fsp, data, n, offset);

    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp); 
    struct timeval start, end;
    gettimeofday(&start, NULL);
    /* check and send data to ncloud if needed */
    if (ncloud_check_and_write_if_needed(state->handle, state->fsp, state->offset, state->n, state->data) != state->n) {
        state->ret = -1;
        state->vfs_aio_state.error = EINVAL;
        tevent_req_error(req, EINVAL);
    } else {
        state->ret = state->n;
        state->vfs_aio_state.error = 0;
        tevent_req_done(req);
    }
    gettimeofday(&end, NULL);
    file_status->perf.check_write_time += get_duration(start, end);
    return tevent_req_post(req, ev);
}

static ssize_t skel_pwrite_recv(struct tevent_req *req,
                struct vfs_aio_state *vfs_aio_state)
{
    struct ncloud_pwrite_state *state =
        tevent_req_data(req, struct ncloud_pwrite_state);

    DEBUG(3, ("pwrite recv offset = %lu size = %ld\n", state->offset, state->n));

    if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
        return -1;
    }
    *vfs_aio_state = state->vfs_aio_state;
    return state->ret;
}

static off_t skel_lseek(vfs_handle_struct *handle, files_struct *fsp,
            off_t offset, int whence)
{

    DEBUG(3, ("lseek %s to %lu (%d)\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)", offset, whence));
    return SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
}

static ssize_t skel_sendfile(vfs_handle_struct *handle, int tofd,
                 files_struct *fromfsp, const DATA_BLOB *hdr,
                 off_t offset, size_t n)
{
    DEBUG(3, ("sendfile\n"));
    return SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
}

static ssize_t skel_recvfile(vfs_handle_struct *handle, int fromfd,
                 files_struct *tofsp, off_t offset, size_t n)
{
    DEBUG(3, ("recvfile\n"));
    return SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
}

static int ncloud_rename(vfs_handle_struct *handle,
               const struct smb_filename *smb_fname_src,
               const struct smb_filename *smb_fname_dst)
{
    /* support rename of empty directories and regular files */
    DEBUG(2, ("rename %s %s\n", smb_fname_src->base_name, smb_fname_dst->base_name));

    char spath[PATH_MAX], dpath[PATH_MAX];
    snprintf(spath, PATH_MAX, "%s/%s", handle->conn->connectpath, smb_fname_src->base_name);
    snprintf(dpath, PATH_MAX, "%s/%s", handle->conn->connectpath, smb_fname_dst->base_name);

    /* rename local cache record */
    int ret = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
    /* rename metadata record */
    if (ret == 0) {
        //ncloud_rename_meta_entry(handle, smb_fname_src, smb_fname_dst);
        if (S_ISDIR(smb_fname_src->st.st_ex_mode))
            ret = ncloud_operate_on_directory(handle, handle->conn->connectpath, smb_fname_dst->base_name, 1 /* rename */, smb_fname_src->base_name);
        else if (S_ISREG(smb_fname_src->st.st_ex_mode))
            ret = ncloud_rename_backend_file(handle, smb_fname_src->base_name, smb_fname_dst->base_name);
    }

    return ret;
}

struct skel_fsync_state {
    int ret;
    struct vfs_aio_state vfs_aio_state;
};

static void skel_fsync_done(struct tevent_req *subreq);

static struct tevent_req *skel_fsync_send(struct vfs_handle_struct *handle,
                      TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct files_struct *fsp)
{
    struct tevent_req *req, *subreq;
    struct skel_fsync_state *state;

    DEBUG(3, ("fsync send %s\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)"));

    req = tevent_req_create(mem_ctx, &state, struct skel_fsync_state);
    if (req == NULL) {
        return NULL;
    }

    state->ret = 0;
    tevent_req_done(req);
    return tevent_req_post(req, ev);
}

static int skel_fsync_recv(struct tevent_req *req,
               struct vfs_aio_state *vfs_aio_state)
{
    struct skel_fsync_state *state =
        tevent_req_data(req, struct skel_fsync_state);

    DEBUG(3, ("fsync recv\n"));

    if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
        return -1;
    }
    *vfs_aio_state = state->vfs_aio_state;
    return state->ret;
}

static int ncloud_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    char *name = smb_fname? smb_fname->base_name : 0;
    int ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
    DEBUG(3, (
        "stat %s ret=%d isDir=%d isReg=%d size=%lu\n"
        , name? name : "(NIL)"
        , ret
        , smb_fname? S_ISDIR(smb_fname->st.st_ex_mode): -1
        , smb_fname? S_ISREG(smb_fname->st.st_ex_mode): -1
        , smb_fname? smb_fname->st.st_ex_size : -1
        )
    );
    if (smb_fname && S_ISREG(smb_fname->st.st_ex_mode)) {
        int ret2 = ncloud_get_filemeta(handle, name, &smb_fname->st, /* has_dir */ true) <= 0? -1 : 0; 
        ret = ret == 0 || ret2 == 0? 0 : -1;
        DEBUG(3, 
            ("ncloud stat %s ret=%d isDir=%d isReg=%d size=%lu\n"
            , name? name : "(NIL)"
            , ret
            , smb_fname? S_ISDIR(smb_fname->st.st_ex_mode): -1
            , smb_fname? S_ISREG(smb_fname->st.st_ex_mode) : -1
            , smb_fname? smb_fname->st.st_ex_size : -1
            )
        );
    }
    return ret;
}

static int ncloud_fstat(vfs_handle_struct *handle, files_struct *fsp,
              SMB_STRUCT_STAT *sbuf)
{
    char *name = fsp? fsp->fsp_name? (fsp->fsp_name->base_name? fsp->fsp_name->base_name : 0) : 0 : 0;
    int ret = -1;
    if (name && !fsp->is_directory) {
        ret = ncloud_get_filemeta(handle, name, sbuf, /* has_dir */ true); 
        if (ret == -1)
            ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
    } else {
        ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
    }
    DEBUG(3, ("fstat %s osize %lu ret = %d\n", name? name : "(NIL)", sbuf->st_ex_size, ret));
    return ret;
}

static int skel_lstat(vfs_handle_struct *handle,
              struct smb_filename *smb_fname)
{
    char *name = smb_fname? smb_fname->base_name : 0;
    DEBUG(3, ("lstat %s\n", name? name : "(NIL)"));
    return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static uint64_t ncloud_get_alloc_size(struct vfs_handle_struct *handle,
                    struct files_struct *fsp,
                    const SMB_STRUCT_STAT *sbuf)
{
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    char *name = fsp? fsp->fsp_name? (fsp->fsp_name->base_name? fsp->fsp_name->base_name : 0) : 0 : 0;
    struct ncloud_file_status *file_status = name? (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp) : 0; 
    uint64_t alloc_size = 0;
    bool obtained = false;
    if (S_ISREG(sbuf->st_ex_mode) && !S_ISDIR(sbuf->st_ex_mode) && name) {
        SMB_STRUCT_STAT tmp;
        obtained = ncloud_get_filemeta(handle, name, &tmp, /* has_dir */ true) == 0;
        if (obtained)
            alloc_size = tmp.st_ex_size;
        /* check if the file is in-write, and return the last touched write offset */
        if (file_status) {
            for (int i = 0; i < ncloud_handle->max_split_ahead; i++)
                if (file_status->written_bytes[i] > 0) {
                    alloc_size = file_status->buf.write.starting_offset + file_status->written_bytes[i];
                    obtained = true;
                }
        }
    }
    if (!obtained)
        alloc_size = SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);
    DEBUG(3, ("get alloc size %s %lu %d\n", name? name : "(NIL)", alloc_size, obtained));
    return alloc_size;
}

static int ncloud_unlink(vfs_handle_struct *handle,
               const struct smb_filename *smb_fname)
{
    request_t req;
    int ret = 0;
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;
    if (set_delete_file_request(&req, smb_fname->base_name, ncloud_handle->namespace_id) == -1) {
        DEBUG(1, ("[NCLOUD] Failed to set delete file request\n"));
        errno = EINVAL;
        return -1;
    }
    ncloud_conn_t *conn = &ncloud_handle->conn;
    int okay = send_request(conn, &req) == 0;
    request_t_release(&req);

    /* silent delete error */
    /*
    if (!okay)
        errno = EACCES;
    */

    DEBUG(2, ("[NCLOUD] Delete file %s\n", smb_fname->base_name));
    
    /* unlink cache entry */
    //return (SMB_VFS_NEXT_UNLINK(handle, smb_fname) == 0 && okay)? 0 : -1;
    return (SMB_VFS_NEXT_UNLINK(handle, smb_fname) == 0)? 0 : -1;
}

static int skel_chmod(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            mode_t mode)
{
    DEBUG(3, ("chmod\n"));
    return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
}

static int skel_fchmod(vfs_handle_struct *handle, files_struct *fsp,
               mode_t mode)
{
    DEBUG(3, ("fchmod\n"));
    return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
}

static int skel_chown(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            uid_t uid,
            gid_t gid)
{
    DEBUG(3, ("chown\n"));
    return SMB_VFS_NEXT_CHOWN(handle, smb_fname, uid, gid);
}

static int skel_fchown(vfs_handle_struct *handle, files_struct *fsp,
               uid_t uid, gid_t gid)
{
    DEBUG(3, ("fchown\n"));
    return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
}

static int skel_lchown(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            uid_t uid,
            gid_t gid)
{
    DEBUG(3, ("lchown\n"));
    return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
}

static int skel_chdir(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname)
{
    DEBUG(3, ("chdir to %s\n", smb_fname->base_name));
    return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
}

static struct smb_filename *skel_getwd(vfs_handle_struct *handle,
                    TALLOC_CTX *ctx)
{
    struct smb_filename *smb_fname = SMB_VFS_NEXT_GETWD(handle, ctx);
    DEBUG(3, ("getwd %s\n", smb_fname? smb_fname->base_name : "(NIL)"));
    return smb_fname;
}

static int skel_ntimes(vfs_handle_struct *handle,
               const struct smb_filename *smb_fname,
               struct smb_file_time *ft)
{
    DEBUG(3, ("ntimes\n"));
    return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int ncloud_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
              off_t offset)
{
    DEBUG(2, ("ftruncate %s %ld\n", fsp && fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)", offset));
    if (offset == 0) {
        struct ncloud_file_status *file_status = ((struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp));
        file_status->truncate_to_zero = true;
        ncloud_reinit_buffers(file_status);
        ncloud_check_and_write_if_needed(handle, fsp, offset, 0, 0);
    } else {
        ((struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, fsp))->truncate_to_zero = false;
    }
    return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
}

static int skel_fallocate(vfs_handle_struct *handle, files_struct *fsp,
              uint32_t mode, off_t offset, off_t len)
{
    DEBUG(3, ("fallocate\n"));
    return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
}

static bool skel_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
              off_t offset, off_t count, int type)
{
    DEBUG(2, ("lock %s\n", fsp? fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)" : "(NIL)"));
    return SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
}

static int skel_kernel_flock(struct vfs_handle_struct *handle,
                 struct files_struct *fsp, uint32_t share_mode,
                 uint32_t access_mask)
{
    DEBUG(3, ("kernel flock %s\n", fsp? fsp->fsp_name? fsp->fsp_name->base_name : "(NIL)" : "(NIL)"));
    return SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_mode, access_mask);
}

static int skel_linux_setlease(struct vfs_handle_struct *handle,
                   struct files_struct *fsp, int leasetype)
{
    DEBUG(3, ("setlease\n"));
    return SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
}

static bool skel_getlock(vfs_handle_struct *handle, files_struct *fsp,
             off_t *poffset, off_t *pcount, int *ptype,
             pid_t *ppid)
{
    DEBUG(3, ("getlock\n"));
    return SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);
}

static int skel_symlink(vfs_handle_struct *handle,
            const char *link_contents,
            const struct smb_filename *new_smb_fname)
{
    DEBUG(3, ("smylink to %s\n", new_smb_fname->base_name));
    return SMB_VFS_NEXT_SYMLINK(handle, link_contents, new_smb_fname);
}

static int skel_vfs_readlink(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            char *buf,
            size_t bufsiz)
{
    return SMB_VFS_NEXT_READLINK(handle, smb_fname, buf, bufsiz);
}

static int skel_link(vfs_handle_struct *handle,
            const struct smb_filename *old_smb_fname,
            const struct smb_filename *new_smb_fname)
{
    DEBUG(3, ("link from %s to %s\n", old_smb_fname->base_name, new_smb_fname->base_name));
    return SMB_VFS_NEXT_LINK(handle, old_smb_fname, new_smb_fname);
}

static int skel_mknod(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            mode_t mode,
            SMB_DEV_T dev)
{
    return SMB_VFS_NEXT_MKNOD(handle, smb_fname, mode, dev);
}

static struct smb_filename *skel_realpath(vfs_handle_struct *handle,
            TALLOC_CTX *ctx,
            const struct smb_filename *smb_fname)
{
    return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
}

static int skel_chflags(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            uint flags)
{
    return SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
}

static struct file_id skel_file_id_create(vfs_handle_struct *handle,
                      const SMB_STRUCT_STAT *sbuf)
{
    return SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);
}

struct skel_offload_read_state {
    struct vfs_handle_struct *handle;
    DATA_BLOB token;
};

static struct vfs_offload_ctx *ncloud_offload_ctx;

static void skel_offload_read_done(struct tevent_req *subreq);

static struct tevent_req *ncloud_offload_read_send(
    TALLOC_CTX *mem_ctx,
    struct tevent_context *ev,
    struct vfs_handle_struct *handle,
    struct files_struct *fsp,
    uint32_t fsctl,
    uint32_t ttl,
    off_t offset,
    size_t to_copy)
{
    struct tevent_req *req = NULL;
    struct skel_offload_read_state *state = NULL;
    //struct tevent_req *subreq = NULL;

    DEBUG(3, ("[NCLOUD] read offload on file %s at %ld %ld\n", fsp->fsp_name->base_name, offset, to_copy));

    req = tevent_req_create(mem_ctx, &state, struct skel_offload_read_state);
    if (req == NULL) {
        return NULL;
    }
    *state = (struct skel_offload_read_state) {
        .handle = handle,
    };

    NTSTATUS status = vfs_offload_token_ctx_init(fsp->conn->sconn->client,
                        &ncloud_offload_ctx);
    if (tevent_req_nterror(req, status)) {
        return tevent_req_post(req, ev);
    }

    if (fsctl != FSCTL_SRV_REQUEST_RESUME_KEY) {
        tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
        return tevent_req_post(req, ev);
    }

    status = vfs_offload_token_create_blob(state, fsp, fsctl,
                           &state->token);
    if (tevent_req_nterror(req, status)) {
        return tevent_req_post(req, ev);
    }

    status = vfs_offload_token_db_store_fsp(ncloud_offload_ctx, fsp,
                        &state->token);
    if (tevent_req_nterror(req, status)) {
        return tevent_req_post(req, ev);
    }

    /*
    subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
                        fsctl, ttl, offset, to_copy);
    if (tevent_req_nomem(subreq, req)) {
        return tevent_req_post(req, ev);
    }
    tevent_req_set_callback(subreq, skel_offload_read_done, req);
    */
    DEBUG(3, ("[NCLOUD] read offload on file %s at %ld %ld done\n", fsp->fsp_name->base_name, offset, to_copy));
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static void skel_offload_read_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(
        subreq, struct tevent_req);
    struct skel_offload_read_state *state = tevent_req_data(
        req, struct skel_offload_read_state);
    NTSTATUS status;

    status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
                        state->handle,
                        state,
                        &state->token);
    TALLOC_FREE(subreq);
    if (tevent_req_nterror(req, status)) {
        return;
    }

    tevent_req_done(req);
    return;
}

static NTSTATUS skel_offload_read_recv(struct tevent_req *req,
                       struct vfs_handle_struct *handle,
                       TALLOC_CTX *mem_ctx,
                       DATA_BLOB *_token)
{
    struct skel_offload_read_state *state = tevent_req_data(
        req, struct skel_offload_read_state);
    DATA_BLOB token;
    NTSTATUS status;

    DEBUG(3, ("[NCLOUD] read recv offload\n"));

    if (tevent_req_is_nterror(req, &status)) {
        tevent_req_received(req);
        return status;
    }

    token = data_blob_talloc(mem_ctx,
                 state->token.data,
                 state->token.length);

    tevent_req_received(req);

    if (token.data == NULL) {
        return NT_STATUS_NO_MEMORY;
    }

    DEBUG(3, ("[NCLOUD] read recv offload ends\n"));
    *_token = token;
    return NT_STATUS_OK;
}

struct skel_offload_write_state {
    struct vfs_handle_struct *handle;
    off_t copied;
};
static void skel_offload_write_done(struct tevent_req *subreq);

static struct tevent_req *ncloud_offload_write_send(struct vfs_handle_struct *handle,
                           TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           uint32_t fsctl,
                           DATA_BLOB *token,
                           off_t transfer_offset,
                           struct files_struct *dest_fsp,
                           off_t dest_off,
                           off_t num)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct skel_offload_write_state *state;
    struct files_struct *src_fsp = 0;

    DEBUG(3, ("[NCLOUD] write offload to file %s at %ld %ld\n", dest_fsp->fsp_name->base_name, dest_off, num));
    struct ncloud_data* ncloud_handle = (struct ncloud_data *) handle->data;

    req = tevent_req_create(mem_ctx, &state, struct skel_offload_write_state);
    if (req == NULL) {
        return NULL;
    }

    switch (fsctl) {
    case FSCTL_SRV_COPYCHUNK:
    case FSCTL_SRV_COPYCHUNK_WRITE:
        break;

    case FSCTL_OFFLOAD_WRITE:
        tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
        return tevent_req_post(req, ev);

    case FSCTL_DUP_EXTENTS_TO_FILE:
        DBG_DEBUG("COW clones not supported by vfs_default\n");
        tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
        return tevent_req_post(req, ev);

    default:
        tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
        return tevent_req_post(req, ev);
    }
    /*
    state->handle = handle;
    subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle, state, ev,
                          fsctl, token, transfer_offset,
                          dest_fsp, dest_off, num);
    if (tevent_req_nomem(subreq, req)) {
        return tevent_req_post(req, ev);
    }
    */

    if (num == 0) {
        state->copied = num;
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    NTSTATUS status = vfs_offload_token_db_fetch_fsp(ncloud_offload_ctx,
                        token, &src_fsp);
    if (tevent_req_nterror(req, status)) {
        DEBUG(1, ("[NCLOUD] Failed to get source fsp\n"));
        return tevent_req_post(req, ev);
    }

    /* copy stripe-by-stripe */
    struct ncloud_file_status *file_status = (struct ncloud_file_status *) VFS_FETCH_FSP_EXTENSION(handle, src_fsp); 
    if (file_status == NULL) {
        file_status = (struct ncloud_file_status *) VFS_ADD_FSP_EXTENSION(
                handle, src_fsp, struct ncloud_file_status, NULL
        );
    }
    if (file_status->read_size == 0) 
        file_status->read_size = ncloud_get_read_size(handle, src_fsp);

    unsigned long int read_size = file_status->read_size;
    /* skip copying empty file, copy only if crossing or at the start of a new stripe */
    if (read_size != 0 && (dest_off % read_size == 0 || (dest_off / read_size) != (dest_off + num) / read_size)) {
        unsigned long int ofs = (dest_off % read_size == 0)? dest_off : (dest_off + read_size - 1) / read_size * read_size;
        unsigned long int len = read_size;
        request_t nreq;
        if (
            set_file_copy_request(&nreq, src_fsp->fsp_name->base_name, dest_fsp->fsp_name->base_name, ofs, len, ncloud_handle->namespace_id) == -1 || 
            send_request(&ncloud_handle->conn, &nreq) == -1
        ) {
            DEBUG(1, ("[NCLOUD] Failed to set/send file copy request\n"));
            tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
            return tevent_req_post(req, ev);
        }
    }

    state->copied = num;
    /*tevent_req_set_callback(subreq, skel_offload_write_done, req); */
    tevent_req_done(req);
    tevent_req_post(req, ev);
    DEBUG(3, ("[NCLOUD] write offload to file %s\n", dest_fsp->fsp_name->base_name));
    return req;
}

static void skel_offload_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(
        subreq, struct tevent_req);
    struct skel_offload_write_state *state
            = tevent_req_data(req, struct skel_offload_write_state);
    NTSTATUS status;

    status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(state->handle,
                          subreq,
                          &state->copied);
    TALLOC_FREE(subreq);
    if (tevent_req_nterror(req, status)) {
        return;
    }
    tevent_req_done(req);
}

static NTSTATUS skel_offload_write_recv(struct vfs_handle_struct *handle,
                     struct tevent_req *req,
                     off_t *copied)
{
    struct skel_offload_write_state *state
            = tevent_req_data(req, struct skel_offload_write_state);
    NTSTATUS status;

    *copied = state->copied;
    if (tevent_req_is_nterror(req, &status)) {
        tevent_req_received(req);
        return status;
    }

    tevent_req_received(req);
    return NT_STATUS_OK;
}

static NTSTATUS skel_get_compression(struct vfs_handle_struct *handle,
                     TALLOC_CTX *mem_ctx,
                     struct files_struct *fsp,
                     struct smb_filename *smb_fname,
                     uint16_t *_compression_fmt)
{
    return SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname,
                        _compression_fmt);
}

static NTSTATUS skel_set_compression(struct vfs_handle_struct *handle,
                     TALLOC_CTX *mem_ctx,
                     struct files_struct *fsp,
                     uint16_t compression_fmt)
{
    return SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
                        compression_fmt);
}

static NTSTATUS skel_streaminfo(struct vfs_handle_struct *handle,
                struct files_struct *fsp,
                const struct smb_filename *smb_fname,
                TALLOC_CTX *mem_ctx,
                unsigned int *num_streams,
                struct stream_struct **streams)
{
    return SMB_VFS_NEXT_STREAMINFO(handle,
                fsp,
                smb_fname,
                mem_ctx,
                num_streams,
                streams);
}

static int skel_get_real_filename(struct vfs_handle_struct *handle,
                  const char *path,
                  const char *name,
                  TALLOC_CTX *mem_ctx, char **found_name)
{
    return SMB_VFS_NEXT_GET_REAL_FILENAME(handle,
                          path, name, mem_ctx, found_name);
}

static const char *ncloud_connectpath(struct vfs_handle_struct *handle,
                const struct smb_filename *smb_fname)
{
    return SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
}

static NTSTATUS skel_brl_lock_windows(struct vfs_handle_struct *handle,
                      struct byte_range_lock *br_lck,
                      struct lock_struct *plock,
                      bool blocking_lock)
{
    return SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle,
                         br_lck, plock, blocking_lock);
}

static bool skel_brl_unlock_windows(struct vfs_handle_struct *handle,
                    struct messaging_context *msg_ctx,
                    struct byte_range_lock *br_lck,
                    const struct lock_struct *plock)
{
    return SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, msg_ctx, br_lck, plock);
}

static bool skel_brl_cancel_windows(struct vfs_handle_struct *handle,
                    struct byte_range_lock *br_lck,
                    struct lock_struct *plock)
{
    return SMB_VFS_NEXT_BRL_CANCEL_WINDOWS(handle, br_lck, plock);
}

static bool skel_strict_lock_check(struct vfs_handle_struct *handle,
                   struct files_struct *fsp,
                   struct lock_struct *plock)
{
    return SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
}

static NTSTATUS skel_translate_name(struct vfs_handle_struct *handle,
                    const char *mapped_name,
                    enum vfs_translate_direction direction,
                    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
    return SMB_VFS_NEXT_TRANSLATE_NAME(handle, mapped_name, direction,
                       mem_ctx, pmapped_name);
}

static NTSTATUS skel_fsctl(struct vfs_handle_struct *handle,
               struct files_struct *fsp,
               TALLOC_CTX *ctx,
               uint32_t function,
               uint16_t req_flags,    /* Needed for UNICODE ... */
               const uint8_t *_in_data,
               uint32_t in_len,
               uint8_t ** _out_data,
               uint32_t max_out_len, uint32_t *out_len)
{
    return SMB_VFS_NEXT_FSCTL(handle,
                  fsp,
                  ctx,
                  function,
                  req_flags,
                  _in_data,
                  in_len, _out_data, max_out_len, out_len);
}

static NTSTATUS skel_readdir_attr(struct vfs_handle_struct *handle,
                  const struct smb_filename *fname,
                  TALLOC_CTX *mem_ctx,
                  struct readdir_attr_data **pattr_data)
{
    return SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
}

static NTSTATUS skel_get_dos_attributes(struct vfs_handle_struct *handle,
                struct smb_filename *smb_fname,
                uint32_t *dosmode)
{
    return SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
                smb_fname,
                dosmode);
}

static NTSTATUS skel_fget_dos_attributes(struct vfs_handle_struct *handle,
                struct files_struct *fsp,
                uint32_t *dosmode)
{
    return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
                fsp,
                dosmode);
}

static NTSTATUS skel_set_dos_attributes(struct vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                uint32_t dosmode)
{
    return SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
                smb_fname,
                dosmode);
}

static NTSTATUS skel_fset_dos_attributes(struct vfs_handle_struct *handle,
                struct files_struct *fsp,
                uint32_t dosmode)
{
    return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
                fsp,
                dosmode);
}

static NTSTATUS skel_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
                 uint32_t security_info,
                 TALLOC_CTX *mem_ctx,
                 struct security_descriptor **ppdesc)
{
    DEBUG(3, ("fget_nt_acl %s\n", smb_fname_str_dbg(fsp->fsp_name)));
    return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx,
                    ppdesc);
}

static NTSTATUS skel_get_nt_acl(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                uint32_t security_info,
                TALLOC_CTX *mem_ctx,
                struct security_descriptor **ppdesc)
{
    DEBUG(3, ("get_nt_acl %s\n", smb_fname->base_name));
    return SMB_VFS_NEXT_GET_NT_ACL(handle,
                smb_fname,
                security_info,
                mem_ctx,
                ppdesc);
}

static NTSTATUS skel_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
                 uint32_t security_info_sent,
                 const struct security_descriptor *psd)
{
    DEBUG(3, ("fset_nt_acl %s\n", smb_fname_str_dbg(fsp->fsp_name)));
    return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
}

static SMB_ACL_T skel_sys_acl_get_file(vfs_handle_struct *handle,
                       const struct smb_filename *smb_fname,
                       SMB_ACL_TYPE_T type,
                       TALLOC_CTX *mem_ctx)
{
    SMB_ACL_T ret = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname, type, mem_ctx);
    DEBUG(3, ("sys_acl_get_file %s %s %s \n", smb_fname->base_name, 
            type == SMB_ACL_TYPE_DEFAULT ? "directory default" : "file"));
    return ret;
}

static SMB_ACL_T skel_sys_acl_get_fd(vfs_handle_struct *handle,
                     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
    DEBUG(3, ("sys_acl_get_fd %s\n", smb_fname_str_dbg(fsp->fsp_name)));
    return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
}

static int skel_sys_acl_blob_get_file(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                TALLOC_CTX *mem_ctx,
                char **blob_description,
                DATA_BLOB *blob)
{
    DEBUG(3, ("sys_acl_blob_get_file %s\n", smb_fname->base_name));
    return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, smb_fname, mem_ctx,
                          blob_description, blob);
}

static int skel_sys_acl_blob_get_fd(vfs_handle_struct *handle,
                    files_struct *fsp, TALLOC_CTX *mem_ctx,
                    char **blob_description, DATA_BLOB *blob)
{
    DEBUG(3, ("sys_acl_blob_get_fd %s\n", smb_fname_str_dbg(fsp->fsp_name)));
    return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
                        blob_description, blob);
}

static int skel_sys_acl_set_file(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                SMB_ACL_TYPE_T acltype,
                SMB_ACL_T theacl)
{
    DEBUG(3, ("sys_acl_blob_set_file %s\n", smb_fname->base_name));
    return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname,
            acltype, theacl);
}

static int skel_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
                   SMB_ACL_T theacl)
{
    DEBUG(3, ("sys_acl_blob_set_fd %s\n", smb_fname_str_dbg(fsp->fsp_name)));
    return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
}

static int skel_sys_acl_delete_def_file(vfs_handle_struct *handle,
                    const struct smb_filename *smb_fname)
{
    return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, smb_fname);
}

static ssize_t skel_getxattr(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                const char *name,
                void *value,
                size_t size)
{
    return SMB_VFS_NEXT_GETXATTR(handle, smb_fname, name, value, size);
}

static ssize_t skel_fgetxattr(vfs_handle_struct *handle,
                  struct files_struct *fsp, const char *name,
                  void *value, size_t size)
{
    return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
}

static ssize_t skel_listxattr(vfs_handle_struct *handle,
                const struct smb_filename *smb_fname,
                char *list,
                size_t size)
{
    return SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
}

static ssize_t skel_flistxattr(vfs_handle_struct *handle,
                   struct files_struct *fsp, char *list,
                   size_t size)
{
    return SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
}

static int skel_removexattr(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            const char *name)
{
    return SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
}

static int skel_fremovexattr(vfs_handle_struct *handle,
                 struct files_struct *fsp, const char *name)
{
    return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int skel_setxattr(vfs_handle_struct *handle,
            const struct smb_filename *smb_fname,
            const char *name,
            const void *value,
            size_t size,
            int flags)
{
    return SMB_VFS_NEXT_SETXATTR(handle, smb_fname,
            name, value, size, flags);
}

static int skel_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
              const char *name, const void *value, size_t size,
              int flags)
{
    return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
}

static bool skel_aio_force(struct vfs_handle_struct *handle,
               struct files_struct *fsp)
{
    return SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
}

/* VFS operations structure */

struct vfs_fn_pointers ncloud_fns = {
    /* Disk operations */

    .connect_fn = ncloud_connect,
    .disconnect_fn = ncloud_disconnect,
    .disk_free_fn = ncloud_disk_free,
    .get_quota_fn = ncloud_get_quota, /* not implemented */
    .set_quota_fn = ncloud_set_quota, /* not implmented */
    .get_shadow_copy_data_fn = ncloud_get_shadow_copy_data, /* not implemented */
    .statvfs_fn = ncloud_statvfs,
    .fs_capabilities_fn = ncloud_fs_capabilities, /* not implemented */
    .get_dfs_referrals_fn = ncloud_get_dfs_referrals, /* not implemented */
    .snap_check_path_fn = ncloud_snap_check_path, /* not implemented */
    .snap_create_fn = ncloud_snap_create, /* not implemented */
    .snap_delete_fn = ncloud_snap_delete, /* not implemented */

    /* Directory operations */

    .opendir_fn = ncloud_opendir,
    .fdopendir_fn = ncloud_fdopendir,
    .readdir_fn = ncloud_readdir,
    .seekdir_fn = ncloud_seekdir,
    .telldir_fn = ncloud_telldir,
    .rewind_dir_fn = ncloud_rewind_dir,
    .mkdir_fn = ncloud_mkdir,
    .rmdir_fn = ncloud_rmdir,
    .closedir_fn = ncloud_closedir,

    /* File operations */

    .open_fn = ncloud_open,
    .create_file_fn = ncloud_create_file,
    .close_fn = ncloud_close_fn,
    .pread_fn = ncloud_pread,
    .pread_send_fn = ncloud_pread_send,
    .pread_recv_fn = skel_pread_recv,
    .pwrite_fn = ncloud_pwrite,
    .pwrite_send_fn = ncloud_pwrite_send,
    .pwrite_recv_fn = skel_pwrite_recv,
    .lseek_fn = skel_lseek,
    .sendfile_fn = skel_sendfile,
    .recvfile_fn = skel_recvfile,
    .rename_fn = ncloud_rename,
    .fsync_send_fn = skel_fsync_send,
    .fsync_recv_fn = skel_fsync_recv,
    .stat_fn = ncloud_stat,
    .fstat_fn = ncloud_fstat,
    .lstat_fn = skel_lstat,
    .get_alloc_size_fn = ncloud_get_alloc_size,
    .unlink_fn = ncloud_unlink,
    .chmod_fn = skel_chmod,
    .fchmod_fn = skel_fchmod,
    .chown_fn = skel_chown,
    .fchown_fn = skel_fchown,
    .lchown_fn = skel_lchown,
    .chdir_fn = skel_chdir,
    .getwd_fn = skel_getwd,
    .ntimes_fn = skel_ntimes,
    .ftruncate_fn = ncloud_ftruncate,
    .fallocate_fn = skel_fallocate,
    .lock_fn = skel_lock,
    .kernel_flock_fn = skel_kernel_flock,
    .linux_setlease_fn = skel_linux_setlease,
    .getlock_fn = skel_getlock,
    .symlink_fn = skel_symlink,
    .readlink_fn = skel_vfs_readlink,
    .link_fn = skel_link,
    .mknod_fn = skel_mknod,
    .realpath_fn = skel_realpath,
    .chflags_fn = skel_chflags,
    .file_id_create_fn = skel_file_id_create,
    .offload_read_send_fn = ncloud_offload_read_send,
    .offload_read_recv_fn = skel_offload_read_recv,
    .offload_write_send_fn = ncloud_offload_write_send,
    .offload_write_recv_fn = skel_offload_write_recv,
    .get_compression_fn = skel_get_compression,
    .set_compression_fn = skel_set_compression,

    .streaminfo_fn = skel_streaminfo,
    .get_real_filename_fn = skel_get_real_filename,
    .connectpath_fn = ncloud_connectpath,
    .brl_lock_windows_fn = skel_brl_lock_windows,
    .brl_unlock_windows_fn = skel_brl_unlock_windows,
    .brl_cancel_windows_fn = skel_brl_cancel_windows,
    .strict_lock_check_fn = skel_strict_lock_check,
    .translate_name_fn = skel_translate_name,
    .fsctl_fn = skel_fsctl,
    .readdir_attr_fn = skel_readdir_attr,

    /* DOS attributes. */
    .get_dos_attributes_fn = skel_get_dos_attributes,
    .fget_dos_attributes_fn = skel_fget_dos_attributes,
    .set_dos_attributes_fn = skel_set_dos_attributes,
    .fset_dos_attributes_fn = skel_fset_dos_attributes,

    /* NT ACL operations. */

    .fget_nt_acl_fn = skel_fget_nt_acl,
    .get_nt_acl_fn = skel_get_nt_acl,
    .fset_nt_acl_fn = skel_fset_nt_acl,

    /* POSIX ACL operations. */

    .sys_acl_get_file_fn = skel_sys_acl_get_file,
    .sys_acl_get_fd_fn = skel_sys_acl_get_fd,
    .sys_acl_blob_get_file_fn = skel_sys_acl_blob_get_file,
    .sys_acl_blob_get_fd_fn = skel_sys_acl_blob_get_fd,
    //.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
    //.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
    .sys_acl_set_file_fn = skel_sys_acl_set_file,
    .sys_acl_set_fd_fn = skel_sys_acl_set_fd,
    .sys_acl_delete_def_file_fn = skel_sys_acl_delete_def_file,

    /* EA operations. */
    .getxattr_fn = skel_getxattr,
    .fgetxattr_fn = skel_fgetxattr,
    .listxattr_fn = skel_listxattr,
    .flistxattr_fn = skel_flistxattr,
    .removexattr_fn = skel_removexattr,
    .fremovexattr_fn = skel_fremovexattr,
    .setxattr_fn = skel_setxattr,
    .fsetxattr_fn = skel_fsetxattr,

    /* aio operations */
    .aio_force_fn = skel_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_ncloud_init(TALLOC_CTX *ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "ncloud",
                &ncloud_fns);
}
