/*
 * OS X and Netatalk interoperability VFS module for Samba-3.x
 *
 * Copyright (C) Ralph Boehme, 2013, 2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "MacExtensions.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/time.h"
#include "../lib/crypto/md5.h"
#include "system/shmem.h"
#include "locking/proto.h"
#include "smbd/globals.h"
#include "messages.h"
#include "libcli/security/security.h"
#include "../libcli/smb/smb2_create_ctx.h"
#include "lib/util/sys_rw.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/tevent_unix.h"
#include "offload_token.h"
#include "string_replace.h"

/*
 * Enhanced OS X and Netatalk compatibility
 * ========================================
 *
 * This modules takes advantage of vfs_streams_xattr and
 * vfs_catia. VFS modules vfs_fruit and vfs_streams_xattr must be
 * loaded in the correct order:
 *
 *   vfs modules = catia fruit streams_xattr
 *
 * The module intercepts the OS X special streams "AFP_AfpInfo" and
 * "AFP_Resource" and handles them in a special way. All other named
 * streams are deferred to vfs_streams_xattr.
 *
 * The OS X client maps all NTFS illegal characters to the Unicode
 * private range. This module optionally stores the charcters using
 * their native ASCII encoding using vfs_catia. If you're not enabling
 * this feature, you can skip catia from vfs modules.
 *
 * Finally, open modes are optionally checked against Netatalk AFP
 * share modes.
 *
 * The "AFP_AfpInfo" named stream is a binary blob containing OS X
 * extended metadata for files and directories. This module optionally
 * reads and stores this metadata in a way compatible with Netatalk 3
 * which stores the metadata in an EA "org.netatalk.metadata". Cf
 * source3/include/MacExtensions.h for a description of the binary
 * blobs content.
 *
 * The "AFP_Resource" named stream may be arbitrarily large, thus it
 * can't be stored in an xattr on most filesystem. ZFS on Solaris is
 * the only available filesystem where xattrs can be of any size and
 * the OS supports using the file APIs for xattrs.
 *
 * The AFP_Resource stream is stored in an AppleDouble file prepending
 * "._" to the filename. On Solaris with ZFS the stream is optionally
 * stored in an EA "org.netatalk.resource".
 *
 *
 * Extended Attributes
 * ===================
 *
 * The OS X SMB client sends xattrs as ADS too. For xattr interop with
 * other protocols you may want to adjust the xattr names the VFS
 * module vfs_streams_xattr uses for storing ADS's. This defaults to
 * user.DosStream.ADS_NAME:$DATA and can be changed by specifying
 * these module parameters:
 *
 *   streams_xattr:prefix = user.
 *   streams_xattr:store_stream_type = false
 *
 *
 * TODO
 * ====
 *
 * - log diagnostic if any needed VFS module is not loaded
 *   (eg with lp_vfs_objects())
 * - add tests
 */

static int vfs_fruit_debug_level = DBGC_VFS;

static struct global_fruit_config {
	bool nego_aapl;	/* client negotiated AAPL */

} global_fruit_config;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_fruit_debug_level

#define FRUIT_PARAM_TYPE_NAME "fruit"
#define ADOUBLE_NAME_PREFIX "._"

#define NETATALK_META_XATTR "org.netatalk.Metadata"
#define NETATALK_RSRC_XATTR "org.netatalk.ResourceFork"

#if defined(HAVE_ATTROPEN)
#define AFPINFO_EA_NETATALK NETATALK_META_XATTR
#define AFPRESOURCE_EA_NETATALK NETATALK_RSRC_XATTR
#else
#define AFPINFO_EA_NETATALK "user." NETATALK_META_XATTR
#define AFPRESOURCE_EA_NETATALK "user." NETATALK_RSRC_XATTR
#endif

enum apple_fork {APPLE_FORK_DATA, APPLE_FORK_RSRC};

enum fruit_rsrc {FRUIT_RSRC_STREAM, FRUIT_RSRC_ADFILE, FRUIT_RSRC_XATTR};
enum fruit_meta {FRUIT_META_STREAM, FRUIT_META_NETATALK};
enum fruit_locking {FRUIT_LOCKING_NETATALK, FRUIT_LOCKING_NONE};
enum fruit_encoding {FRUIT_ENC_NATIVE, FRUIT_ENC_PRIVATE};

struct fruit_config_data {
	enum fruit_rsrc rsrc;
	enum fruit_meta meta;
	enum fruit_locking locking;
	enum fruit_encoding encoding;
	bool use_aapl;		/* config from smb.conf */
	bool use_copyfile;
	bool readdir_attr_enabled;
	bool unix_info_enabled;
	bool copyfile_enabled;
	bool veto_appledouble;
	bool posix_rename;
	bool aapl_zero_file_id;
	const char *model;
	bool time_machine;
	off_t time_machine_max_size;
	bool wipe_intentionally_left_blank_rfork;
	bool delete_empty_adfiles;

	/*
	 * Additional options, all enabled by default,
	 * possibly useful for analyzing performance. The associated
	 * operations with each of them may be expensive, so having
	 * the chance to disable them individually gives a chance
	 * tweaking the setup for the particular usecase.
	 */
	bool readdir_attr_rsize;
	bool readdir_attr_finder_info;
	bool readdir_attr_max_access;
};

static const struct enum_list fruit_rsrc[] = {
	{FRUIT_RSRC_STREAM, "stream"}, /* pass on to vfs_streams_xattr */
	{FRUIT_RSRC_ADFILE, "file"}, /* ._ AppleDouble file */
	{FRUIT_RSRC_XATTR, "xattr"}, /* Netatalk compatible xattr (ZFS only) */
	{ -1, NULL}
};

static const struct enum_list fruit_meta[] = {
	{FRUIT_META_STREAM, "stream"}, /* pass on to vfs_streams_xattr */
	{FRUIT_META_NETATALK, "netatalk"}, /* Netatalk compatible xattr */
	{ -1, NULL}
};

static const struct enum_list fruit_locking[] = {
	{FRUIT_LOCKING_NETATALK, "netatalk"}, /* synchronize locks with Netatalk */
	{FRUIT_LOCKING_NONE, "none"},
	{ -1, NULL}
};

static const struct enum_list fruit_encoding[] = {
	{FRUIT_ENC_NATIVE, "native"}, /* map unicode private chars to ASCII */
	{FRUIT_ENC_PRIVATE, "private"}, /* keep unicode private chars */
	{ -1, NULL}
};

static const char *fruit_catia_maps =
	"0x01:0xf001,0x02:0xf002,0x03:0xf003,0x04:0xf004,"
	"0x05:0xf005,0x06:0xf006,0x07:0xf007,0x08:0xf008,"
	"0x09:0xf009,0x0a:0xf00a,0x0b:0xf00b,0x0c:0xf00c,"
	"0x0d:0xf00d,0x0e:0xf00e,0x0f:0xf00f,0x10:0xf010,"
	"0x11:0xf011,0x12:0xf012,0x13:0xf013,0x14:0xf014,"
	"0x15:0xf015,0x16:0xf016,0x17:0xf017,0x18:0xf018,"
	"0x19:0xf019,0x1a:0xf01a,0x1b:0xf01b,0x1c:0xf01c,"
	"0x1d:0xf01d,0x1e:0xf01e,0x1f:0xf01f,"
	"0x22:0xf020,0x2a:0xf021,0x3a:0xf022,0x3c:0xf023,"
	"0x3e:0xf024,0x3f:0xf025,0x5c:0xf026,0x7c:0xf027,"
	"0x0d:0xf00d";

/*****************************************************************************
 * Defines, functions and data structures that deal with AppleDouble
 *****************************************************************************/

/*
 * There are two AppleDouble blobs we deal with:
 *
 * - ADOUBLE_META - AppleDouble blob used by Netatalk for storing
 *   metadata in an xattr
 *
 * - ADOUBLE_RSRC - AppleDouble blob used by OS X and Netatalk in
 *   ._ files
 */
typedef enum {ADOUBLE_META, ADOUBLE_RSRC} adouble_type_t;

/* Version info */
#define AD_VERSION2     0x00020000
#define AD_VERSION      AD_VERSION2

/*
 * AppleDouble entry IDs.
 */
#define ADEID_DFORK         1
#define ADEID_RFORK         2
#define ADEID_NAME          3
#define ADEID_COMMENT       4
#define ADEID_ICONBW        5
#define ADEID_ICONCOL       6
#define ADEID_FILEI         7
#define ADEID_FILEDATESI    8
#define ADEID_FINDERI       9
#define ADEID_MACFILEI      10
#define ADEID_PRODOSFILEI   11
#define ADEID_MSDOSFILEI    12
#define ADEID_SHORTNAME     13
#define ADEID_AFPFILEI      14
#define ADEID_DID           15

/* Private Netatalk entries */
#define ADEID_PRIVDEV       16
#define ADEID_PRIVINO       17
#define ADEID_PRIVSYN       18
#define ADEID_PRIVID        19
#define ADEID_MAX           (ADEID_PRIVID + 1)

/*
 * These are the real ids for the private entries,
 * as stored in the adouble file
 */
#define AD_DEV              0x80444556
#define AD_INO              0x80494E4F
#define AD_SYN              0x8053594E
#define AD_ID               0x8053567E

/* Number of actually used entries */
#define ADEID_NUM_XATTR      8
#define ADEID_NUM_DOT_UND    2
#define ADEID_NUM_RSRC_XATTR 1

/* AppleDouble magic */
#define AD_APPLESINGLE_MAGIC 0x00051600
#define AD_APPLEDOUBLE_MAGIC 0x00051607
#define AD_MAGIC             AD_APPLEDOUBLE_MAGIC

/* Sizes of relevant entry bits */
#define ADEDLEN_MAGIC       4
#define ADEDLEN_VERSION     4
#define ADEDLEN_FILLER      16
#define AD_FILLER_TAG       "Netatalk        " /* should be 16 bytes */
#define AD_FILLER_TAG_OSX   "Mac OS X        " /* should be 16 bytes */
#define ADEDLEN_NENTRIES    2
#define AD_HEADER_LEN       (ADEDLEN_MAGIC + ADEDLEN_VERSION + \
			     ADEDLEN_FILLER + ADEDLEN_NENTRIES) /* 26 */
#define AD_ENTRY_LEN_EID    4
#define AD_ENTRY_LEN_OFF    4
#define AD_ENTRY_LEN_LEN    4
#define AD_ENTRY_LEN (AD_ENTRY_LEN_EID + AD_ENTRY_LEN_OFF + AD_ENTRY_LEN_LEN)

/* Field widths */
#define ADEDLEN_NAME            255
#define ADEDLEN_COMMENT         200
#define ADEDLEN_FILEI           16
#define ADEDLEN_FINDERI         32
#define ADEDLEN_FILEDATESI      16
#define ADEDLEN_SHORTNAME       12 /* length up to 8.3 */
#define ADEDLEN_AFPFILEI        4
#define ADEDLEN_MACFILEI        4
#define ADEDLEN_PRODOSFILEI     8
#define ADEDLEN_MSDOSFILEI      2
#define ADEDLEN_DID             4
#define ADEDLEN_PRIVDEV         8
#define ADEDLEN_PRIVINO         8
#define ADEDLEN_PRIVSYN         8
#define ADEDLEN_PRIVID          4

/* Offsets */
#define ADEDOFF_MAGIC         0
#define ADEDOFF_VERSION       (ADEDOFF_MAGIC + ADEDLEN_MAGIC)
#define ADEDOFF_FILLER        (ADEDOFF_VERSION + ADEDLEN_VERSION)
#define ADEDOFF_NENTRIES      (ADEDOFF_FILLER + ADEDLEN_FILLER)

#define ADEDOFF_FINDERI_XATTR    (AD_HEADER_LEN + \
				  (ADEID_NUM_XATTR * AD_ENTRY_LEN))
#define ADEDOFF_COMMENT_XATTR    (ADEDOFF_FINDERI_XATTR    + ADEDLEN_FINDERI)
#define ADEDOFF_FILEDATESI_XATTR (ADEDOFF_COMMENT_XATTR    + ADEDLEN_COMMENT)
#define ADEDOFF_AFPFILEI_XATTR   (ADEDOFF_FILEDATESI_XATTR + \
				  ADEDLEN_FILEDATESI)
#define ADEDOFF_PRIVDEV_XATTR    (ADEDOFF_AFPFILEI_XATTR   + ADEDLEN_AFPFILEI)
#define ADEDOFF_PRIVINO_XATTR    (ADEDOFF_PRIVDEV_XATTR    + ADEDLEN_PRIVDEV)
#define ADEDOFF_PRIVSYN_XATTR    (ADEDOFF_PRIVINO_XATTR    + ADEDLEN_PRIVINO)
#define ADEDOFF_PRIVID_XATTR     (ADEDOFF_PRIVSYN_XATTR    + ADEDLEN_PRIVSYN)

#define ADEDOFF_FINDERI_DOT_UND  (AD_HEADER_LEN + \
				  (ADEID_NUM_DOT_UND * AD_ENTRY_LEN))
#define ADEDOFF_RFORK_DOT_UND    (ADEDOFF_FINDERI_DOT_UND + ADEDLEN_FINDERI)

#define AD_DATASZ_XATTR (AD_HEADER_LEN + \
			 (ADEID_NUM_XATTR * AD_ENTRY_LEN) + \
			 ADEDLEN_FINDERI + ADEDLEN_COMMENT + \
			 ADEDLEN_FILEDATESI + ADEDLEN_AFPFILEI + \
			 ADEDLEN_PRIVDEV + ADEDLEN_PRIVINO + \
			 ADEDLEN_PRIVSYN + ADEDLEN_PRIVID)

#if AD_DATASZ_XATTR != 402
#error bad size for AD_DATASZ_XATTR
#endif

#define AD_DATASZ_DOT_UND (AD_HEADER_LEN + \
			   (ADEID_NUM_DOT_UND * AD_ENTRY_LEN) + \
			   ADEDLEN_FINDERI)
#if AD_DATASZ_DOT_UND != 82
#error bad size for AD_DATASZ_DOT_UND
#endif

/*
 * Sharemode locks fcntl() offsets
 */
#if _FILE_OFFSET_BITS == 64 || defined(HAVE_LARGEFILE)
#define AD_FILELOCK_BASE (UINT64_C(0x7FFFFFFFFFFFFFFF) - 9)
#else
#define AD_FILELOCK_BASE (UINT32_C(0x7FFFFFFF) - 9)
#endif
#define BYTELOCK_MAX (AD_FILELOCK_BASE - 1)

#define AD_FILELOCK_OPEN_WR        (AD_FILELOCK_BASE + 0)
#define AD_FILELOCK_OPEN_RD        (AD_FILELOCK_BASE + 1)
#define AD_FILELOCK_RSRC_OPEN_WR   (AD_FILELOCK_BASE + 2)
#define AD_FILELOCK_RSRC_OPEN_RD   (AD_FILELOCK_BASE + 3)
#define AD_FILELOCK_DENY_WR        (AD_FILELOCK_BASE + 4)
#define AD_FILELOCK_DENY_RD        (AD_FILELOCK_BASE + 5)
#define AD_FILELOCK_RSRC_DENY_WR   (AD_FILELOCK_BASE + 6)
#define AD_FILELOCK_RSRC_DENY_RD   (AD_FILELOCK_BASE + 7)
#define AD_FILELOCK_OPEN_NONE      (AD_FILELOCK_BASE + 8)
#define AD_FILELOCK_RSRC_OPEN_NONE (AD_FILELOCK_BASE + 9)

/* Time stuff we overload the bits a little */
#define AD_DATE_CREATE         0
#define AD_DATE_MODIFY         4
#define AD_DATE_BACKUP         8
#define AD_DATE_ACCESS        12
#define AD_DATE_MASK          (AD_DATE_CREATE | AD_DATE_MODIFY | \
                               AD_DATE_BACKUP | AD_DATE_ACCESS)
#define AD_DATE_UNIX          (1 << 10)
#define AD_DATE_START         0x80000000
#define AD_DATE_DELTA         946684800
#define AD_DATE_FROM_UNIX(x)  (htonl((x) - AD_DATE_DELTA))
#define AD_DATE_TO_UNIX(x)    (ntohl(x) + AD_DATE_DELTA)

#define AD_XATTR_HDR_MAGIC    0x41545452 /* 'ATTR' */
#define AD_XATTR_MAX_ENTRIES  1024 /* Some arbitrarily enforced limit */
#define AD_XATTR_HDR_SIZE     36
#define AD_XATTR_MAX_HDR_SIZE 65536

/* Accessor macros */
#define ad_getentrylen(ad,eid)     ((ad)->ad_eid[(eid)].ade_len)
#define ad_getentryoff(ad,eid)     ((ad)->ad_eid[(eid)].ade_off)
#define ad_setentrylen(ad,eid,len) ((ad)->ad_eid[(eid)].ade_len = (len))
#define ad_setentryoff(ad,eid,off) ((ad)->ad_eid[(eid)].ade_off = (off))

/*
 * Both struct ad_xattr_header and struct ad_xattr_entry describe the in memory
 * representation as well as the on-disk format.
 *
 * The ad_xattr_header follows the FinderInfo data in the FinderInfo entry if
 * the length of the FinderInfo entry is larger then 32 bytes. It is then
 * preceeded with 2 bytes padding.
 *
 * Cf: https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/vfs/vfs_xattr.c
 */

struct ad_xattr_header {
	uint32_t adx_magic;        /* ATTR_HDR_MAGIC */
	uint32_t adx_debug_tag;    /* for debugging == file id of owning file */
	uint32_t adx_total_size;   /* file offset of end of attribute header + entries + data */
	uint32_t adx_data_start;   /* file offset to attribute data area */
	uint32_t adx_data_length;  /* length of attribute data area */
	uint32_t adx_reserved[3];
	uint16_t adx_flags;
	uint16_t adx_num_attrs;
};

/* On-disk entries are aligned on 4 byte boundaries */
struct ad_xattr_entry {
	uint32_t adx_offset;    /* file offset to data */
	uint32_t adx_length;    /* size of attribute data */
	uint16_t adx_flags;
	uint8_t  adx_namelen;	/* included the NULL terminator */
	char    *adx_name;      /* NULL-terminated UTF-8 name */
};

struct ad_entry {
	size_t ade_off;
	size_t ade_len;
};

struct adouble {
	vfs_handle_struct        *ad_handle;
	int                       ad_fd;
	bool                      ad_opened;
	adouble_type_t            ad_type;
	uint32_t                  ad_magic;
	uint32_t                  ad_version;
	uint8_t                   ad_filler[ADEDLEN_FILLER];
	struct ad_entry           ad_eid[ADEID_MAX];
	char                     *ad_data;
	struct ad_xattr_header    adx_header;
	struct ad_xattr_entry    *adx_entries;
};

struct ad_entry_order {
	uint32_t id, offset, len;
};

/* Netatalk AppleDouble metadata xattr */
static const
struct ad_entry_order entry_order_meta_xattr[ADEID_NUM_XATTR + 1] = {
	{ADEID_FINDERI,    ADEDOFF_FINDERI_XATTR,    ADEDLEN_FINDERI},
	{ADEID_COMMENT,    ADEDOFF_COMMENT_XATTR,    0},
	{ADEID_FILEDATESI, ADEDOFF_FILEDATESI_XATTR, ADEDLEN_FILEDATESI},
	{ADEID_AFPFILEI,   ADEDOFF_AFPFILEI_XATTR,   ADEDLEN_AFPFILEI},
	{ADEID_PRIVDEV,    ADEDOFF_PRIVDEV_XATTR,    0},
	{ADEID_PRIVINO,    ADEDOFF_PRIVINO_XATTR,    0},
	{ADEID_PRIVSYN,    ADEDOFF_PRIVSYN_XATTR,    0},
	{ADEID_PRIVID,     ADEDOFF_PRIVID_XATTR,     0},
	{0, 0, 0}
};

/* AppleDouble resource fork file (the ones prefixed by "._") */
static const
struct ad_entry_order entry_order_dot_und[ADEID_NUM_DOT_UND + 1] = {
	{ADEID_FINDERI,    ADEDOFF_FINDERI_DOT_UND,  ADEDLEN_FINDERI},
	{ADEID_RFORK,      ADEDOFF_RFORK_DOT_UND,    0},
	{0, 0, 0}
};

/*
 * Fake AppleDouble entry oder for resource fork xattr.  The xattr
 * isn't an AppleDouble file, it simply contains the resource data,
 * but in order to be able to use some API calls like ad_getentryoff()
 * we build a fake/helper struct adouble with this entry order struct.
 */
static const
struct ad_entry_order entry_order_rsrc_xattr[ADEID_NUM_RSRC_XATTR + 1] = {
	{ADEID_RFORK, 0, 0},
	{0, 0, 0}
};

/* Conversion from enumerated id to on-disk AppleDouble id */
#define AD_EID_DISK(a) (set_eid[a])
static const uint32_t set_eid[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	AD_DEV, AD_INO, AD_SYN, AD_ID
};

static char empty_resourcefork[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E,
	0x54, 0x68, 0x69, 0x73, 0x20, 0x72, 0x65, 0x73,
	0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x66, 0x6F,
	0x72, 0x6B, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6E,
	0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x6C, 0x79,
	0x20, 0x6C, 0x65, 0x66, 0x74, 0x20, 0x62, 0x6C,
	0x61, 0x6E, 0x6B, 0x20, 0x20, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x1C, 0x00, 0x1E, 0xFF, 0xFF
};

struct fio {
	/* tcon config handle */
	struct fruit_config_data *config;

	/* Denote stream type, meta or rsrc */
	adouble_type_t type;

	/* Whether the create created the stream */
	bool created;

	/*
	 * AFP_AfpInfo stream created, but not written yet, thus still a fake
	 * pipe fd. This is set to true in fruit_open_meta if there was no
	 * exisiting stream but the caller requested O_CREAT. It is later set to
	 * false when we get a write on the stream that then does open and
	 * create the stream.
	 */
	bool fake_fd;
	int flags;
	int mode;
};

/*
 * Forward declarations
 */
static struct adouble *ad_init(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			       adouble_type_t type);
static int ad_set(struct adouble *ad, const struct smb_filename *smb_fname);
static int ad_fset(struct adouble *ad, files_struct *fsp);
static int adouble_path(TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname__in,
			struct smb_filename **ppsmb_fname_out);
static AfpInfo *afpinfo_new(TALLOC_CTX *ctx);
static ssize_t afpinfo_pack(const AfpInfo *ai, char *buf);
static AfpInfo *afpinfo_unpack(TALLOC_CTX *ctx, const void *data);


/**
 * Return a pointer to an AppleDouble entry
 *
 * Returns NULL if the entry is not present
 **/
static char *ad_get_entry(const struct adouble *ad, int eid)
{
	off_t off = ad_getentryoff(ad, eid);
	size_t len = ad_getentrylen(ad, eid);

	if (off == 0 || len == 0) {
		return NULL;
	}

	return ad->ad_data + off;
}

/**
 * Get a date
 **/
static int ad_getdate(const struct adouble *ad,
		      unsigned int dateoff,
		      uint32_t *date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);
	char *p = NULL;

	dateoff &= AD_DATE_MASK;
	p = ad_get_entry(ad, ADEID_FILEDATESI);
	if (p == NULL) {
		return -1;
	}

	if (dateoff > AD_DATE_ACCESS) {
	    return -1;
	}

	memcpy(date, p + dateoff, sizeof(uint32_t));

	if (xlate) {
		*date = AD_DATE_TO_UNIX(*date);
	}
	return 0;
}

/**
 * Set a date
 **/
static int ad_setdate(struct adouble *ad, unsigned int dateoff, uint32_t date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);
	char *p = NULL;

	p = ad_get_entry(ad, ADEID_FILEDATESI);
	if (p == NULL) {
		return -1;
	}

	dateoff &= AD_DATE_MASK;
	if (xlate) {
		date = AD_DATE_FROM_UNIX(date);
	}

	if (dateoff > AD_DATE_ACCESS) {
		return -1;
	}

	memcpy(p + dateoff, &date, sizeof(date));

	return 0;
}


/**
 * Map on-disk AppleDouble id to enumerated id
 **/
static uint32_t get_eid(uint32_t eid)
{
	if (eid <= 15) {
		return eid;
	}

	switch (eid) {
	case AD_DEV:
		return ADEID_PRIVDEV;
	case AD_INO:
		return ADEID_PRIVINO;
	case AD_SYN:
		return ADEID_PRIVSYN;
	case AD_ID:
		return ADEID_PRIVID;
	default:
		break;
	}

	return 0;
}

/**
 * Pack AppleDouble structure into data buffer
 **/
static bool ad_pack(struct adouble *ad)
{
	uint32_t       eid;
	uint16_t       nent;
	uint32_t       bufsize;
	uint32_t       offset = 0;

	bufsize = talloc_get_size(ad->ad_data);
	if (bufsize < AD_DATASZ_DOT_UND) {
		DBG_ERR("bad buffer size [0x%" PRIx32 "]\n", bufsize);
		return false;
	}

	if (offset + ADEDLEN_MAGIC < offset ||
			offset + ADEDLEN_MAGIC >= bufsize) {
		return false;
	}
	RSIVAL(ad->ad_data, offset, ad->ad_magic);
	offset += ADEDLEN_MAGIC;

	if (offset + ADEDLEN_VERSION < offset ||
			offset + ADEDLEN_VERSION >= bufsize) {
		return false;
	}
	RSIVAL(ad->ad_data, offset, ad->ad_version);
	offset += ADEDLEN_VERSION;

	if (offset + ADEDLEN_FILLER < offset ||
			offset + ADEDLEN_FILLER >= bufsize) {
		return false;
	}
	if (ad->ad_type == ADOUBLE_RSRC) {
		memcpy(ad->ad_data + offset, AD_FILLER_TAG, ADEDLEN_FILLER);
	}
	offset += ADEDLEN_FILLER;

	if (offset + ADEDLEN_NENTRIES < offset ||
			offset + ADEDLEN_NENTRIES >= bufsize) {
		return false;
	}
	offset += ADEDLEN_NENTRIES;

	for (eid = 0, nent = 0; eid < ADEID_MAX; eid++) {
		if (ad->ad_eid[eid].ade_off == 0) {
			/*
			 * ade_off is also used as indicator whether a
			 * specific entry is used or not
			 */
			continue;
		}

		if (offset + AD_ENTRY_LEN_EID < offset ||
				offset + AD_ENTRY_LEN_EID >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, AD_EID_DISK(eid));
		offset += AD_ENTRY_LEN_EID;

		if (offset + AD_ENTRY_LEN_OFF < offset ||
				offset + AD_ENTRY_LEN_OFF >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, ad->ad_eid[eid].ade_off);
		offset += AD_ENTRY_LEN_OFF;

		if (offset + AD_ENTRY_LEN_LEN < offset ||
				offset + AD_ENTRY_LEN_LEN >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, ad->ad_eid[eid].ade_len);
		offset += AD_ENTRY_LEN_LEN;

		nent++;
	}

	if (ADEDOFF_NENTRIES + 2 >= bufsize) {
		return false;
	}
	RSSVAL(ad->ad_data, ADEDOFF_NENTRIES, nent);

	return true;
}

static bool ad_unpack_xattrs(struct adouble *ad)
{
	struct ad_xattr_header *h = &ad->adx_header;
	const char *p = ad->ad_data;
	uint32_t hoff;
	uint32_t i;

	if (ad_getentrylen(ad, ADEID_FINDERI) <= ADEDLEN_FINDERI) {
		return true;
	}

	/* 2 bytes padding */
	hoff = ad_getentryoff(ad, ADEID_FINDERI) + ADEDLEN_FINDERI + 2;

	h->adx_magic       = RIVAL(p, hoff + 0);
	h->adx_debug_tag   = RIVAL(p, hoff + 4); /* Not used -> not checked */
	h->adx_total_size  = RIVAL(p, hoff + 8);
	h->adx_data_start  = RIVAL(p, hoff + 12);
	h->adx_data_length = RIVAL(p, hoff + 16);
	h->adx_flags       = RSVAL(p, hoff + 32); /* Not used -> not checked */
	h->adx_num_attrs   = RSVAL(p, hoff + 34);

	if (h->adx_magic != AD_XATTR_HDR_MAGIC) {
		DBG_ERR("Bad magic: 0x%" PRIx32 "\n", h->adx_magic);
		return false;
	}

	if (h->adx_total_size > ad_getentryoff(ad, ADEID_RFORK)) {
		DBG_ERR("Bad total size: 0x%" PRIx32 "\n", h->adx_total_size);
		return false;
	}
	if (h->adx_total_size > AD_XATTR_MAX_HDR_SIZE) {
		DBG_ERR("Bad total size: 0x%" PRIx32 "\n", h->adx_total_size);
		return false;
	}

	if (h->adx_data_start < (hoff + AD_XATTR_HDR_SIZE)) {
		DBG_ERR("Bad start: 0x%" PRIx32 "\n", h->adx_data_start);
		return false;
	}

	if ((h->adx_data_start + h->adx_data_length) < h->adx_data_start) {
		DBG_ERR("Bad length: %" PRIu32 "\n", h->adx_data_length);
		return false;
	}
	if ((h->adx_data_start + h->adx_data_length) >
	    ad->adx_header.adx_total_size)
	{
		DBG_ERR("Bad length: %" PRIu32 "\n", h->adx_data_length);
		return false;
	}

	if (h->adx_num_attrs > AD_XATTR_MAX_ENTRIES) {
		DBG_ERR("Bad num xattrs: %" PRIu16 "\n", h->adx_num_attrs);
		return false;
	}

	if (h->adx_num_attrs == 0) {
		return true;
	}

	ad->adx_entries = talloc_zero_array(
		ad, struct ad_xattr_entry, h->adx_num_attrs);
	if (ad->adx_entries == NULL) {
		return false;
	}

	hoff += AD_XATTR_HDR_SIZE;

	for (i = 0; i < h->adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];

		hoff = (hoff + 3) & ~3;

		e->adx_offset  = RIVAL(p, hoff + 0);
		e->adx_length  = RIVAL(p, hoff + 4);
		e->adx_flags   = RSVAL(p, hoff + 8);
		e->adx_namelen = *(p + hoff + 10);

		if (e->adx_offset >= ad->adx_header.adx_total_size) {
			DBG_ERR("Bad adx_offset: %" PRIx32 "\n",
				e->adx_offset);
			return false;
		}

		if ((e->adx_offset + e->adx_length) < e->adx_offset) {
			DBG_ERR("Bad adx_length: %" PRIx32 "\n",
				e->adx_length);
			return false;
		}

		if ((e->adx_offset + e->adx_length) >
		    ad->adx_header.adx_total_size)
		{
			DBG_ERR("Bad adx_length: %" PRIx32 "\n",
				e->adx_length);
			return false;
		}

		if (e->adx_namelen == 0) {
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}
		if ((hoff + 11 + e->adx_namelen) < hoff + 11) {
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}
		if ((hoff + 11 + e->adx_namelen) >
		    ad->adx_header.adx_data_start)
		{
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}

		e->adx_name = talloc_strndup(ad->adx_entries,
					     p + hoff + 11,
					     e->adx_namelen);
		if (e->adx_name == NULL) {
			return false;
		}

		DBG_DEBUG("xattr [%s] offset [0x%x] size [0x%x]\n",
			  e->adx_name, e->adx_offset, e->adx_length);
		dump_data(10, (uint8_t *)(ad->ad_data + e->adx_offset),
			  e->adx_length);

		hoff += 11 + e->adx_namelen;
	}

	return true;
}

/**
 * Unpack an AppleDouble blob into a struct adoble
 **/
static bool ad_unpack(struct adouble *ad, const size_t nentries,
		      size_t filesize)
{
	size_t bufsize = talloc_get_size(ad->ad_data);
	size_t adentries, i;
	uint32_t eid, len, off;
	bool ok;

	/*
	 * The size of the buffer ad->ad_data is checked when read, so
	 * we wouldn't have to check our own offsets, a few extra
	 * checks won't hurt though. We have to check the offsets we
	 * read from the buffer anyway.
	 */

	if (bufsize < (AD_HEADER_LEN + (AD_ENTRY_LEN * nentries))) {
		DEBUG(1, ("bad size\n"));
		return false;
	}

	ad->ad_magic = RIVAL(ad->ad_data, 0);
	ad->ad_version = RIVAL(ad->ad_data, ADEDOFF_VERSION);
	if ((ad->ad_magic != AD_MAGIC) || (ad->ad_version != AD_VERSION)) {
		DEBUG(1, ("wrong magic or version\n"));
		return false;
	}

	memcpy(ad->ad_filler, ad->ad_data + ADEDOFF_FILLER, ADEDLEN_FILLER);

	adentries = RSVAL(ad->ad_data, ADEDOFF_NENTRIES);
	if (adentries != nentries) {
		DEBUG(1, ("invalid number of entries: %zu\n",
			  adentries));
		return false;
	}

	/* now, read in the entry bits */
	for (i = 0; i < adentries; i++) {
		eid = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN));
		eid = get_eid(eid);
		off = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 4);
		len = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 8);

		if (!eid || eid >= ADEID_MAX) {
			DEBUG(1, ("bogus eid %d\n", eid));
			return false;
		}

		/*
		 * All entries other than the resource fork are
		 * expected to be read into the ad_data buffer, so
		 * ensure the specified offset is within that bound
		 */
		if ((off > bufsize) && (eid != ADEID_RFORK)) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		/*
		 * All entries besides FinderInfo and resource fork
		 * must fit into the buffer. FinderInfo is special as
		 * it may be larger then the default 32 bytes (if it
		 * contains marshalled xattrs), but we will fixup that
		 * in ad_convert(). And the resource fork is never
		 * accessed directly by the ad_data buf (also see
		 * comment above) anyway.
		 */
		if ((eid != ADEID_RFORK) &&
		    (eid != ADEID_FINDERI) &&
		    ((off + len) > bufsize)) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		/*
		 * That would be obviously broken
		 */
		if (off > filesize) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		/*
		 * Check for any entry that has its end beyond the
		 * filesize.
		 */
		if (off + len < off) {
			DEBUG(1, ("offset wrap in eid %d: off: %" PRIu32
				  ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;

		}
		if (off + len > filesize) {
			/*
			 * If this is the resource fork entry, we fix
			 * up the length, for any other entry we bail
			 * out.
			 */
			if (eid != ADEID_RFORK) {
				DEBUG(1, ("bogus eid %d: off: %" PRIu32
					  ", len: %" PRIu32 "\n",
					  eid, off, len));
				return false;
			}

			/*
			 * Fixup the resource fork entry by limiting
			 * the size to entryoffset - filesize.
			 */
			len = filesize - off;
			DEBUG(1, ("Limiting ADEID_RFORK: off: %" PRIu32
				  ", len: %" PRIu32 "\n", off, len));
		}

		ad->ad_eid[eid].ade_off = off;
		ad->ad_eid[eid].ade_len = len;
	}

	ok = ad_unpack_xattrs(ad);
	if (!ok) {
		return false;
	}

	return true;
}

static bool ad_convert_move_reso(struct adouble *ad,
				 const struct smb_filename *smb_fname)
{
	char *map = MAP_FAILED;
	size_t maplen;
	ssize_t len;
	int rc;
	bool ok;

	if (ad_getentrylen(ad, ADEID_RFORK) == 0) {
		return true;
	}

	maplen = ad_getentryoff(ad, ADEID_RFORK) +
		ad_getentrylen(ad, ADEID_RFORK);

	/* FIXME: direct use of mmap(), vfs_aio_fork does it too */
	map = mmap(NULL, maplen, PROT_READ|PROT_WRITE, MAP_SHARED,
		   ad->ad_fd, 0);
	if (map == MAP_FAILED) {
		DBG_ERR("mmap AppleDouble: %s\n", strerror(errno));
		return false;
	}


	memmove(map + ADEDOFF_RFORK_DOT_UND,
		map + ad_getentryoff(ad, ADEID_RFORK),
		ad_getentrylen(ad, ADEID_RFORK));

	rc = munmap(map, maplen);
	if (rc != 0) {
		DBG_ERR("munmap failed: %s\n", strerror(errno));
		return false;
	}

	ad_setentryoff(ad, ADEID_RFORK, ADEDOFF_RFORK_DOT_UND);

	ok = ad_pack(ad);
	if (!ok) {
		DBG_WARNING("ad_pack [%s] failed\n", smb_fname->base_name);
		return false;
	}

	len = sys_pwrite(ad->ad_fd, ad->ad_data, AD_DATASZ_DOT_UND, 0);
	if (len != AD_DATASZ_DOT_UND) {
		DBG_ERR("%s: bad size: %zd\n", smb_fname->base_name, len);
		return false;
	}

	return true;
}

static bool ad_convert_xattr(struct adouble *ad,
			     const struct smb_filename *smb_fname,
			     bool *converted_xattr)
{
	static struct char_mappings **string_replace_cmaps = NULL;
	char *map = MAP_FAILED;
	size_t maplen;
	uint16_t i;
	ssize_t len;
	int saved_errno = 0;
	NTSTATUS status;
	int rc;
	bool ok;

	*converted_xattr = false;

	if (ad_getentrylen(ad, ADEID_FINDERI) == ADEDLEN_FINDERI) {
		return true;
	}

	if (string_replace_cmaps == NULL) {
		const char **mappings = NULL;

		mappings = str_list_make_v3_const(
			talloc_tos(), fruit_catia_maps, NULL);
		if (mappings == NULL) {
			return false;
		}
		string_replace_cmaps = string_replace_init_map(mappings);
		TALLOC_FREE(mappings);
	}

	maplen = ad_getentryoff(ad, ADEID_RFORK) +
		ad_getentrylen(ad, ADEID_RFORK);

	/* FIXME: direct use of mmap(), vfs_aio_fork does it too */
	map = mmap(NULL, maplen, PROT_READ|PROT_WRITE, MAP_SHARED,
		   ad->ad_fd, 0);
	if (map == MAP_FAILED) {
		DBG_ERR("mmap AppleDouble: %s\n", strerror(errno));
		return false;
	}

	for (i = 0; i < ad->adx_header.adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];
		char *mapped_name = NULL;
		char *tmp = NULL;
		struct smb_filename *stream_name = NULL;
		files_struct *fsp = NULL;
		ssize_t nwritten;

		status = string_replace_allocate(ad->ad_handle->conn,
						 e->adx_name,
						 string_replace_cmaps,
						 talloc_tos(),
						 &mapped_name,
						 vfs_translate_to_windows);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED))
		{
			DBG_ERR("string_replace_allocate failed\n");
			ok = false;
			goto fail;
		}

		tmp = mapped_name;
		mapped_name = talloc_asprintf(talloc_tos(), ":%s", tmp);
		TALLOC_FREE(tmp);
		if (mapped_name == NULL) {
			ok = false;
			goto fail;
		}

		stream_name = synthetic_smb_fname(talloc_tos(),
						  smb_fname->base_name,
						  mapped_name,
						  NULL,
						  smb_fname->flags);
		TALLOC_FREE(mapped_name);
		if (stream_name == NULL) {
			DBG_ERR("synthetic_smb_fname failed\n");
			ok = false;
			goto fail;
		}

		DBG_DEBUG("stream_name: %s\n", smb_fname_str_dbg(stream_name));

		status = SMB_VFS_CREATE_FILE(
			ad->ad_handle->conn,		/* conn */
			NULL,				/* req */
			0,				/* root_dir_fid */
			stream_name,			/* fname */
			FILE_GENERIC_WRITE,		/* access_mask */
			FILE_SHARE_READ | FILE_SHARE_WRITE, /* share_access */
			FILE_OPEN_IF,			/* create_disposition */
			0,				/* create_options */
			0,				/* file_attributes */
			INTERNAL_OPEN_ONLY,		/* oplock_request */
			NULL,				/* lease */
			0,				/* allocation_size */
			0,				/* private_flags */
			NULL,				/* sd */
			NULL,				/* ea_list */
			&fsp,				/* result */
			NULL,				/* psbuf */
			NULL, NULL);			/* create context */
		TALLOC_FREE(stream_name);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("SMB_VFS_CREATE_FILE failed\n");
			ok = false;
			goto fail;
		}

		nwritten = SMB_VFS_PWRITE(fsp,
					  map + e->adx_offset,
					  e->adx_length,
					  0);
		if (nwritten == -1) {
			DBG_ERR("SMB_VFS_PWRITE failed\n");
			saved_errno = errno;
			close_file(NULL, fsp, ERROR_CLOSE);
			errno = saved_errno;
			ok = false;
			goto fail;
		}

		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			ok = false;
			goto fail;
		}
		fsp = NULL;
	}

	ad_setentrylen(ad, ADEID_FINDERI, ADEDLEN_FINDERI);

	ok = ad_pack(ad);
	if (!ok) {
		DBG_WARNING("ad_pack [%s] failed\n", smb_fname->base_name);
		goto fail;
	}

	len = sys_pwrite(ad->ad_fd, ad->ad_data, AD_DATASZ_DOT_UND, 0);
	if (len != AD_DATASZ_DOT_UND) {
		DBG_ERR("%s: bad size: %zd\n", smb_fname->base_name, len);
		ok = false;
		goto fail;
	}

	ok = ad_convert_move_reso(ad, smb_fname);
	if (!ok) {
		goto fail;
	}

	*converted_xattr = true;
	ok = true;

fail:
	rc = munmap(map, maplen);
	if (rc != 0) {
		DBG_ERR("munmap failed: %s\n", strerror(errno));
		return false;
	}

	return ok;
}

static bool ad_convert_finderinfo(struct adouble *ad,
				  const struct smb_filename *smb_fname)
{
	char *p_ad = NULL;
	AfpInfo *ai = NULL;
	DATA_BLOB aiblob;
	struct smb_filename *stream_name = NULL;
	files_struct *fsp = NULL;
	size_t size;
	ssize_t nwritten;
	NTSTATUS status;
	int saved_errno = 0;
	int cmp;

	cmp = memcmp(ad->ad_filler, AD_FILLER_TAG_OSX, ADEDLEN_FILLER);
	if (cmp != 0) {
		return true;
	}

	p_ad = ad_get_entry(ad, ADEID_FINDERI);
	if (p_ad == NULL) {
		return false;
	}

	ai = afpinfo_new(talloc_tos());
	if (ai == NULL) {
		return false;
	}

	memcpy(ai->afpi_FinderInfo, p_ad, ADEDLEN_FINDERI);

	aiblob = data_blob_talloc(talloc_tos(), NULL, AFP_INFO_SIZE);
	if (aiblob.data == NULL) {
		TALLOC_FREE(ai);
		return false;
	}

	size = afpinfo_pack(ai, (char *)aiblob.data);
	TALLOC_FREE(ai);
	if (size != AFP_INFO_SIZE) {
		return false;
	}

	stream_name = synthetic_smb_fname(talloc_tos(),
					  smb_fname->base_name,
					  AFPINFO_STREAM,
					  NULL,
					  smb_fname->flags);
	if (stream_name == NULL) {
		data_blob_free(&aiblob);
		DBG_ERR("synthetic_smb_fname failed\n");
		return false;
	}

	DBG_DEBUG("stream_name: %s\n", smb_fname_str_dbg(stream_name));

	status = SMB_VFS_CREATE_FILE(
		ad->ad_handle->conn,		/* conn */
		NULL,				/* req */
		0,				/* root_dir_fid */
		stream_name,			/* fname */
		FILE_GENERIC_WRITE,		/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE, /* share_access */
		FILE_OPEN_IF,			/* create_disposition */
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,				/* result */
		NULL,				/* psbuf */
		NULL, NULL);			/* create context */
	TALLOC_FREE(stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE failed\n");
		return false;
	}

	nwritten = SMB_VFS_PWRITE(fsp,
				  aiblob.data,
				  aiblob.length,
				  0);
	if (nwritten == -1) {
		DBG_ERR("SMB_VFS_PWRITE failed\n");
		saved_errno = errno;
		close_file(NULL, fsp, ERROR_CLOSE);
		errno = saved_errno;
		return false;
	}

	status = close_file(NULL, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	fsp = NULL;

	return true;
}

static bool ad_convert_truncate(struct adouble *ad,
				const struct smb_filename *smb_fname)
{
	int rc;

	/*
	 * FIXME: direct ftruncate(), but we don't have a fsp for the
	 * VFS call
	 */
	rc = ftruncate(ad->ad_fd, ADEDOFF_RFORK_DOT_UND +
		       ad_getentrylen(ad, ADEID_RFORK));
	if (rc != 0) {
		return false;
	}

	return true;
}

static bool ad_convert_blank_rfork(struct adouble *ad,
				   bool *blank)
{
	struct fruit_config_data *config = NULL;
	uint8_t *map = MAP_FAILED;
	size_t maplen;
	int cmp;
	ssize_t len;
	int rc;
	bool ok;

	*blank = false;

	SMB_VFS_HANDLE_GET_DATA(ad->ad_handle, config,
				struct fruit_config_data, return false);

	if (!config->wipe_intentionally_left_blank_rfork) {
		return true;
	}

	if (ad_getentrylen(ad, ADEID_RFORK) != sizeof(empty_resourcefork)) {
		return true;
	}

	maplen = ad_getentryoff(ad, ADEID_RFORK) +
		ad_getentrylen(ad, ADEID_RFORK);

	/* FIXME: direct use of mmap(), vfs_aio_fork does it too */
	map = mmap(NULL, maplen, PROT_READ|PROT_WRITE, MAP_SHARED,
		   ad->ad_fd, 0);
	if (map == MAP_FAILED) {
		DBG_ERR("mmap AppleDouble: %s\n", strerror(errno));
		return false;
	}

	cmp = memcmp(map + ADEDOFF_RFORK_DOT_UND,
		     empty_resourcefork,
		     sizeof(empty_resourcefork));
	rc = munmap(map, maplen);
	if (rc != 0) {
		DBG_ERR("munmap failed: %s\n", strerror(errno));
		return false;
	}

	if (cmp != 0) {
		return true;
	}

	ad_setentrylen(ad, ADEID_RFORK, 0);

	ok = ad_pack(ad);
	if (!ok) {
		return false;
	}

	len = sys_pwrite(ad->ad_fd, ad->ad_data, AD_DATASZ_DOT_UND, 0);
	if (len != AD_DATASZ_DOT_UND) {
		return false;
	}

	*blank = true;
	return true;
}

static bool ad_convert_delete_adfile(struct adouble *ad,
				     const struct smb_filename *smb_fname)
{
	struct fruit_config_data *config = NULL;
	struct smb_filename *ad_name = NULL;
	int rc;

	if (ad_getentrylen(ad, ADEID_RFORK) > 0) {
		return true;
	}

	SMB_VFS_HANDLE_GET_DATA(ad->ad_handle, config,
				struct fruit_config_data, return false);

	if (!config->delete_empty_adfiles) {
		return true;
	}

	rc = adouble_path(talloc_tos(), smb_fname, &ad_name);
	if (rc != 0) {
		return false;
	}

	rc = SMB_VFS_NEXT_UNLINK(ad->ad_handle, ad_name);
	if (rc != 0) {
		DBG_ERR("Unlinking [%s] failed: %s\n",
			smb_fname_str_dbg(ad_name), strerror(errno));
		TALLOC_FREE(ad_name);
		return false;
	}

	DBG_WARNING("Unlinked [%s] after conversion\n", smb_fname_str_dbg(ad_name));
	TALLOC_FREE(ad_name);

	return true;
}

/**
 * Convert from Apple's ._ file to Netatalk
 *
 * Apple's AppleDouble may contain a FinderInfo entry longer then 32
 * bytes containing packed xattrs.
 *
 * @return -1 in case an error occurred, 0 if no conversion was done, 1
 * otherwise
 **/
static int ad_convert(struct adouble *ad,
		      const struct smb_filename *smb_fname)
{
	bool ok;
	bool converted_xattr = false;
	bool blank;

	ok = ad_convert_xattr(ad, smb_fname, &converted_xattr);
	if (!ok) {
		return -1;
	}

	ok = ad_convert_blank_rfork(ad, &blank);
	if (!ok) {
		return -1;
	}

	if (converted_xattr || blank) {
		ok = ad_convert_truncate(ad, smb_fname);
		if (!ok) {
			return -1;
		}
	}

	ok = ad_convert_finderinfo(ad, smb_fname);
	if (!ok) {
		DBG_ERR("Failed to convert [%s]\n",
			smb_fname_str_dbg(smb_fname));
		return -1;
	}

	ok = ad_convert_delete_adfile(ad, smb_fname);
	if (!ok) {
		return -1;
	}

	return 0;
}

/**
 * Read and parse Netatalk AppleDouble metadata xattr
 **/
static ssize_t ad_read_meta(struct adouble *ad,
				const struct smb_filename *smb_fname)
{
	int      rc = 0;
	ssize_t  ealen;
	bool     ok;

	DEBUG(10, ("reading meta xattr for %s\n", smb_fname->base_name));

	ealen = SMB_VFS_GETXATTR(ad->ad_handle->conn, smb_fname,
				 AFPINFO_EA_NETATALK, ad->ad_data,
				 AD_DATASZ_XATTR);
	if (ealen == -1) {
		switch (errno) {
		case ENOATTR:
		case ENOENT:
			if (errno == ENOATTR) {
				errno = ENOENT;
			}
			rc = -1;
			goto exit;
		default:
			DEBUG(2, ("error reading meta xattr: %s\n",
				  strerror(errno)));
			rc = -1;
			goto exit;
		}
	}
	if (ealen != AD_DATASZ_XATTR) {
		DEBUG(2, ("bad size %zd\n", ealen));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

	/* Now parse entries */
	ok = ad_unpack(ad, ADEID_NUM_XATTR, AD_DATASZ_XATTR);
	if (!ok) {
		DEBUG(2, ("invalid AppleDouble metadata xattr\n"));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

	if (!ad_getentryoff(ad, ADEID_FINDERI)
	    || !ad_getentryoff(ad, ADEID_COMMENT)
	    || !ad_getentryoff(ad, ADEID_FILEDATESI)
	    || !ad_getentryoff(ad, ADEID_AFPFILEI)
	    || !ad_getentryoff(ad, ADEID_PRIVDEV)
	    || !ad_getentryoff(ad, ADEID_PRIVINO)
	    || !ad_getentryoff(ad, ADEID_PRIVSYN)
	    || !ad_getentryoff(ad, ADEID_PRIVID)) {
		DEBUG(2, ("invalid AppleDouble metadata xattr\n"));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

exit:
	DEBUG(10, ("reading meta xattr for %s, rc: %d\n",
		smb_fname->base_name, rc));

	if (rc != 0) {
		ealen = -1;
		if (errno == EINVAL) {
			become_root();
			removexattr(smb_fname->base_name, AFPINFO_EA_NETATALK);
			unbecome_root();
			errno = ENOENT;
		}
	}
	return ealen;
}

static int ad_open_rsrc_xattr(const struct smb_filename *smb_fname,
				int flags,
				mode_t mode)
{
#ifdef HAVE_ATTROPEN
	/* FIXME: direct Solaris xattr syscall */
	return attropen(smb_fname->base_name,
			AFPRESOURCE_EA_NETATALK, flags, mode);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int ad_open_rsrc_adouble(const struct smb_filename *smb_fname,
				int flags,
				mode_t mode)
{
	int ret;
	int fd;
	struct smb_filename *adp_smb_fname = NULL;

	ret = adouble_path(talloc_tos(), smb_fname, &adp_smb_fname);
	if (ret != 0) {
		return -1;
	}

	fd = open(adp_smb_fname->base_name, flags, mode);
	TALLOC_FREE(adp_smb_fname);

	return fd;
}

static int ad_open_rsrc(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			int flags,
			mode_t mode)
{
	struct fruit_config_data *config = NULL;
	int fd;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		fd = ad_open_rsrc_xattr(smb_fname, flags, mode);
	} else {
		fd = ad_open_rsrc_adouble(smb_fname, flags, mode);
	}

	return fd;
}

/*
 * Here's the deal: for ADOUBLE_META we can do without an fd as we can issue
 * path based xattr calls. For ADOUBLE_RSRC however we need a full-fledged fd
 * for file IO on the ._ file.
 */
static int ad_open(vfs_handle_struct *handle,
		   struct adouble *ad,
		   files_struct *fsp,
		   const struct smb_filename *smb_fname,
		   int flags,
		   mode_t mode)
{
	int fd;

	DBG_DEBUG("Path [%s] type [%s]\n", smb_fname->base_name,
		  ad->ad_type == ADOUBLE_META ? "meta" : "rsrc");

	if (ad->ad_type == ADOUBLE_META) {
		return 0;
	}

	if ((fsp != NULL) && (fsp->fh != NULL) && (fsp->fh->fd != -1)) {
		ad->ad_fd = fsp->fh->fd;
		ad->ad_opened = false;
		return 0;
	}

	fd = ad_open_rsrc(handle, smb_fname, flags, mode);
	if (fd == -1) {
		return -1;
	}
	ad->ad_opened = true;
	ad->ad_fd = fd;

	DBG_DEBUG("Path [%s] type [%s] fd [%d]\n",
		  smb_fname->base_name,
		  ad->ad_type == ADOUBLE_META ? "meta" : "rsrc", fd);

	return 0;
}

static ssize_t ad_read_rsrc_xattr(struct adouble *ad)
{
	int ret;
	SMB_STRUCT_STAT st;

	/* FIXME: direct sys_fstat(), don't have an fsp */
	ret = sys_fstat(ad->ad_fd, &st,
			lp_fake_directory_create_times(
				SNUM(ad->ad_handle->conn)));
	if (ret != 0) {
		return -1;
	}

	ad_setentrylen(ad, ADEID_RFORK, st.st_ex_size);
	return st.st_ex_size;
}

static ssize_t ad_read_rsrc_adouble(struct adouble *ad,
				const struct smb_filename *smb_fname)
{
	SMB_STRUCT_STAT sbuf;
	char *p_ad = NULL;
	size_t size;
	ssize_t len;
	int ret;
	bool ok;

	ret = sys_fstat(ad->ad_fd, &sbuf, lp_fake_directory_create_times(
				SNUM(ad->ad_handle->conn)));
	if (ret != 0) {
		return -1;
	}

	/*
	 * AppleDouble file header content and size, two cases:
	 *
	 * - without xattrs it is exactly AD_DATASZ_DOT_UND (82) bytes large
	 * - with embedded xattrs it can be larger, up to AD_XATTR_MAX_HDR_SIZE
	 *
	 * Read as much as we can up to AD_XATTR_MAX_HDR_SIZE.
	 */
	size = sbuf.st_ex_size;
	if (size > talloc_array_length(ad->ad_data)) {
		if (size > AD_XATTR_MAX_HDR_SIZE) {
			size = AD_XATTR_MAX_HDR_SIZE;
		}
		p_ad = talloc_realloc(ad, ad->ad_data, char, size);
		if (p_ad == NULL) {
			return -1;
		}
		ad->ad_data = p_ad;
	}

	len = sys_pread(ad->ad_fd, ad->ad_data,
			talloc_array_length(ad->ad_data), 0);
	if (len != talloc_array_length(ad->ad_data)) {
		DBG_NOTICE("%s %s: bad size: %zd\n",
			   smb_fname->base_name, strerror(errno), len);
		return -1;
	}

	/* Now parse entries */
	ok = ad_unpack(ad, ADEID_NUM_DOT_UND, sbuf.st_ex_size);
	if (!ok) {
		DBG_ERR("invalid AppleDouble resource %s\n",
			smb_fname->base_name);
		errno = EINVAL;
		return -1;
	}

	if ((ad_getentryoff(ad, ADEID_FINDERI) != ADEDOFF_FINDERI_DOT_UND)
	    || (ad_getentrylen(ad, ADEID_FINDERI) < ADEDLEN_FINDERI)
	    || (ad_getentryoff(ad, ADEID_RFORK)	< ADEDOFF_RFORK_DOT_UND)) {
		DBG_ERR("invalid AppleDouble resource %s\n",
			smb_fname->base_name);
		errno = EINVAL;
		return -1;
	}

	/*
	 * Try to fixup AppleDouble files created by OS X with xattrs
	 * appended to the ADEID_FINDERI entry.
	 */

	ret = ad_convert(ad, smb_fname);
	if (ret != 0) {
		DBG_WARNING("Failed to convert [%s]\n", smb_fname->base_name);
		return len;
	}

	return len;
}

/**
 * Read and parse resource fork, either ._ AppleDouble file or xattr
 **/
static ssize_t ad_read_rsrc(struct adouble *ad,
			const struct smb_filename *smb_fname)
{
	struct fruit_config_data *config = NULL;
	ssize_t len;

	SMB_VFS_HANDLE_GET_DATA(ad->ad_handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		len = ad_read_rsrc_xattr(ad);
	} else {
		len = ad_read_rsrc_adouble(ad, smb_fname);
	}

	return len;
}

/**
 * Read and unpack an AppleDouble metadata xattr or resource
 **/
static ssize_t ad_read(struct adouble *ad, const struct smb_filename *smb_fname)
{
	switch (ad->ad_type) {
	case ADOUBLE_META:
		return ad_read_meta(ad, smb_fname);
	case ADOUBLE_RSRC:
		return ad_read_rsrc(ad, smb_fname);
	default:
		return -1;
	}
}

static int adouble_destructor(struct adouble *ad)
{
	if ((ad->ad_fd != -1) && ad->ad_opened) {
		close(ad->ad_fd);
		ad->ad_fd = -1;
	}
	return 0;
}

/**
 * Allocate a struct adouble without initialiing it
 *
 * The struct is either hang of the fsp extension context or if fsp is
 * NULL from ctx.
 *
 * @param[in] ctx        talloc context
 * @param[in] handle     vfs handle
 * @param[in] type       type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return               adouble handle
 **/
static struct adouble *ad_alloc(TALLOC_CTX *ctx, vfs_handle_struct *handle,
				adouble_type_t type)
{
	int rc = 0;
	size_t adsize = 0;
	struct adouble *ad;
	struct fruit_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return NULL);

	switch (type) {
	case ADOUBLE_META:
		adsize = AD_DATASZ_XATTR;
		break;
	case ADOUBLE_RSRC:
		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			adsize = AD_DATASZ_DOT_UND;
		}
		break;
	default:
		return NULL;
	}

	ad = talloc_zero(ctx, struct adouble);
	if (ad == NULL) {
		rc = -1;
		goto exit;
	}

	if (adsize) {
		ad->ad_data = talloc_zero_array(ad, char, adsize);
		if (ad->ad_data == NULL) {
			rc = -1;
			goto exit;
		}
	}

	ad->ad_handle = handle;
	ad->ad_type = type;
	ad->ad_magic = AD_MAGIC;
	ad->ad_version = AD_VERSION;
	ad->ad_fd = -1;

	talloc_set_destructor(ad, adouble_destructor);

exit:
	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

/**
 * Allocate and initialize a new struct adouble
 *
 * @param[in] ctx        talloc context
 * @param[in] handle     vfs handle
 * @param[in] type       type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return               adouble handle, initialized
 **/
static struct adouble *ad_init(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			       adouble_type_t type)
{
	int rc = 0;
	const struct ad_entry_order  *eid;
	struct adouble *ad = NULL;
	struct fruit_config_data *config;
	time_t t = time(NULL);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return NULL);

	switch (type) {
	case ADOUBLE_META:
		eid = entry_order_meta_xattr;
		break;
	case ADOUBLE_RSRC:
		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			eid = entry_order_dot_und;
		} else {
			eid = entry_order_rsrc_xattr;
		}
		break;
	default:
		return NULL;
	}

	ad = ad_alloc(ctx, handle, type);
	if (ad == NULL) {
		return NULL;
	}

	while (eid->id) {
		ad->ad_eid[eid->id].ade_off = eid->offset;
		ad->ad_eid[eid->id].ade_len = eid->len;
		eid++;
	}

	/* put something sane in the date fields */
	ad_setdate(ad, AD_DATE_CREATE | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_MODIFY | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_ACCESS | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_BACKUP, htonl(AD_DATE_START));

	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

static struct adouble *ad_get_internal(TALLOC_CTX *ctx,
				       vfs_handle_struct *handle,
				       files_struct *fsp,
				       const struct smb_filename *smb_fname,
				       adouble_type_t type)
{
	int rc = 0;
	ssize_t len;
	struct adouble *ad = NULL;
	int mode;

	if (fsp != NULL) {
		smb_fname = fsp->base_fsp->fsp_name;
	}

	DEBUG(10, ("ad_get(%s) called for %s\n",
		   type == ADOUBLE_META ? "meta" : "rsrc",
		   smb_fname->base_name));

	ad = ad_alloc(ctx, handle, type);
	if (ad == NULL) {
		rc = -1;
		goto exit;
	}

	/* Try rw first so we can use the fd in ad_convert() */
	mode = O_RDWR;

	rc = ad_open(handle, ad, fsp, smb_fname, mode, 0);
	if (rc == -1 && ((errno == EROFS) || (errno == EACCES))) {
		mode = O_RDONLY;
		rc = ad_open(handle, ad, fsp, smb_fname, mode, 0);
	}
	if (rc == -1) {
		DBG_DEBUG("ad_open [%s] error [%s]\n",
			  smb_fname->base_name, strerror(errno));
		goto exit;

	}

	len = ad_read(ad, smb_fname);
	if (len == -1) {
		DEBUG(10, ("error reading AppleDouble for %s\n",
			smb_fname->base_name));
		rc = -1;
		goto exit;
	}

exit:
	DEBUG(10, ("ad_get(%s) for %s returning %d\n",
		  type == ADOUBLE_META ? "meta" : "rsrc",
		  smb_fname->base_name, rc));

	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

/**
 * Return AppleDouble data for a file
 *
 * @param[in] ctx      talloc context
 * @param[in] handle   vfs handle
 * @param[in] smb_fname pathname to file or directory
 * @param[in] type     type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return             talloced struct adouble or NULL on error
 **/
static struct adouble *ad_get(TALLOC_CTX *ctx,
			      vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      adouble_type_t type)
{
	return ad_get_internal(ctx, handle, NULL, smb_fname, type);
}

/**
 * Return AppleDouble data for a file
 *
 * @param[in] ctx      talloc context
 * @param[in] handle   vfs handle
 * @param[in] fsp      fsp to use for IO
 * @param[in] type     type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return             talloced struct adouble or NULL on error
 **/
static struct adouble *ad_fget(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			       files_struct *fsp, adouble_type_t type)
{
	return ad_get_internal(ctx, handle, fsp, NULL, type);
}

/**
 * Set AppleDouble metadata on a file or directory
 *
 * @param[in] ad      adouble handle
 *
 * @param[in] smb_fname    pathname to file or directory
 *
 * @return            status code, 0 means success
 **/
static int ad_set(struct adouble *ad, const struct smb_filename *smb_fname)
{
	bool ok;
	int ret;

	DBG_DEBUG("Path [%s]\n", smb_fname->base_name);

	if (ad->ad_type != ADOUBLE_META) {
		DBG_ERR("ad_set on [%s] used with ADOUBLE_RSRC\n",
			smb_fname->base_name);
		return -1;
	}

	ok = ad_pack(ad);
	if (!ok) {
		return -1;
	}

	ret = SMB_VFS_SETXATTR(ad->ad_handle->conn,
			       smb_fname,
			       AFPINFO_EA_NETATALK,
			       ad->ad_data,
			       AD_DATASZ_XATTR, 0);

	DBG_DEBUG("Path [%s] ret [%d]\n", smb_fname->base_name, ret);

	return ret;
}

/**
 * Set AppleDouble metadata on a file or directory
 *
 * @param[in] ad      adouble handle
 * @param[in] fsp     file handle
 *
 * @return            status code, 0 means success
 **/
static int ad_fset(struct adouble *ad, files_struct *fsp)
{
	int rc = -1;
	ssize_t len;
	bool ok;

	DBG_DEBUG("Path [%s]\n", fsp_str_dbg(fsp));

	if ((fsp == NULL)
	    || (fsp->fh == NULL)
	    || (fsp->fh->fd == -1))
	{
		smb_panic("bad fsp");
	}

	ok = ad_pack(ad);
	if (!ok) {
		return -1;
	}

	switch (ad->ad_type) {
	case ADOUBLE_META:
		rc = SMB_VFS_NEXT_SETXATTR(ad->ad_handle,
					   fsp->fsp_name,
					   AFPINFO_EA_NETATALK,
					   ad->ad_data,
					   AD_DATASZ_XATTR, 0);
		break;

	case ADOUBLE_RSRC:
		len = SMB_VFS_NEXT_PWRITE(ad->ad_handle,
					  fsp,
					  ad->ad_data,
					  AD_DATASZ_DOT_UND,
					  0);
		if (len != AD_DATASZ_DOT_UND) {
			DBG_ERR("short write on %s: %zd", fsp_str_dbg(fsp), len);
			return -1;
		}
		rc = 0;
		break;

	default:
		return -1;
	}

	DBG_DEBUG("Path [%s] rc [%d]\n", fsp_str_dbg(fsp), rc);

	return rc;
}

/*****************************************************************************
 * Helper functions
 *****************************************************************************/

static bool is_afpinfo_stream(const struct smb_filename *smb_fname)
{
	if (strncasecmp_m(smb_fname->stream_name,
			  AFPINFO_STREAM_NAME,
			  strlen(AFPINFO_STREAM_NAME)) == 0) {
		return true;
	}
	return false;
}

static bool is_afpresource_stream(const struct smb_filename *smb_fname)
{
	if (strncasecmp_m(smb_fname->stream_name,
			  AFPRESOURCE_STREAM_NAME,
			  strlen(AFPRESOURCE_STREAM_NAME)) == 0) {
		return true;
	}
	return false;
}

/**
 * Test whether stream is an Apple stream, not used atm
 **/
#if 0
static bool is_apple_stream(const struct smb_filename *smb_fname)
{
	if (is_afpinfo_stream(smb_fname)) {
		return true;
	}
	if (is_afpresource_stream(smb_fname)) {
		return true;
	}
	return false;
}
#endif

/**
 * Initialize config struct from our smb.conf config parameters
 **/
static int init_fruit_config(vfs_handle_struct *handle)
{
	struct fruit_config_data *config;
	int enumval;
	const char *tm_size_str = NULL;

	config = talloc_zero(handle->conn, struct fruit_config_data);
	if (!config) {
		DEBUG(1, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Versions up to Samba 4.5.x had a spelling bug in the
	 * fruit:resource option calling lp_parm_enum with
	 * "res*s*ource" (ie two s).
	 *
	 * In Samba 4.6 we accept both the wrong and the correct
	 * spelling, in Samba 4.7 the bad spelling will be removed.
	 */
	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "ressource", fruit_rsrc, FRUIT_RSRC_ADFILE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: resource type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->rsrc = (enum fruit_rsrc)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "resource", fruit_rsrc, enumval);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: resource type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->rsrc = (enum fruit_rsrc)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "metadata", fruit_meta, FRUIT_META_NETATALK);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: metadata type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->meta = (enum fruit_meta)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "locking", fruit_locking, FRUIT_LOCKING_NONE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: locking type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->locking = (enum fruit_locking)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "encoding", fruit_encoding, FRUIT_ENC_PRIVATE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: encoding type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->encoding = (enum fruit_encoding)enumval;

	if (config->rsrc == FRUIT_RSRC_ADFILE) {
		config->veto_appledouble = lp_parm_bool(SNUM(handle->conn),
							FRUIT_PARAM_TYPE_NAME,
							"veto_appledouble",
							true);
	}

	config->use_aapl = lp_parm_bool(
		-1, FRUIT_PARAM_TYPE_NAME, "aapl", true);

	config->time_machine = lp_parm_bool(
		SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME, "time machine", false);

	config->unix_info_enabled = lp_parm_bool(
		-1, FRUIT_PARAM_TYPE_NAME, "nfs_aces", true);

	config->use_copyfile = lp_parm_bool(-1, FRUIT_PARAM_TYPE_NAME,
					   "copyfile", false);

	config->posix_rename = lp_parm_bool(
		SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME, "posix_rename", true);

	config->aapl_zero_file_id =
	    lp_parm_bool(-1, FRUIT_PARAM_TYPE_NAME, "zero_file_id", true);

	config->readdir_attr_rsize = lp_parm_bool(
		SNUM(handle->conn), "readdir_attr", "aapl_rsize", true);

	config->readdir_attr_finder_info = lp_parm_bool(
		SNUM(handle->conn), "readdir_attr", "aapl_finder_info", true);

	config->readdir_attr_max_access = lp_parm_bool(
		SNUM(handle->conn), "readdir_attr", "aapl_max_access", true);

	config->model = lp_parm_const_string(
		-1, FRUIT_PARAM_TYPE_NAME, "model", "MacSamba");

	tm_size_str = lp_parm_const_string(
		SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
		"time machine max size", NULL);
	if (tm_size_str != NULL) {
		config->time_machine_max_size = conv_str_size(tm_size_str);
	}

	config->wipe_intentionally_left_blank_rfork = lp_parm_bool(
		SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
		"wipe_intentionally_left_blank_rfork", false);

	config->delete_empty_adfiles = lp_parm_bool(
		SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
		"delete_empty_adfiles", false);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct fruit_config_data,
				return -1);

	return 0;
}

/**
 * Prepend "._" to a basename
 * Return a new struct smb_filename with stream_name == NULL.
 **/
static int adouble_path(TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname_in,
			struct smb_filename **pp_smb_fname_out)
{
	char *parent;
	const char *base;
	struct smb_filename *smb_fname = cp_smb_filename(ctx,
						smb_fname_in);

	if (smb_fname == NULL) {
		return -1;
	}

	/* We need streamname to be NULL */
	TALLOC_FREE(smb_fname->stream_name);

	/* And we're replacing base_name. */
	TALLOC_FREE(smb_fname->base_name);

	if (!parent_dirname(smb_fname, smb_fname_in->base_name,
				&parent, &base)) {
		TALLOC_FREE(smb_fname);
		return -1;
	}

	smb_fname->base_name = talloc_asprintf(smb_fname,
					"%s/._%s", parent, base);
	if (smb_fname->base_name == NULL) {
		TALLOC_FREE(smb_fname);
		return -1;
	}

	*pp_smb_fname_out = smb_fname;

	return 0;
}

/**
 * Allocate and initialize an AfpInfo struct
 **/
static AfpInfo *afpinfo_new(TALLOC_CTX *ctx)
{
	AfpInfo *ai = talloc_zero(ctx, AfpInfo);
	if (ai == NULL) {
		return NULL;
	}
	ai->afpi_Signature = AFP_Signature;
	ai->afpi_Version = AFP_Version;
	ai->afpi_BackupTime = AD_DATE_START;
	return ai;
}

/**
 * Pack an AfpInfo struct into a buffer
 *
 * Buffer size must be at least AFP_INFO_SIZE
 * Returns size of packed buffer
 **/
static ssize_t afpinfo_pack(const AfpInfo *ai, char *buf)
{
	memset(buf, 0, AFP_INFO_SIZE);

	RSIVAL(buf, 0, ai->afpi_Signature);
	RSIVAL(buf, 4, ai->afpi_Version);
	RSIVAL(buf, 12, ai->afpi_BackupTime);
	memcpy(buf + 16, ai->afpi_FinderInfo, sizeof(ai->afpi_FinderInfo));

	return AFP_INFO_SIZE;
}

/**
 * Unpack a buffer into a AfpInfo structure
 *
 * Buffer size must be at least AFP_INFO_SIZE
 * Returns allocated AfpInfo struct
 **/
static AfpInfo *afpinfo_unpack(TALLOC_CTX *ctx, const void *data)
{
	AfpInfo *ai = talloc_zero(ctx, AfpInfo);
	if (ai == NULL) {
		return NULL;
	}

	ai->afpi_Signature = RIVAL(data, 0);
	ai->afpi_Version = RIVAL(data, 4);
	ai->afpi_BackupTime = RIVAL(data, 12);
	memcpy(ai->afpi_FinderInfo, (const char *)data + 16,
	       sizeof(ai->afpi_FinderInfo));

	if (ai->afpi_Signature != AFP_Signature
	    || ai->afpi_Version != AFP_Version) {
		DEBUG(1, ("Bad AfpInfo signature or version\n"));
		TALLOC_FREE(ai);
	}

	return ai;
}

/**
 * Fake an inode number from the md5 hash of the (xattr) name
 **/
static SMB_INO_T fruit_inode(const SMB_STRUCT_STAT *sbuf, const char *sname)
{
	MD5_CTX ctx;
	unsigned char hash[16];
	SMB_INO_T result;
	char *upper_sname;

	DBG_DEBUG("fruit_inode called for %ju/%ju [%s]\n",
		  (uintmax_t)sbuf->st_ex_dev,
		  (uintmax_t)sbuf->st_ex_ino, sname);

	upper_sname = talloc_strdup_upper(talloc_tos(), sname);
	SMB_ASSERT(upper_sname != NULL);

	MD5Init(&ctx);
	MD5Update(&ctx, (const unsigned char *)&(sbuf->st_ex_dev),
		  sizeof(sbuf->st_ex_dev));
	MD5Update(&ctx, (const unsigned char *)&(sbuf->st_ex_ino),
		  sizeof(sbuf->st_ex_ino));
	MD5Update(&ctx, (unsigned char *)upper_sname,
		  talloc_get_size(upper_sname)-1);
	MD5Final(hash, &ctx);

	TALLOC_FREE(upper_sname);

	/* Hopefully all the variation is in the lower 4 (or 8) bytes! */
	memcpy(&result, hash, sizeof(result));

	DBG_DEBUG("fruit_inode \"%s\": ino=%ju\n",
		  sname, (uintmax_t)result);

	return result;
}

static bool add_fruit_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			     struct stream_struct **streams,
			     const char *name, off_t size,
			     off_t alloc_size)
{
	struct stream_struct *tmp;

	tmp = talloc_realloc(mem_ctx, *streams, struct stream_struct,
			     (*num_streams)+1);
	if (tmp == NULL) {
		return false;
	}

	tmp[*num_streams].name = talloc_asprintf(tmp, "%s:$DATA", name);
	if (tmp[*num_streams].name == NULL) {
		return false;
	}

	tmp[*num_streams].size = size;
	tmp[*num_streams].alloc_size = alloc_size;

	*streams = tmp;
	*num_streams += 1;
	return true;
}

static bool filter_empty_rsrc_stream(unsigned int *num_streams,
				     struct stream_struct **streams)
{
	struct stream_struct *tmp = *streams;
	unsigned int i;

	if (*num_streams == 0) {
		return true;
	}

	for (i = 0; i < *num_streams; i++) {
		if (strequal_m(tmp[i].name, AFPRESOURCE_STREAM)) {
			break;
		}
	}

	if (i == *num_streams) {
		return true;
	}

	if (tmp[i].size > 0) {
		return true;
	}

	TALLOC_FREE(tmp[i].name);
	if (*num_streams - 1 > i) {
		memmove(&tmp[i], &tmp[i+1],
			(*num_streams - i - 1) * sizeof(struct stream_struct));
	}

	*num_streams -= 1;
	return true;
}

static bool del_fruit_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			     struct stream_struct **streams,
			     const char *name)
{
	struct stream_struct *tmp = *streams;
	unsigned int i;

	if (*num_streams == 0) {
		return true;
	}

	for (i = 0; i < *num_streams; i++) {
		if (strequal_m(tmp[i].name, name)) {
			break;
		}
	}

	if (i == *num_streams) {
		return true;
	}

	TALLOC_FREE(tmp[i].name);
	if (*num_streams - 1 > i) {
		memmove(&tmp[i], &tmp[i+1],
			(*num_streams - i - 1) * sizeof(struct stream_struct));
	}

	*num_streams -= 1;
	return true;
}

static bool ad_empty_finderinfo(const struct adouble *ad)
{
	int cmp;
	char emptybuf[ADEDLEN_FINDERI] = {0};
	char *fi = NULL;

	fi = ad_get_entry(ad, ADEID_FINDERI);
	if (fi == NULL) {
		DBG_ERR("Missing FinderInfo in struct adouble [%p]\n", ad);
		return false;
	}

	cmp = memcmp(emptybuf, fi, ADEDLEN_FINDERI);
	return (cmp == 0);
}

static bool ai_empty_finderinfo(const AfpInfo *ai)
{
	int cmp;
	char emptybuf[ADEDLEN_FINDERI] = {0};

	cmp = memcmp(emptybuf, &ai->afpi_FinderInfo[0], ADEDLEN_FINDERI);
	return (cmp == 0);
}

/**
 * Update btime with btime from Netatalk
 **/
static void update_btime(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	uint32_t t;
	struct timespec creation_time = {0};
	struct adouble *ad;
	struct fruit_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return);

	switch (config->meta) {
	case FRUIT_META_STREAM:
		return;
	case FRUIT_META_NETATALK:
		/* Handled below */
		break;
	default:
		DBG_ERR("Unexpected meta config [%d]\n", config->meta);
		return;
	}

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad == NULL) {
		return;
	}
	if (ad_getdate(ad, AD_DATE_UNIX | AD_DATE_CREATE, &t) != 0) {
		TALLOC_FREE(ad);
		return;
	}
	TALLOC_FREE(ad);

	creation_time.tv_sec = convert_uint32_t_to_time_t(t);
	update_stat_ex_create_time(&smb_fname->st, creation_time);

	return;
}

/**
 * Map an access mask to a Netatalk single byte byte range lock
 **/
static off_t access_to_netatalk_brl(enum apple_fork fork_type,
				    uint32_t access_mask)
{
	off_t offset;

	switch (access_mask) {
	case FILE_READ_DATA:
		offset = AD_FILELOCK_OPEN_RD;
		break;

	case FILE_WRITE_DATA:
	case FILE_APPEND_DATA:
		offset = AD_FILELOCK_OPEN_WR;
		break;

	default:
		offset = AD_FILELOCK_OPEN_NONE;
		break;
	}

	if (fork_type == APPLE_FORK_RSRC) {
		if (offset == AD_FILELOCK_OPEN_NONE) {
			offset = AD_FILELOCK_RSRC_OPEN_NONE;
		} else {
			offset += 2;
		}
	}

	return offset;
}

/**
 * Map a deny mode to a Netatalk brl
 **/
static off_t denymode_to_netatalk_brl(enum apple_fork fork_type,
				      uint32_t deny_mode)
{
	off_t offset;

	switch (deny_mode) {
	case DENY_READ:
		offset = AD_FILELOCK_DENY_RD;
		break;

	case DENY_WRITE:
		offset = AD_FILELOCK_DENY_WR;
		break;

	default:
		smb_panic("denymode_to_netatalk_brl: bad deny mode\n");
	}

	if (fork_type == APPLE_FORK_RSRC) {
		offset += 2;
	}

	return offset;
}

/**
 * Call fcntl() with an exclusive F_GETLK request in order to
 * determine if there's an exisiting shared lock
 *
 * @return true if the requested lock was found or any error occurred
 *         false if the lock was not found
 **/
static bool test_netatalk_lock(files_struct *fsp, off_t in_offset)
{
	bool result;
	off_t offset = in_offset;
	off_t len = 1;
	int type = F_WRLCK;
	pid_t pid;

	result = SMB_VFS_GETLOCK(fsp, &offset, &len, &type, &pid);
	if (result == false) {
		return true;
	}

	if (type != F_UNLCK) {
		return true;
	}

	return false;
}

static NTSTATUS fruit_check_access(vfs_handle_struct *handle,
				   files_struct *fsp,
				   uint32_t access_mask,
				   uint32_t deny_mode)
{
	NTSTATUS status = NT_STATUS_OK;
	bool open_for_reading, open_for_writing, deny_read, deny_write;
	off_t off;
	bool have_read = false;
	int flags;

	/* FIXME: hardcoded data fork, add resource fork */
	enum apple_fork fork_type = APPLE_FORK_DATA;

	DEBUG(10, ("fruit_check_access: %s, am: %s/%s, dm: %s/%s\n",
		  fsp_str_dbg(fsp),
		  access_mask & FILE_READ_DATA ? "READ" :"-",
		  access_mask & FILE_WRITE_DATA ? "WRITE" : "-",
		  deny_mode & DENY_READ ? "DENY_READ" : "-",
		  deny_mode & DENY_WRITE ? "DENY_WRITE" : "-"));

	if (fsp->fh->fd == -1) {
		return NT_STATUS_OK;
	}

	flags = fcntl(fsp->fh->fd, F_GETFL);
	if (flags == -1) {
		DBG_ERR("fcntl get flags [%s] fd [%d] failed [%s]\n",
			fsp_str_dbg(fsp), fsp->fh->fd, strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	if (flags & (O_RDONLY|O_RDWR)) {
		/*
		 * Applying fcntl read locks requires an fd opened for
		 * reading. This means we won't be applying locks for
		 * files openend write-only, but what can we do...
		 */
		have_read = true;
	}

	/*
	 * Check read access and deny read mode
	 */
	if ((access_mask & FILE_READ_DATA) || (deny_mode & DENY_READ)) {
		/* Check access */
		open_for_reading = test_netatalk_lock(
			fsp, access_to_netatalk_brl(fork_type, FILE_READ_DATA));

		deny_read = test_netatalk_lock(
			fsp, denymode_to_netatalk_brl(fork_type, DENY_READ));

		DEBUG(10, ("read: %s, deny_write: %s\n",
			  open_for_reading == true ? "yes" : "no",
			  deny_read == true ? "yes" : "no"));

		if (((access_mask & FILE_READ_DATA) && deny_read)
		    || ((deny_mode & DENY_READ) && open_for_reading)) {
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* Set locks */
		if ((access_mask & FILE_READ_DATA) && have_read) {
			struct byte_range_lock *br_lck = NULL;

			off = access_to_netatalk_brl(fork_type, FILE_READ_DATA);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			TALLOC_FREE(br_lck);

			if (!NT_STATUS_IS_OK(status))  {
				return status;
			}
		}

		if ((deny_mode & DENY_READ) && have_read) {
			struct byte_range_lock *br_lck = NULL;

			off = denymode_to_netatalk_brl(fork_type, DENY_READ);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			TALLOC_FREE(br_lck);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	/*
	 * Check write access and deny write mode
	 */
	if ((access_mask & FILE_WRITE_DATA) || (deny_mode & DENY_WRITE)) {
		/* Check access */
		open_for_writing = test_netatalk_lock(
			fsp, access_to_netatalk_brl(fork_type, FILE_WRITE_DATA));

		deny_write = test_netatalk_lock(
			fsp, denymode_to_netatalk_brl(fork_type, DENY_WRITE));

		DEBUG(10, ("write: %s, deny_write: %s\n",
			  open_for_writing == true ? "yes" : "no",
			  deny_write == true ? "yes" : "no"));

		if (((access_mask & FILE_WRITE_DATA) && deny_write)
		    || ((deny_mode & DENY_WRITE) && open_for_writing)) {
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* Set locks */
		if ((access_mask & FILE_WRITE_DATA) && have_read) {
			struct byte_range_lock *br_lck = NULL;

			off = access_to_netatalk_brl(fork_type, FILE_WRITE_DATA);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			TALLOC_FREE(br_lck);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
		if ((deny_mode & DENY_WRITE) && have_read) {
			struct byte_range_lock *br_lck = NULL;

			off = denymode_to_netatalk_brl(fork_type, DENY_WRITE);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			TALLOC_FREE(br_lck);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	return status;
}

static NTSTATUS check_aapl(vfs_handle_struct *handle,
			   struct smb_request *req,
			   const struct smb2_create_blobs *in_context_blobs,
			   struct smb2_create_blobs *out_context_blobs)
{
	struct fruit_config_data *config;
	NTSTATUS status;
	struct smb2_create_blob *aapl = NULL;
	uint32_t cmd;
	bool ok;
	uint8_t p[16];
	DATA_BLOB blob = data_blob_talloc(req, NULL, 0);
	uint64_t req_bitmap, client_caps;
	uint64_t server_caps = SMB2_CRTCTX_AAPL_UNIX_BASED;
	smb_ucs2_t *model;
	size_t modellen;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	if (!config->use_aapl
	    || in_context_blobs == NULL
	    || out_context_blobs == NULL) {
		return NT_STATUS_OK;
	}

	aapl = smb2_create_blob_find(in_context_blobs,
				     SMB2_CREATE_TAG_AAPL);
	if (aapl == NULL) {
		return NT_STATUS_OK;
	}

	if (aapl->data.length != 24) {
		DEBUG(1, ("unexpected AAPL ctxt length: %ju\n",
			  (uintmax_t)aapl->data.length));
		return NT_STATUS_INVALID_PARAMETER;
	}

	cmd = IVAL(aapl->data.data, 0);
	if (cmd != SMB2_CRTCTX_AAPL_SERVER_QUERY) {
		DEBUG(1, ("unsupported AAPL cmd: %d\n", cmd));
		return NT_STATUS_INVALID_PARAMETER;
	}

	req_bitmap = BVAL(aapl->data.data, 8);
	client_caps = BVAL(aapl->data.data, 16);

	SIVAL(p, 0, SMB2_CRTCTX_AAPL_SERVER_QUERY);
	SIVAL(p, 4, 0);
	SBVAL(p, 8, req_bitmap);
	ok = data_blob_append(req, &blob, p, 16);
	if (!ok) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (req_bitmap & SMB2_CRTCTX_AAPL_SERVER_CAPS) {
		if ((client_caps & SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR) &&
		    (handle->conn->tcon->compat->fs_capabilities & FILE_NAMED_STREAMS)) {
			server_caps |= SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR;
			config->readdir_attr_enabled = true;
		}

		if (config->use_copyfile) {
			server_caps |= SMB2_CRTCTX_AAPL_SUPPORTS_OSX_COPYFILE;
			config->copyfile_enabled = true;
		}

		/*
		 * The client doesn't set the flag, so we can't check
		 * for it and just set it unconditionally
		 */
		if (config->unix_info_enabled) {
			server_caps |= SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE;
		}

		SBVAL(p, 0, server_caps);
		ok = data_blob_append(req, &blob, p, 8);
		if (!ok) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (req_bitmap & SMB2_CRTCTX_AAPL_VOLUME_CAPS) {
		int val = lp_case_sensitive(SNUM(handle->conn->tcon->compat));
		uint64_t caps = 0;

		switch (val) {
		case Auto:
			break;

		case True:
			caps |= SMB2_CRTCTX_AAPL_CASE_SENSITIVE;
			break;

		default:
			break;
		}

		if (config->time_machine) {
			caps |= SMB2_CRTCTX_AAPL_FULL_SYNC;
		}

		SBVAL(p, 0, caps);

		ok = data_blob_append(req, &blob, p, 8);
		if (!ok) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (req_bitmap & SMB2_CRTCTX_AAPL_MODEL_INFO) {
		ok = convert_string_talloc(req,
					   CH_UNIX, CH_UTF16LE,
					   config->model, strlen(config->model),
					   &model, &modellen);
		if (!ok) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		SIVAL(p, 0, 0);
		SIVAL(p + 4, 0, modellen);
		ok = data_blob_append(req, &blob, p, 8);
		if (!ok) {
			talloc_free(model);
			return NT_STATUS_UNSUCCESSFUL;
		}

		ok = data_blob_append(req, &blob, model, modellen);
		talloc_free(model);
		if (!ok) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	status = smb2_create_blob_add(out_context_blobs,
				      out_context_blobs,
				      SMB2_CREATE_TAG_AAPL,
				      blob);
	if (NT_STATUS_IS_OK(status)) {
		global_fruit_config.nego_aapl = true;
		if (config->aapl_zero_file_id) {
			aapl_force_zero_file_id(handle->conn->sconn);
		}
	}

	return status;
}

static bool readdir_attr_meta_finderi_stream(
	struct vfs_handle_struct *handle,
	const struct smb_filename *smb_fname,
	AfpInfo *ai)
{
	struct smb_filename *stream_name = NULL;
	files_struct *fsp = NULL;
	ssize_t nread;
	NTSTATUS status;
	int ret;
	bool ok;
	uint8_t buf[AFP_INFO_SIZE];

	stream_name = synthetic_smb_fname(talloc_tos(),
					  smb_fname->base_name,
					  AFPINFO_STREAM_NAME,
					  NULL, smb_fname->flags);
	if (stream_name == NULL) {
		return false;
	}

	ret = SMB_VFS_STAT(handle->conn, stream_name);
	if (ret != 0) {
		return false;
	}

	status = SMB_VFS_CREATE_FILE(
		handle->conn,                           /* conn */
		NULL,                                   /* req */
		0,                                      /* root_dir_fid */
		stream_name,				/* fname */
		FILE_READ_DATA,                         /* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |   /* share_access */
			FILE_SHARE_DELETE),
		FILE_OPEN,                              /* create_disposition*/
		0,                                      /* create_options */
		0,                                      /* file_attributes */
		INTERNAL_OPEN_ONLY,                     /* oplock_request */
		NULL,					/* lease */
                0,                                      /* allocation_size */
		0,                                      /* private_flags */
		NULL,                                   /* sd */
		NULL,                                   /* ea_list */
		&fsp,                                   /* result */
		NULL,                                   /* pinfo */
		NULL, NULL);				/* create context */

	TALLOC_FREE(stream_name);

	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	nread = SMB_VFS_PREAD(fsp, &buf[0], AFP_INFO_SIZE, 0);
	if (nread != AFP_INFO_SIZE) {
		DBG_ERR("short read [%s] [%zd/%d]\n",
			smb_fname_str_dbg(stream_name), nread, AFP_INFO_SIZE);
		ok = false;
		goto fail;
	}

	memcpy(&ai->afpi_FinderInfo[0], &buf[AFP_OFF_FinderInfo],
	       AFP_FinderSize);

	ok = true;

fail:
	if (fsp != NULL) {
		close_file(NULL, fsp, NORMAL_CLOSE);
	}

	return ok;
}

static bool readdir_attr_meta_finderi_netatalk(
	struct vfs_handle_struct *handle,
	const struct smb_filename *smb_fname,
	AfpInfo *ai)
{
	struct adouble *ad = NULL;
	char *p = NULL;

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad == NULL) {
		return false;
	}

	p = ad_get_entry(ad, ADEID_FINDERI);
	if (p == NULL) {
		DBG_ERR("No ADEID_FINDERI for [%s]\n", smb_fname->base_name);
		TALLOC_FREE(ad);
		return false;
	}

	memcpy(&ai->afpi_FinderInfo[0], p, AFP_FinderSize);
	TALLOC_FREE(ad);
	return true;
}

static bool readdir_attr_meta_finderi(struct vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      struct readdir_attr_data *attr_data)
{
	struct fruit_config_data *config = NULL;
	uint32_t date_added;
	AfpInfo ai = {0};
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return false);

	switch (config->meta) {
	case FRUIT_META_NETATALK:
		ok = readdir_attr_meta_finderi_netatalk(
			handle, smb_fname, &ai);
		break;

	case FRUIT_META_STREAM:
		ok = readdir_attr_meta_finderi_stream(
			handle, smb_fname, &ai);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", config->meta);
		return false;
	}

	if (!ok) {
		/* Don't bother with errors, it's likely ENOENT */
		return true;
	}

	if (S_ISREG(smb_fname->st.st_ex_mode)) {
		/* finder_type */
		memcpy(&attr_data->attr_data.aapl.finder_info[0],
		       &ai.afpi_FinderInfo[0], 4);

		/* finder_creator */
		memcpy(&attr_data->attr_data.aapl.finder_info[0] + 4,
		       &ai.afpi_FinderInfo[4], 4);
	}

	/* finder_flags */
	memcpy(&attr_data->attr_data.aapl.finder_info[0] + 8,
	       &ai.afpi_FinderInfo[8], 2);

	/* finder_ext_flags */
	memcpy(&attr_data->attr_data.aapl.finder_info[0] + 10,
	       &ai.afpi_FinderInfo[24], 2);

	/* creation date */
	date_added = convert_time_t_to_uint32_t(
		smb_fname->st.st_ex_btime.tv_sec - AD_DATE_DELTA);

	RSIVAL(&attr_data->attr_data.aapl.finder_info[0], 12, date_added);

	return true;
}

static uint64_t readdir_attr_rfork_size_adouble(
	struct vfs_handle_struct *handle,
	const struct smb_filename *smb_fname)
{
	struct adouble *ad = NULL;
	uint64_t rfork_size;

	ad = ad_get(talloc_tos(), handle, smb_fname,
		    ADOUBLE_RSRC);
	if (ad == NULL) {
		return 0;
	}

	rfork_size = ad_getentrylen(ad, ADEID_RFORK);
	TALLOC_FREE(ad);

	return rfork_size;
}

static uint64_t readdir_attr_rfork_size_stream(
	struct vfs_handle_struct *handle,
	const struct smb_filename *smb_fname)
{
	struct smb_filename *stream_name = NULL;
	int ret;
	uint64_t rfork_size;

	stream_name = synthetic_smb_fname(talloc_tos(),
					  smb_fname->base_name,
					  AFPRESOURCE_STREAM_NAME,
					  NULL, 0);
	if (stream_name == NULL) {
		return 0;
	}

	ret = SMB_VFS_STAT(handle->conn, stream_name);
	if (ret != 0) {
		TALLOC_FREE(stream_name);
		return 0;
	}

	rfork_size = stream_name->st.st_ex_size;
	TALLOC_FREE(stream_name);

	return rfork_size;
}

static uint64_t readdir_attr_rfork_size(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	struct fruit_config_data *config = NULL;
	uint64_t rfork_size;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return 0);

	switch (config->rsrc) {
	case FRUIT_RSRC_ADFILE:
	case FRUIT_RSRC_XATTR:
		rfork_size = readdir_attr_rfork_size_adouble(handle,
							     smb_fname);
		break;

	case FRUIT_META_STREAM:
		rfork_size = readdir_attr_rfork_size_stream(handle,
							    smb_fname);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", config->rsrc);
		rfork_size = 0;
		break;
	}

	return rfork_size;
}

static NTSTATUS readdir_attr_macmeta(struct vfs_handle_struct *handle,
				     const struct smb_filename *smb_fname,
				     struct readdir_attr_data *attr_data)
{
	NTSTATUS status = NT_STATUS_OK;
	struct fruit_config_data *config = NULL;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);


	/* Ensure we return a default value in the creation_date field */
	RSIVAL(&attr_data->attr_data.aapl.finder_info, 12, AD_DATE_START);

	/*
	 * Resource fork length
	 */

	if (config->readdir_attr_rsize) {
		uint64_t rfork_size;

		rfork_size = readdir_attr_rfork_size(handle, smb_fname);
		attr_data->attr_data.aapl.rfork_size = rfork_size;
	}

	/*
	 * FinderInfo
	 */

	if (config->readdir_attr_finder_info) {
		ok = readdir_attr_meta_finderi(handle, smb_fname, attr_data);
		if (!ok) {
			status = NT_STATUS_INTERNAL_ERROR;
		}
	}

	return status;
}

static NTSTATUS remove_virtual_nfs_aces(struct security_descriptor *psd)
{
	NTSTATUS status;
	uint32_t i;

	if (psd->dacl == NULL) {
		return NT_STATUS_OK;
	}

	for (i = 0; i < psd->dacl->num_aces; i++) {
		/* MS NFS style mode/uid/gid */
		int cmp = dom_sid_compare_domain(
				&global_sid_Unix_NFS,
				&psd->dacl->aces[i].trustee);
		if (cmp != 0) {
			/* Normal ACE entry. */
			continue;
		}

		/*
		 * security_descriptor_dacl_del()
		 * *must* return NT_STATUS_OK as we know
		 * we have something to remove.
		 */

		status = security_descriptor_dacl_del(psd,
				&psd->dacl->aces[i].trustee);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to remove MS NFS style ACE: %s\n",
				nt_errstr(status));
			return status;
		}

		/*
		 * security_descriptor_dacl_del() may delete more
		 * then one entry subsequent to this one if the
		 * SID matches, but we only need to ensure that
		 * we stay looking at the same element in the array.
		 */
		i--;
	}
	return NT_STATUS_OK;
}

/* Search MS NFS style ACE with UNIX mode */
static NTSTATUS check_ms_nfs(vfs_handle_struct *handle,
			     files_struct *fsp,
			     struct security_descriptor *psd,
			     mode_t *pmode,
			     bool *pdo_chmod)
{
	uint32_t i;
	struct fruit_config_data *config = NULL;

	*pdo_chmod = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	if (!global_fruit_config.nego_aapl) {
		return NT_STATUS_OK;
	}
	if (psd->dacl == NULL || !config->unix_info_enabled) {
		return NT_STATUS_OK;
	}

	for (i = 0; i < psd->dacl->num_aces; i++) {
		if (dom_sid_compare_domain(
			    &global_sid_Unix_NFS_Mode,
			    &psd->dacl->aces[i].trustee) == 0) {
			*pmode = (mode_t)psd->dacl->aces[i].trustee.sub_auths[2];
			*pmode &= (S_IRWXU | S_IRWXG | S_IRWXO);
			*pdo_chmod = true;

			DEBUG(10, ("MS NFS chmod request %s, %04o\n",
				   fsp_str_dbg(fsp), (unsigned)(*pmode)));
			break;
		}
	}

	/*
	 * Remove any incoming virtual ACE entries generated by
	 * fruit_fget_nt_acl().
	 */

	return remove_virtual_nfs_aces(psd);
}

/****************************************************************************
 * VFS ops
 ****************************************************************************/

static int fruit_connect(vfs_handle_struct *handle,
			 const char *service,
			 const char *user)
{
	int rc;
	char *list = NULL, *newlist = NULL;
	struct fruit_config_data *config;

	DEBUG(10, ("fruit_connect\n"));

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc < 0) {
		return rc;
	}

	rc = init_fruit_config(handle);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->veto_appledouble) {
		list = lp_veto_files(talloc_tos(), SNUM(handle->conn));

		if (list) {
			if (strstr(list, "/" ADOUBLE_NAME_PREFIX "*/") == NULL) {
				newlist = talloc_asprintf(
					list,
					"%s/" ADOUBLE_NAME_PREFIX "*/",
					list);
				lp_do_parameter(SNUM(handle->conn),
						"veto files",
						newlist);
			}
		} else {
			lp_do_parameter(SNUM(handle->conn),
					"veto files",
					"/" ADOUBLE_NAME_PREFIX "*/");
		}

		TALLOC_FREE(list);
	}

	if (config->encoding == FRUIT_ENC_NATIVE) {
		lp_do_parameter(SNUM(handle->conn),
				"catia:mappings",
				fruit_catia_maps);
	}

	if (config->time_machine) {
		DBG_NOTICE("Enabling durable handles for Time Machine "
			   "support on [%s]\n", service);
		lp_do_parameter(SNUM(handle->conn), "durable handles", "yes");
		lp_do_parameter(SNUM(handle->conn), "kernel oplocks", "no");
		lp_do_parameter(SNUM(handle->conn), "kernel share modes", "no");
		if (!lp_strict_sync(SNUM(handle->conn))) {
			DBG_WARNING("Time Machine without strict sync is not "
				    "recommended!\n");
		}
		lp_do_parameter(SNUM(handle->conn), "posix locking", "no");
	}

	return rc;
}

static int fruit_fake_fd(void)
{
	int pipe_fds[2];
	int fd;
	int ret;

	/*
	 * Return a valid fd, but ensure any attempt to use it returns
	 * an error (EPIPE). Once we get a write on the handle, we open
	 * the real fd.
	 */
	ret = pipe(pipe_fds);
	if (ret != 0) {
		return -1;
	}
	fd = pipe_fds[0];
	close(pipe_fds[1]);

	return fd;
}

static int fruit_open_meta_stream(vfs_handle_struct *handle,
				  struct smb_filename *smb_fname,
				  files_struct *fsp,
				  int flags,
				  mode_t mode)
{
	struct fruit_config_data *config = NULL;
	struct fio *fio = NULL;
	int open_flags = flags & ~O_CREAT;
	int fd;

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	fio = VFS_ADD_FSP_EXTENSION(handle, fsp, struct fio, NULL);
	fio->type = ADOUBLE_META;
	fio->config = config;

	fd = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, open_flags, mode);
	if (fd != -1) {
		return fd;
	}

	if (!(flags & O_CREAT)) {
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
		return -1;
	}

	fd = fruit_fake_fd();
	if (fd == -1) {
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
		return -1;
	}

	fio->fake_fd = true;
	fio->flags = flags;
	fio->mode = mode;

	return fd;
}

static int fruit_open_meta_netatalk(vfs_handle_struct *handle,
				    struct smb_filename *smb_fname,
				    files_struct *fsp,
				    int flags,
				    mode_t mode)
{
	struct fruit_config_data *config = NULL;
	struct fio *fio = NULL;
	struct adouble *ad = NULL;
	bool meta_exists = false;
	int fd;

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad != NULL) {
		meta_exists = true;
	}

	TALLOC_FREE(ad);

	if (!meta_exists && !(flags & O_CREAT)) {
		errno = ENOENT;
		return -1;
	}

	fd = fruit_fake_fd();
	if (fd == -1) {
		return -1;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	fio = VFS_ADD_FSP_EXTENSION(handle, fsp, struct fio, NULL);
	fio->type = ADOUBLE_META;
	fio->config = config;
	fio->fake_fd = true;
	fio->flags = flags;
	fio->mode = mode;

	return fd;
}

static int fruit_open_meta(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   files_struct *fsp, int flags, mode_t mode)
{
	int fd;
	struct fruit_config_data *config = NULL;

	DBG_DEBUG("path [%s]\n", smb_fname_str_dbg(smb_fname));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->meta) {
	case FRUIT_META_STREAM:
		fd = fruit_open_meta_stream(handle, smb_fname,
					    fsp, flags, mode);
		break;

	case FRUIT_META_NETATALK:
		fd = fruit_open_meta_netatalk(handle, smb_fname,
					      fsp, flags, mode);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", config->meta);
		return -1;
	}

	DBG_DEBUG("path [%s] fd [%d]\n", smb_fname_str_dbg(smb_fname), fd);

	return fd;
}

static int fruit_open_rsrc_adouble(vfs_handle_struct *handle,
				   struct smb_filename *smb_fname,
				   files_struct *fsp,
				   int flags,
				   mode_t mode)
{
	int rc = 0;
	struct adouble *ad = NULL;
	struct smb_filename *smb_fname_base = NULL;
	struct fruit_config_data *config = NULL;
	int hostfd = -1;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if ((!(flags & O_CREAT)) &&
	    S_ISDIR(fsp->base_fsp->fsp_name->st.st_ex_mode))
	{
		/* sorry, but directories don't habe a resource fork */
		rc = -1;
		goto exit;
	}

	rc = adouble_path(talloc_tos(), smb_fname, &smb_fname_base);
	if (rc != 0) {
		goto exit;
	}

	/* We always need read/write access for the metadata header too */
	flags &= ~(O_RDONLY | O_WRONLY);
	flags |= O_RDWR;

	hostfd = SMB_VFS_NEXT_OPEN(handle, smb_fname_base, fsp,
				   flags, mode);
	if (hostfd == -1) {
		rc = -1;
		goto exit;
	}

	if (flags & (O_CREAT | O_TRUNC)) {
		ad = ad_init(fsp, handle, ADOUBLE_RSRC);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}

		fsp->fh->fd = hostfd;

		rc = ad_fset(ad, fsp);
		fsp->fh->fd = -1;
		if (rc != 0) {
			rc = -1;
			goto exit;
		}
		TALLOC_FREE(ad);
	}

exit:

	TALLOC_FREE(smb_fname_base);

	DEBUG(10, ("fruit_open resource fork: rc=%d, fd=%d\n", rc, hostfd));
	if (rc != 0) {
		int saved_errno = errno;
		if (hostfd >= 0) {
			/*
			 * BUGBUGBUG -- we would need to call
			 * fd_close_posix here, but we don't have a
			 * full fsp yet
			 */
			fsp->fh->fd = hostfd;
			SMB_VFS_CLOSE(fsp);
		}
		hostfd = -1;
		errno = saved_errno;
	}
	return hostfd;
}

static int fruit_open_rsrc_xattr(vfs_handle_struct *handle,
				 struct smb_filename *smb_fname,
				 files_struct *fsp,
				 int flags,
				 mode_t mode)
{
#ifdef HAVE_ATTROPEN
	int fd = -1;

	fd = attropen(smb_fname->base_name,
		      AFPRESOURCE_EA_NETATALK,
		      flags,
		      mode);
	if (fd == -1) {
		return -1;
	}

	return fd;

#else
	errno = ENOSYS;
	return -1;
#endif
}

static int fruit_open_rsrc(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   files_struct *fsp, int flags, mode_t mode)
{
	int fd;
	struct fruit_config_data *config = NULL;
	struct fio *fio = NULL;

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->rsrc) {
	case FRUIT_RSRC_STREAM:
		fd = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
		break;

	case FRUIT_RSRC_ADFILE:
		fd = fruit_open_rsrc_adouble(handle, smb_fname,
					     fsp, flags, mode);
		break;

	case FRUIT_RSRC_XATTR:
		fd = fruit_open_rsrc_xattr(handle, smb_fname,
					   fsp, flags, mode);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", config->rsrc);
		return -1;
	}

	DBG_DEBUG("Path [%s] fd [%d]\n", smb_fname_str_dbg(smb_fname), fd);

	if (fd == -1) {
		return -1;
	}

	fio = VFS_ADD_FSP_EXTENSION(handle, fsp, struct fio, NULL);
	fio->type = ADOUBLE_RSRC;
	fio->config = config;

	return fd;
}

static int fruit_open(vfs_handle_struct *handle,
                      struct smb_filename *smb_fname,
                      files_struct *fsp, int flags, mode_t mode)
{
	int fd;

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	if (!is_ntfs_stream_smb_fname(smb_fname)) {
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	if (is_afpinfo_stream(smb_fname)) {
		fd = fruit_open_meta(handle, smb_fname, fsp, flags, mode);
	} else if (is_afpresource_stream(smb_fname)) {
		fd = fruit_open_rsrc(handle, smb_fname, fsp, flags, mode);
	} else {
		fd = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	DBG_DEBUG("Path [%s] fd [%d]\n", smb_fname_str_dbg(smb_fname), fd);

	return fd;
}

static int fruit_rename(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_src,
			const struct smb_filename *smb_fname_dst)
{
	int rc = -1;
	struct fruit_config_data *config = NULL;
	struct smb_filename *src_adp_smb_fname = NULL;
	struct smb_filename *dst_adp_smb_fname = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (!VALID_STAT(smb_fname_src->st)) {
		DBG_ERR("Need valid stat for [%s]\n",
			smb_fname_str_dbg(smb_fname_src));
		return -1;
	}

	rc = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
	if (rc != 0) {
		return -1;
	}

	if ((config->rsrc != FRUIT_RSRC_ADFILE) ||
	    (!S_ISREG(smb_fname_src->st.st_ex_mode)))
	{
		return 0;
	}

	rc = adouble_path(talloc_tos(), smb_fname_src, &src_adp_smb_fname);
	if (rc != 0) {
		goto done;
	}

	rc = adouble_path(talloc_tos(), smb_fname_dst, &dst_adp_smb_fname);
	if (rc != 0) {
		goto done;
	}

	DBG_DEBUG("%s -> %s\n",
		  smb_fname_str_dbg(src_adp_smb_fname),
		  smb_fname_str_dbg(dst_adp_smb_fname));

	rc = SMB_VFS_NEXT_RENAME(handle, src_adp_smb_fname, dst_adp_smb_fname);
	if (errno == ENOENT) {
		rc = 0;
	}

done:
	TALLOC_FREE(src_adp_smb_fname);
	TALLOC_FREE(dst_adp_smb_fname);
	return rc;
}

static int fruit_unlink_meta_stream(vfs_handle_struct *handle,
				    const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
}

static int fruit_unlink_meta_netatalk(vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname)
{
	return SMB_VFS_REMOVEXATTR(handle->conn,
				   smb_fname,
				   AFPINFO_EA_NETATALK);
}

static int fruit_unlink_meta(vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname)
{
	struct fruit_config_data *config = NULL;
	int rc;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->meta) {
	case FRUIT_META_STREAM:
		rc = fruit_unlink_meta_stream(handle, smb_fname);
		break;

	case FRUIT_META_NETATALK:
		rc = fruit_unlink_meta_netatalk(handle, smb_fname);
		break;

	default:
		DBG_ERR("Unsupported meta config [%d]\n", config->meta);
		return -1;
	}

	return rc;
}

static int fruit_unlink_rsrc_stream(vfs_handle_struct *handle,
				    const struct smb_filename *smb_fname,
				    bool force_unlink)
{
	int ret;

	if (!force_unlink) {
		struct smb_filename *smb_fname_cp = NULL;
		off_t size;

		smb_fname_cp = cp_smb_filename(talloc_tos(), smb_fname);
		if (smb_fname_cp == NULL) {
			return -1;
		}

		/*
		 * 0 byte resource fork streams are not listed by
		 * vfs_streaminfo, as a result stream cleanup/deletion of file
		 * deletion doesn't remove the resourcefork stream.
		 */

		ret = SMB_VFS_NEXT_STAT(handle, smb_fname_cp);
		if (ret != 0) {
			TALLOC_FREE(smb_fname_cp);
			DBG_ERR("stat [%s] failed [%s]\n",
				smb_fname_str_dbg(smb_fname_cp), strerror(errno));
			return -1;
		}

		size = smb_fname_cp->st.st_ex_size;
		TALLOC_FREE(smb_fname_cp);

		if (size > 0) {
			/* OS X ignores resource fork stream delete requests */
			return 0;
		}
	}

	ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	if ((ret != 0) && (errno == ENOENT) && force_unlink) {
		ret = 0;
	}

	return ret;
}

static int fruit_unlink_rsrc_adouble(vfs_handle_struct *handle,
				     const struct smb_filename *smb_fname,
				     bool force_unlink)
{
	int rc;
	struct adouble *ad = NULL;
	struct smb_filename *adp_smb_fname = NULL;

	if (!force_unlink) {
		ad = ad_get(talloc_tos(), handle, smb_fname,
			    ADOUBLE_RSRC);
		if (ad == NULL) {
			errno = ENOENT;
			return -1;
		}


		/*
		 * 0 byte resource fork streams are not listed by
		 * vfs_streaminfo, as a result stream cleanup/deletion of file
		 * deletion doesn't remove the resourcefork stream.
		 */

		if (ad_getentrylen(ad, ADEID_RFORK) > 0) {
			/* OS X ignores resource fork stream delete requests */
			TALLOC_FREE(ad);
			return 0;
		}

		TALLOC_FREE(ad);
	}

	rc = adouble_path(talloc_tos(), smb_fname, &adp_smb_fname);
	if (rc != 0) {
		return -1;
	}

	rc = SMB_VFS_NEXT_UNLINK(handle, adp_smb_fname);
	TALLOC_FREE(adp_smb_fname);
	if ((rc != 0) && (errno == ENOENT) && force_unlink) {
		rc = 0;
	}

	return rc;
}

static int fruit_unlink_rsrc_xattr(vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   bool force_unlink)
{
	/*
	 * OS X ignores resource fork stream delete requests, so nothing to do
	 * here. Removing the file will remove the xattr anyway, so we don't
	 * have to take care of removing 0 byte resource forks that could be
	 * left behind.
	 */
	return 0;
}

static int fruit_unlink_rsrc(vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname,
			     bool force_unlink)
{
	struct fruit_config_data *config = NULL;
	int rc;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->rsrc) {
	case FRUIT_RSRC_STREAM:
		rc = fruit_unlink_rsrc_stream(handle, smb_fname, force_unlink);
		break;

	case FRUIT_RSRC_ADFILE:
		rc = fruit_unlink_rsrc_adouble(handle, smb_fname, force_unlink);
		break;

	case FRUIT_RSRC_XATTR:
		rc = fruit_unlink_rsrc_xattr(handle, smb_fname, force_unlink);
		break;

	default:
		DBG_ERR("Unsupported rsrc config [%d]\n", config->rsrc);
		return -1;
	}

	return rc;
}

static int fruit_unlink(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int rc;
	struct fruit_config_data *config = NULL;
	struct smb_filename *rsrc_smb_fname = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (is_afpinfo_stream(smb_fname)) {
		return fruit_unlink_meta(handle, smb_fname);
	} else if (is_afpresource_stream(smb_fname)) {
		return fruit_unlink_rsrc(handle, smb_fname, false);
	} if (is_ntfs_stream_smb_fname(smb_fname)) {
		return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	}

	/*
	 * A request to delete the base file. Because 0 byte resource
	 * fork streams are not listed by fruit_streaminfo,
	 * delete_all_streams() can't remove 0 byte resource fork
	 * streams, so we have to cleanup this here.
	 */
	rsrc_smb_fname = synthetic_smb_fname(talloc_tos(),
					     smb_fname->base_name,
					     AFPRESOURCE_STREAM_NAME,
					     NULL,
					     smb_fname->flags);
	if (rsrc_smb_fname == NULL) {
		return -1;
	}

	rc = fruit_unlink_rsrc(handle, rsrc_smb_fname, true);
	if ((rc != 0) && (errno != ENOENT)) {
		DBG_ERR("Forced unlink of [%s] failed [%s]\n",
			smb_fname_str_dbg(rsrc_smb_fname), strerror(errno));
		TALLOC_FREE(rsrc_smb_fname);
		return -1;
	}
	TALLOC_FREE(rsrc_smb_fname);

	return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
}

static int fruit_chmod(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       mode_t mode)
{
	int rc = -1;
	struct fruit_config_data *config = NULL;
	struct smb_filename *smb_fname_adp = NULL;

	rc = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc != FRUIT_RSRC_ADFILE) {
		return 0;
	}

	if (!VALID_STAT(smb_fname->st)) {
		return 0;
	}

	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
		return 0;
	}

	rc = adouble_path(talloc_tos(), smb_fname, &smb_fname_adp);
	if (rc != 0) {
		return -1;
	}

	DEBUG(10, ("fruit_chmod: %s\n", smb_fname_adp->base_name));

	rc = SMB_VFS_NEXT_CHMOD(handle, smb_fname_adp, mode);
	if (errno == ENOENT) {
		rc = 0;
	}

	TALLOC_FREE(smb_fname_adp);
	return rc;
}

static int fruit_chown(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       uid_t uid,
		       gid_t gid)
{
	int rc = -1;
	struct fruit_config_data *config = NULL;
	struct smb_filename *adp_smb_fname = NULL;

	rc = SMB_VFS_NEXT_CHOWN(handle, smb_fname, uid, gid);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc != FRUIT_RSRC_ADFILE) {
		return 0;
	}

	if (!VALID_STAT(smb_fname->st)) {
		return 0;
	}

	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
		return 0;
	}

	rc = adouble_path(talloc_tos(), smb_fname, &adp_smb_fname);
	if (rc != 0) {
		goto done;
	}

	DEBUG(10, ("fruit_chown: %s\n", adp_smb_fname->base_name));

	rc = SMB_VFS_NEXT_CHOWN(handle, adp_smb_fname, uid, gid);
	if (errno == ENOENT) {
		rc = 0;
	}

 done:
	TALLOC_FREE(adp_smb_fname);
	return rc;
}

static int fruit_rmdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	DIR *dh = NULL;
	struct dirent *de;
	struct fruit_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc != FRUIT_RSRC_ADFILE) {
		goto exit_rmdir;
	}

	/*
	 * Due to there is no way to change bDeleteVetoFiles variable
	 * from this module, need to clean up ourselves
	 */

	dh = SMB_VFS_OPENDIR(handle->conn, smb_fname, NULL, 0);
	if (dh == NULL) {
		goto exit_rmdir;
	}

	while ((de = SMB_VFS_READDIR(handle->conn, dh, NULL)) != NULL) {
		int match;
		struct adouble *ad = NULL;
		char *p = NULL;
		struct smb_filename *ad_smb_fname = NULL;
		int ret;

		match = strncmp(de->d_name,
				ADOUBLE_NAME_PREFIX,
				strlen(ADOUBLE_NAME_PREFIX));
		if (match != 0) {
			continue;
		}

		p = talloc_asprintf(talloc_tos(), "%s/%s",
				    smb_fname->base_name, de->d_name);
		if (p == NULL) {
			DBG_ERR("talloc_asprintf failed\n");
			return -1;
		}

		ad_smb_fname = synthetic_smb_fname(talloc_tos(), p,
						    NULL, NULL,
						    smb_fname->flags);
		TALLOC_FREE(p);
		if (ad_smb_fname == NULL) {
			DBG_ERR("synthetic_smb_fname failed\n");
			return -1;
		}

		/*
		 * Check whether it's a valid AppleDouble file, if
		 * yes, delete it, ignore it otherwise.
		 */
		ad = ad_get(talloc_tos(), handle, ad_smb_fname, ADOUBLE_RSRC);
		if (ad == NULL) {
			TALLOC_FREE(ad_smb_fname);
			TALLOC_FREE(p);
			continue;
		}
		TALLOC_FREE(ad);

		ret = SMB_VFS_NEXT_UNLINK(handle, ad_smb_fname);
		if (ret != 0) {
			DBG_ERR("Deleting [%s] failed\n",
				smb_fname_str_dbg(ad_smb_fname));
		}
		TALLOC_FREE(ad_smb_fname);
	}

exit_rmdir:
	if (dh) {
		SMB_VFS_CLOSEDIR(handle->conn, dh);
	}
	return SMB_VFS_NEXT_RMDIR(handle, smb_fname);
}

static ssize_t fruit_pread_meta_stream(vfs_handle_struct *handle,
				       files_struct *fsp, void *data,
				       size_t n, off_t offset)
{
	ssize_t nread;
	int ret;

	nread = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	if (nread == -1 || nread == n) {
		return nread;
	}

	DBG_ERR("Removing [%s] after short read [%zd]\n",
		fsp_str_dbg(fsp), nread);

	ret = SMB_VFS_NEXT_UNLINK(handle, fsp->fsp_name);
	if (ret != 0) {
		DBG_ERR("Removing [%s] failed\n", fsp_str_dbg(fsp));
		return -1;
	}

	errno = EINVAL;
	return -1;
}

static ssize_t fruit_pread_meta_adouble(vfs_handle_struct *handle,
					files_struct *fsp, void *data,
					size_t n, off_t offset)
{
	AfpInfo *ai = NULL;
	struct adouble *ad = NULL;
	char afpinfo_buf[AFP_INFO_SIZE];
	char *p = NULL;
	ssize_t nread;

	ai = afpinfo_new(talloc_tos());
	if (ai == NULL) {
		return -1;
	}

	ad = ad_fget(talloc_tos(), handle, fsp, ADOUBLE_META);
	if (ad == NULL) {
		nread = -1;
		goto fail;
	}

	p = ad_get_entry(ad, ADEID_FINDERI);
	if (p == NULL) {
		DBG_ERR("No ADEID_FINDERI for [%s]\n", fsp_str_dbg(fsp));
		nread = -1;
		goto fail;
	}

	memcpy(&ai->afpi_FinderInfo[0], p, ADEDLEN_FINDERI);

	nread = afpinfo_pack(ai, afpinfo_buf);
	if (nread != AFP_INFO_SIZE) {
		nread = -1;
		goto fail;
	}

	memcpy(data, afpinfo_buf, n);
	nread = n;

fail:
	TALLOC_FREE(ai);
	return nread;
}

static ssize_t fruit_pread_meta(vfs_handle_struct *handle,
				files_struct *fsp, void *data,
				size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nread;
	ssize_t to_return;

	/*
	 * OS X has a off-by-1 error in the offset calculation, so we're
	 * bug compatible here. It won't hurt, as any relevant real
	 * world read requests from the AFP_AfpInfo stream will be
	 * offset=0 n=60. offset is ignored anyway, see below.
	 */
	if ((offset < 0) || (offset >= AFP_INFO_SIZE + 1)) {
		return 0;
	}

	if (fio == NULL) {
		DBG_ERR("Failed to fetch fsp extension");
		return -1;
	}

	/* Yes, macOS always reads from offset 0 */
	offset = 0;
	to_return = MIN(n, AFP_INFO_SIZE);

	switch (fio->config->meta) {
	case FRUIT_META_STREAM:
		nread = fruit_pread_meta_stream(handle, fsp, data,
						to_return, offset);
		break;

	case FRUIT_META_NETATALK:
		nread = fruit_pread_meta_adouble(handle, fsp, data,
						 to_return, offset);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", fio->config->meta);
		return -1;
	}

	if (nread == -1 && fio->created) {
		AfpInfo *ai = NULL;
		char afpinfo_buf[AFP_INFO_SIZE];

		ai = afpinfo_new(talloc_tos());
		if (ai == NULL) {
			return -1;
		}

		nread = afpinfo_pack(ai, afpinfo_buf);
		TALLOC_FREE(ai);
		if (nread != AFP_INFO_SIZE) {
			return -1;
		}

		memcpy(data, afpinfo_buf, to_return);
		return to_return;
	}

	return nread;
}

static ssize_t fruit_pread_rsrc_stream(vfs_handle_struct *handle,
				       files_struct *fsp, void *data,
				       size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
}

static ssize_t fruit_pread_rsrc_xattr(vfs_handle_struct *handle,
				      files_struct *fsp, void *data,
				      size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
}

static ssize_t fruit_pread_rsrc_adouble(vfs_handle_struct *handle,
					files_struct *fsp, void *data,
					size_t n, off_t offset)
{
	struct adouble *ad = NULL;
	ssize_t nread;

	ad = ad_fget(talloc_tos(), handle, fsp, ADOUBLE_RSRC);
	if (ad == NULL) {
		return -1;
	}

	nread = SMB_VFS_NEXT_PREAD(handle, fsp, data, n,
				   offset + ad_getentryoff(ad, ADEID_RFORK));

	TALLOC_FREE(ad);
	return nread;
}

static ssize_t fruit_pread_rsrc(vfs_handle_struct *handle,
				files_struct *fsp, void *data,
				size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nread;

	if (fio == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch (fio->config->rsrc) {
	case FRUIT_RSRC_STREAM:
		nread = fruit_pread_rsrc_stream(handle, fsp, data, n, offset);
		break;

	case FRUIT_RSRC_ADFILE:
		nread = fruit_pread_rsrc_adouble(handle, fsp, data, n, offset);
		break;

	case FRUIT_RSRC_XATTR:
		nread = fruit_pread_rsrc_xattr(handle, fsp, data, n, offset);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", fio->config->rsrc);
		return -1;
	}

	return nread;
}

static ssize_t fruit_pread(vfs_handle_struct *handle,
			   files_struct *fsp, void *data,
			   size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nread;

	DBG_DEBUG("Path [%s] offset=%"PRIdMAX", size=%zd\n",
		  fsp_str_dbg(fsp), (intmax_t)offset, n);

	if (fio == NULL) {
		return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	}

	if (fio->type == ADOUBLE_META) {
		nread = fruit_pread_meta(handle, fsp, data, n, offset);
	} else {
		nread = fruit_pread_rsrc(handle, fsp, data, n, offset);
	}

	DBG_DEBUG("Path [%s] nread [%zd]\n", fsp_str_dbg(fsp), nread);
	return nread;
}

static bool fruit_must_handle_aio_stream(struct fio *fio)
{
	if (fio == NULL) {
		return false;
	};

	if (fio->type == ADOUBLE_META) {
		return true;
	}

	if ((fio->type == ADOUBLE_RSRC) &&
	    (fio->config->rsrc == FRUIT_RSRC_ADFILE))
	{
		return true;
	}

	return false;
}

struct fruit_pread_state {
	ssize_t nread;
	struct vfs_aio_state vfs_aio_state;
};

static void fruit_pread_done(struct tevent_req *subreq);

static struct tevent_req *fruit_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct fruit_pread_state *state = NULL;
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct fruit_pread_state);
	if (req == NULL) {
		return NULL;
	}

	if (fruit_must_handle_aio_stream(fio)) {
		state->nread = SMB_VFS_PREAD(fsp, data, n, offset);
		if (state->nread != n) {
			if (state->nread != -1) {
				errno = EIO;
			}
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp,
					 data, n, offset);
	if (tevent_req_nomem(req, subreq)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fruit_pread_done, req);
	return req;
}

static void fruit_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fruit_pread_state *state = tevent_req_data(
		req, struct fruit_pread_state);

	state->nread = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t fruit_pread_recv(struct tevent_req *req,
					struct vfs_aio_state *vfs_aio_state)
{
	struct fruit_pread_state *state = tevent_req_data(
		req, struct fruit_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nread;
}

static ssize_t fruit_pwrite_meta_stream(vfs_handle_struct *handle,
					files_struct *fsp, const void *data,
					size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	AfpInfo *ai = NULL;
	size_t nwritten;
	int ret;
	bool ok;

	DBG_DEBUG("Path [%s] offset=%"PRIdMAX", size=%zd\n",
		  fsp_str_dbg(fsp), (intmax_t)offset, n);

	if (fio == NULL) {
		return -1;
	}

	if (fio->fake_fd) {
		int fd;

		ret = SMB_VFS_NEXT_CLOSE(handle, fsp);
		if (ret != 0) {
			DBG_ERR("Close [%s] failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			fsp->fh->fd = -1;
			return -1;
		}

		fd = SMB_VFS_NEXT_OPEN(handle,
				       fsp->fsp_name,
				       fsp,
				       fio->flags,
				       fio->mode);
		if (fd == -1) {
			DBG_ERR("On-demand create [%s] in write failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			return -1;
		}
		fsp->fh->fd = fd;
		fio->fake_fd = false;
	}

	ai = afpinfo_unpack(talloc_tos(), data);
	if (ai == NULL) {
		return -1;
	}

	if (ai_empty_finderinfo(ai)) {
		ret = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, 0);
		if (ret != 0) {
			DBG_ERR("SMB_VFS_NEXT_FTRUNCATE on [%s] failed\n",
				fsp_str_dbg(fsp));
			return -1;
		}

		ok = set_delete_on_close(
			fsp,
			true,
			handle->conn->session_info->security_token,
			handle->conn->session_info->unix_token);
		if (!ok) {
			DBG_ERR("set_delete_on_close on [%s] failed\n",
				fsp_str_dbg(fsp));
			return -1;
		}
		return n;
	}

	nwritten = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	if (nwritten != n) {
		return -1;
	}

	return n;
}

static ssize_t fruit_pwrite_meta_netatalk(vfs_handle_struct *handle,
					  files_struct *fsp, const void *data,
					  size_t n, off_t offset)
{
	struct adouble *ad = NULL;
	AfpInfo *ai = NULL;
	char *p = NULL;
	int ret;
	bool ok;

	ai = afpinfo_unpack(talloc_tos(), data);
	if (ai == NULL) {
		return -1;
	}

	ad = ad_fget(talloc_tos(), handle, fsp, ADOUBLE_META);
	if (ad == NULL) {
		ad = ad_init(talloc_tos(), handle, ADOUBLE_META);
		if (ad == NULL) {
			return -1;
		}
	}
	p = ad_get_entry(ad, ADEID_FINDERI);
	if (p == NULL) {
		DBG_ERR("No ADEID_FINDERI for [%s]\n", fsp_str_dbg(fsp));
		TALLOC_FREE(ad);
		return -1;
	}

	memcpy(p, &ai->afpi_FinderInfo[0], ADEDLEN_FINDERI);

	ret = ad_fset(ad, fsp);
	if (ret != 0) {
		DBG_ERR("ad_pwrite [%s] failed\n", fsp_str_dbg(fsp));
		TALLOC_FREE(ad);
		return -1;
	}

	TALLOC_FREE(ad);

	if (!ai_empty_finderinfo(ai)) {
		return n;
	}

	ok = set_delete_on_close(
		fsp,
		true,
		handle->conn->session_info->security_token,
		handle->conn->session_info->unix_token);
	if (!ok) {
		DBG_ERR("set_delete_on_close on [%s] failed\n",
			fsp_str_dbg(fsp));
		return -1;
	}

	return n;
}

static ssize_t fruit_pwrite_meta(vfs_handle_struct *handle,
				 files_struct *fsp, const void *data,
				 size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nwritten;

	/*
	 * Writing an all 0 blob to the metadata stream
	 * results in the stream being removed on a macOS
	 * server. This ensures we behave the same and it
	 * verified by the "delete AFP_AfpInfo by writing all
	 * 0" test.
	 */
	if (n != AFP_INFO_SIZE || offset != 0) {
		DBG_ERR("unexpected offset=%jd or size=%jd\n",
			(intmax_t)offset, (intmax_t)n);
		return -1;
	}

	if (fio == NULL) {
		DBG_ERR("Failed to fetch fsp extension");
		return -1;
	}

	switch (fio->config->meta) {
	case FRUIT_META_STREAM:
		nwritten = fruit_pwrite_meta_stream(handle, fsp, data,
						    n, offset);
		break;

	case FRUIT_META_NETATALK:
		nwritten = fruit_pwrite_meta_netatalk(handle, fsp, data,
						      n, offset);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", fio->config->meta);
		return -1;
	}

	return nwritten;
}

static ssize_t fruit_pwrite_rsrc_stream(vfs_handle_struct *handle,
					files_struct *fsp, const void *data,
					size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
}

static ssize_t fruit_pwrite_rsrc_xattr(vfs_handle_struct *handle,
				       files_struct *fsp, const void *data,
				       size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
}

static ssize_t fruit_pwrite_rsrc_adouble(vfs_handle_struct *handle,
					 files_struct *fsp, const void *data,
					 size_t n, off_t offset)
{
	struct adouble *ad = NULL;
	ssize_t nwritten;
	int ret;

	ad = ad_fget(talloc_tos(), handle, fsp, ADOUBLE_RSRC);
	if (ad == NULL) {
		DBG_ERR("ad_get [%s] failed\n", fsp_str_dbg(fsp));
		return -1;
	}

	nwritten = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n,
				       offset + ad_getentryoff(ad, ADEID_RFORK));
	if (nwritten != n) {
		DBG_ERR("Short write on [%s] [%zd/%zd]\n",
			fsp_str_dbg(fsp), nwritten, n);
		TALLOC_FREE(ad);
		return -1;
	}

	if ((n + offset) > ad_getentrylen(ad, ADEID_RFORK)) {
		ad_setentrylen(ad, ADEID_RFORK, n + offset);
		ret = ad_fset(ad, fsp);
		if (ret != 0) {
			DBG_ERR("ad_pwrite [%s] failed\n", fsp_str_dbg(fsp));
			TALLOC_FREE(ad);
			return -1;
		}
	}

	TALLOC_FREE(ad);
	return n;
}

static ssize_t fruit_pwrite_rsrc(vfs_handle_struct *handle,
				 files_struct *fsp, const void *data,
				 size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nwritten;

	if (fio == NULL) {
		DBG_ERR("Failed to fetch fsp extension");
		return -1;
	}

	switch (fio->config->rsrc) {
	case FRUIT_RSRC_STREAM:
		nwritten = fruit_pwrite_rsrc_stream(handle, fsp, data, n, offset);
		break;

	case FRUIT_RSRC_ADFILE:
		nwritten = fruit_pwrite_rsrc_adouble(handle, fsp, data, n, offset);
		break;

	case FRUIT_RSRC_XATTR:
		nwritten = fruit_pwrite_rsrc_xattr(handle, fsp, data, n, offset);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", fio->config->rsrc);
		return -1;
	}

	return nwritten;
}

static ssize_t fruit_pwrite(vfs_handle_struct *handle,
			    files_struct *fsp, const void *data,
			    size_t n, off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ssize_t nwritten;

	DBG_DEBUG("Path [%s] offset=%"PRIdMAX", size=%zd\n",
		  fsp_str_dbg(fsp), (intmax_t)offset, n);

	if (fio == NULL) {
		return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	}

	if (fio->type == ADOUBLE_META) {
		nwritten = fruit_pwrite_meta(handle, fsp, data, n, offset);
	} else {
		nwritten = fruit_pwrite_rsrc(handle, fsp, data, n, offset);
	}

	DBG_DEBUG("Path [%s] nwritten=%zd\n", fsp_str_dbg(fsp), nwritten);
	return nwritten;
}

struct fruit_pwrite_state {
	ssize_t nwritten;
	struct vfs_aio_state vfs_aio_state;
};

static void fruit_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *fruit_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct fruit_pwrite_state *state = NULL;
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct fruit_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	if (fruit_must_handle_aio_stream(fio)) {
		state->nwritten = SMB_VFS_PWRITE(fsp, data, n, offset);
		if (state->nwritten != n) {
			if (state->nwritten != -1) {
				errno = EIO;
			}
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp,
					  data, n, offset);
	if (tevent_req_nomem(req, subreq)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fruit_pwrite_done, req);
	return req;
}

static void fruit_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fruit_pwrite_state *state = tevent_req_data(
		req, struct fruit_pwrite_state);

	state->nwritten = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t fruit_pwrite_recv(struct tevent_req *req,
					 struct vfs_aio_state *vfs_aio_state)
{
	struct fruit_pwrite_state *state = tevent_req_data(
		req, struct fruit_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nwritten;
}

/**
 * Helper to stat/lstat the base file of an smb_fname.
 */
static int fruit_stat_base(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)
{
	char *tmp_stream_name;
	int rc;

	tmp_stream_name = smb_fname->stream_name;
	smb_fname->stream_name = NULL;
	if (follow_links) {
		rc = SMB_VFS_NEXT_STAT(handle, smb_fname);
	} else {
		rc = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}
	smb_fname->stream_name = tmp_stream_name;

	DBG_DEBUG("fruit_stat_base [%s] dev [%ju] ino [%ju]\n",
		  smb_fname->base_name,
		  (uintmax_t)smb_fname->st.st_ex_dev,
		  (uintmax_t)smb_fname->st.st_ex_ino);
	return rc;
}

static int fruit_stat_meta_stream(vfs_handle_struct *handle,
				  struct smb_filename *smb_fname,
				  bool follow_links)
{
	int ret;
	ino_t ino;

	ret = fruit_stat_base(handle, smb_fname, false);
	if (ret != 0) {
		return -1;
	}

	ino = fruit_inode(&smb_fname->st, smb_fname->stream_name);

	if (follow_links) {
		ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	} else {
		ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	smb_fname->st.st_ex_ino = ino;

	return ret;
}

static int fruit_stat_meta_netatalk(vfs_handle_struct *handle,
				    struct smb_filename *smb_fname,
				    bool follow_links)
{
	struct adouble *ad = NULL;

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad == NULL) {
		DBG_INFO("fruit_stat_meta %s: %s\n",
			 smb_fname_str_dbg(smb_fname), strerror(errno));
		errno = ENOENT;
		return -1;
	}
	TALLOC_FREE(ad);

	/* Populate the stat struct with info from the base file. */
	if (fruit_stat_base(handle, smb_fname, follow_links) == -1) {
		return -1;
	}
	smb_fname->st.st_ex_size = AFP_INFO_SIZE;
	smb_fname->st.st_ex_ino = fruit_inode(&smb_fname->st,
					      smb_fname->stream_name);
	return 0;
}

static int fruit_stat_meta(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)
{
	struct fruit_config_data *config = NULL;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->meta) {
	case FRUIT_META_STREAM:
		ret = fruit_stat_meta_stream(handle, smb_fname, follow_links);
		break;

	case FRUIT_META_NETATALK:
		ret = fruit_stat_meta_netatalk(handle, smb_fname, follow_links);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", config->meta);
		return -1;
	}

	return ret;
}

static int fruit_stat_rsrc_netatalk(vfs_handle_struct *handle,
				    struct smb_filename *smb_fname,
				    bool follow_links)
{
	struct adouble *ad = NULL;
	int ret;

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_RSRC);
	if (ad == NULL) {
		errno = ENOENT;
		return -1;
	}

	/* Populate the stat struct with info from the base file. */
	ret = fruit_stat_base(handle, smb_fname, follow_links);
	if (ret != 0) {
		TALLOC_FREE(ad);
		return -1;
	}

	smb_fname->st.st_ex_size = ad_getentrylen(ad, ADEID_RFORK);
	smb_fname->st.st_ex_ino = fruit_inode(&smb_fname->st,
					      smb_fname->stream_name);
	TALLOC_FREE(ad);
	return 0;
}

static int fruit_stat_rsrc_stream(vfs_handle_struct *handle,
				  struct smb_filename *smb_fname,
				  bool follow_links)
{
	int ret;

	if (follow_links) {
		ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	} else {
		ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	return ret;
}

static int fruit_stat_rsrc_xattr(vfs_handle_struct *handle,
				 struct smb_filename *smb_fname,
				 bool follow_links)
{
#ifdef HAVE_ATTROPEN
	int ret;
	int fd = -1;

	/* Populate the stat struct with info from the base file. */
	ret = fruit_stat_base(handle, smb_fname, follow_links);
	if (ret != 0) {
		return -1;
	}

	fd = attropen(smb_fname->base_name,
		      AFPRESOURCE_EA_NETATALK,
		      O_RDONLY);
	if (fd == -1) {
		return 0;
	}

	ret = sys_fstat(fd, &smb_fname->st, false);
	if (ret != 0) {
		close(fd);
		DBG_ERR("fstat [%s:%s] failed\n", smb_fname->base_name,
			AFPRESOURCE_EA_NETATALK);
		return -1;
	}
	close(fd);
	fd = -1;

	smb_fname->st.st_ex_ino = fruit_inode(&smb_fname->st,
					      smb_fname->stream_name);

	return ret;

#else
	errno = ENOSYS;
	return -1;
#endif
}

static int fruit_stat_rsrc(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)
{
	struct fruit_config_data *config = NULL;
	int ret;

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->rsrc) {
	case FRUIT_RSRC_STREAM:
		ret = fruit_stat_rsrc_stream(handle, smb_fname, follow_links);
		break;

	case FRUIT_RSRC_XATTR:
		ret = fruit_stat_rsrc_xattr(handle, smb_fname, follow_links);
		break;

	case FRUIT_RSRC_ADFILE:
		ret = fruit_stat_rsrc_netatalk(handle, smb_fname, follow_links);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", config->rsrc);
		return -1;
	}

	return ret;
}

static int fruit_stat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	int rc = -1;

	DEBUG(10, ("fruit_stat called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	if (!is_ntfs_stream_smb_fname(smb_fname)
	    || is_ntfs_default_stream_smb_fname(smb_fname)) {
		rc = SMB_VFS_NEXT_STAT(handle, smb_fname);
		if (rc == 0) {
			update_btime(handle, smb_fname);
		}
		return rc;
	}

	/*
	 * Note if lp_posix_paths() is true, we can never
	 * get here as is_ntfs_stream_smb_fname() is
	 * always false. So we never need worry about
	 * not following links here.
	 */

	if (is_afpinfo_stream(smb_fname)) {
		rc = fruit_stat_meta(handle, smb_fname, true);
	} else if (is_afpresource_stream(smb_fname)) {
		rc = fruit_stat_rsrc(handle, smb_fname, true);
	} else {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	if (rc == 0) {
		update_btime(handle, smb_fname);
		smb_fname->st.st_ex_mode &= ~S_IFMT;
		smb_fname->st.st_ex_mode |= S_IFREG;
		smb_fname->st.st_ex_blocks =
			smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}
	return rc;
}

static int fruit_lstat(vfs_handle_struct *handle,
		       struct smb_filename *smb_fname)
{
	int rc = -1;

	DEBUG(10, ("fruit_lstat called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	if (!is_ntfs_stream_smb_fname(smb_fname)
	    || is_ntfs_default_stream_smb_fname(smb_fname)) {
		rc = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
		if (rc == 0) {
			update_btime(handle, smb_fname);
		}
		return rc;
	}

	if (is_afpinfo_stream(smb_fname)) {
		rc = fruit_stat_meta(handle, smb_fname, false);
	} else if (is_afpresource_stream(smb_fname)) {
		rc = fruit_stat_rsrc(handle, smb_fname, false);
	} else {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	if (rc == 0) {
		update_btime(handle, smb_fname);
		smb_fname->st.st_ex_mode &= ~S_IFMT;
		smb_fname->st.st_ex_mode |= S_IFREG;
		smb_fname->st.st_ex_blocks =
			smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}
	return rc;
}

static int fruit_fstat_meta_stream(vfs_handle_struct *handle,
				   files_struct *fsp,
				   SMB_STRUCT_STAT *sbuf)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ino_t ino;
	int ret;

	if (fio == NULL) {
		return -1;
	}

	if (fio->fake_fd) {
		ret = fruit_stat_base(handle, fsp->base_fsp->fsp_name, false);
		if (ret != 0) {
			return -1;
		}

		*sbuf = fsp->base_fsp->fsp_name->st;
		sbuf->st_ex_size = AFP_INFO_SIZE;
		sbuf->st_ex_ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);
		return 0;
	}

	ret = fruit_stat_base(handle, fsp->base_fsp->fsp_name, false);
	if (ret != 0) {
		return -1;
	}
	*sbuf = fsp->base_fsp->fsp_name->st;

	ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret != 0) {
		return -1;
	}

	sbuf->st_ex_ino = ino;
	return 0;
}

static int fruit_fstat_meta_netatalk(vfs_handle_struct *handle,
				     files_struct *fsp,
				     SMB_STRUCT_STAT *sbuf)
{
	int ret;

	ret = fruit_stat_base(handle, fsp->base_fsp->fsp_name, false);
	if (ret != 0) {
		return -1;
	}

	*sbuf = fsp->base_fsp->fsp_name->st;
	sbuf->st_ex_size = AFP_INFO_SIZE;
	sbuf->st_ex_ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);

	return 0;
}

static int fruit_fstat_meta(vfs_handle_struct *handle,
			    files_struct *fsp,
			    SMB_STRUCT_STAT *sbuf,
			    struct fio *fio)
{
	int ret;

	DBG_DEBUG("Path [%s]\n", fsp_str_dbg(fsp));

	switch (fio->config->meta) {
	case FRUIT_META_STREAM:
		ret = fruit_fstat_meta_stream(handle, fsp, sbuf);
		break;

	case FRUIT_META_NETATALK:
		ret = fruit_fstat_meta_netatalk(handle, fsp, sbuf);
		break;

	default:
		DBG_ERR("Unexpected meta config [%d]\n", fio->config->meta);
		return -1;
	}

	DBG_DEBUG("Path [%s] ret [%d]\n", fsp_str_dbg(fsp), ret);
	return ret;
}

static int fruit_fstat_rsrc_xattr(vfs_handle_struct *handle,
				  files_struct *fsp,
				  SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
}

static int fruit_fstat_rsrc_stream(vfs_handle_struct *handle,
				   files_struct *fsp,
				   SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
}

static int fruit_fstat_rsrc_adouble(vfs_handle_struct *handle,
				    files_struct *fsp,
				    SMB_STRUCT_STAT *sbuf)
{
	struct adouble *ad = NULL;
	int ret;

	/* Populate the stat struct with info from the base file. */
	ret = fruit_stat_base(handle, fsp->base_fsp->fsp_name, false);
	if (ret == -1) {
		return -1;
	}

	ad = ad_get(talloc_tos(), handle,
		    fsp->base_fsp->fsp_name,
		    ADOUBLE_RSRC);
	if (ad == NULL) {
		DBG_ERR("ad_get [%s] failed [%s]\n",
			fsp_str_dbg(fsp), strerror(errno));
		return -1;
	}

	*sbuf = fsp->base_fsp->fsp_name->st;
	sbuf->st_ex_size = ad_getentrylen(ad, ADEID_RFORK);
	sbuf->st_ex_ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);

	TALLOC_FREE(ad);
	return 0;
}

static int fruit_fstat_rsrc(vfs_handle_struct *handle, files_struct *fsp,
			    SMB_STRUCT_STAT *sbuf, struct fio *fio)
{
	int ret;

	switch (fio->config->rsrc) {
	case FRUIT_RSRC_STREAM:
		ret = fruit_fstat_rsrc_stream(handle, fsp, sbuf);
		break;

	case FRUIT_RSRC_ADFILE:
		ret = fruit_fstat_rsrc_adouble(handle, fsp, sbuf);
		break;

	case FRUIT_RSRC_XATTR:
		ret = fruit_fstat_rsrc_xattr(handle, fsp, sbuf);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", fio->config->rsrc);
		return -1;
	}

	return ret;
}

static int fruit_fstat(vfs_handle_struct *handle, files_struct *fsp,
		       SMB_STRUCT_STAT *sbuf)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	int rc;

	if (fio == NULL) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	DBG_DEBUG("Path [%s]\n", fsp_str_dbg(fsp));

	if (fio->type == ADOUBLE_META) {
		rc = fruit_fstat_meta(handle, fsp, sbuf, fio);
	} else {
		rc = fruit_fstat_rsrc(handle, fsp, sbuf, fio);
	}

	if (rc == 0) {
		sbuf->st_ex_mode &= ~S_IFMT;
		sbuf->st_ex_mode |= S_IFREG;
		sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}

	DBG_DEBUG("Path [%s] rc [%d] size [%"PRIdMAX"]\n",
		  fsp_str_dbg(fsp), rc, (intmax_t)sbuf->st_ex_size);
	return rc;
}

static NTSTATUS delete_invalid_meta_stream(
	vfs_handle_struct *handle,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams,
	off_t size)
{
	struct smb_filename *sname = NULL;
	int ret;
	bool ok;

	ok = del_fruit_stream(mem_ctx, pnum_streams, pstreams, AFPINFO_STREAM);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (size == 0) {
		return NT_STATUS_OK;
	}

	sname = synthetic_smb_fname(talloc_tos(),
				    smb_fname->base_name,
				    AFPINFO_STREAM_NAME,
				    NULL, 0);
	if (sname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_NEXT_UNLINK(handle, sname);
	TALLOC_FREE(sname);
	if (ret != 0) {
		DBG_ERR("Removing [%s] failed\n", smb_fname_str_dbg(sname));
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_meta_stream(
	vfs_handle_struct *handle,
	struct files_struct *fsp,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams)
{
	struct stream_struct *stream = *pstreams;
	unsigned int num_streams = *pnum_streams;
	int i;

	for (i = 0; i < num_streams; i++) {
		if (strequal_m(stream[i].name, AFPINFO_STREAM)) {
			break;
		}
	}

	if (i == num_streams) {
		return NT_STATUS_OK;
	}

	if (stream[i].size != AFP_INFO_SIZE) {
		DBG_ERR("Removing invalid AFPINFO_STREAM size [%jd] from [%s]\n",
			(intmax_t)stream[i].size, smb_fname_str_dbg(smb_fname));

		return delete_invalid_meta_stream(handle,
						  smb_fname,
						  mem_ctx,
						  pnum_streams,
						  pstreams,
						  stream[i].size);
	}


	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_meta_netatalk(
	vfs_handle_struct *handle,
	struct files_struct *fsp,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams)
{
	struct stream_struct *stream = *pstreams;
	unsigned int num_streams = *pnum_streams;
	struct adouble *ad = NULL;
	bool is_fi_empty;
	int i;
	bool ok;

	/* Remove the Netatalk xattr from the list */
	ok = del_fruit_stream(mem_ctx, pnum_streams, pstreams,
			      ":" NETATALK_META_XATTR ":$DATA");
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Check if there's a AFPINFO_STREAM from the VFS streams
	 * backend and if yes, remove it from the list
	 */
	for (i = 0; i < num_streams; i++) {
		if (strequal_m(stream[i].name, AFPINFO_STREAM)) {
			break;
		}
	}

	if (i < num_streams) {
		DBG_WARNING("Unexpected AFPINFO_STREAM on [%s]\n",
			    smb_fname_str_dbg(smb_fname));

		ok = del_fruit_stream(mem_ctx, pnum_streams, pstreams,
				      AFPINFO_STREAM);
		if (!ok) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad == NULL) {
		return NT_STATUS_OK;
	}

	is_fi_empty = ad_empty_finderinfo(ad);
	TALLOC_FREE(ad);

	if (is_fi_empty) {
		return NT_STATUS_OK;
	}

	ok = add_fruit_stream(mem_ctx, pnum_streams, pstreams,
			      AFPINFO_STREAM_NAME, AFP_INFO_SIZE,
			      smb_roundup(handle->conn, AFP_INFO_SIZE));
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_meta(vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      const struct smb_filename *smb_fname,
				      TALLOC_CTX *mem_ctx,
				      unsigned int *pnum_streams,
				      struct stream_struct **pstreams)
{
	struct fruit_config_data *config = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	switch (config->meta) {
	case FRUIT_META_NETATALK:
		status = fruit_streaminfo_meta_netatalk(handle, fsp, smb_fname,
							mem_ctx, pnum_streams,
							pstreams);
		break;

	case FRUIT_META_STREAM:
		status = fruit_streaminfo_meta_stream(handle, fsp, smb_fname,
						      mem_ctx, pnum_streams,
						      pstreams);
		break;

	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	return status;
}

static NTSTATUS fruit_streaminfo_rsrc_stream(
	vfs_handle_struct *handle,
	struct files_struct *fsp,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams)
{
	bool ok;

	ok = filter_empty_rsrc_stream(pnum_streams, pstreams);
	if (!ok) {
		DBG_ERR("Filtering resource stream failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_rsrc_xattr(
	vfs_handle_struct *handle,
	struct files_struct *fsp,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams)
{
	bool ok;

	ok = filter_empty_rsrc_stream(pnum_streams, pstreams);
	if (!ok) {
		DBG_ERR("Filtering resource stream failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_rsrc_adouble(
	vfs_handle_struct *handle,
	struct files_struct *fsp,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	unsigned int *pnum_streams,
	struct stream_struct **pstreams)
{
	struct stream_struct *stream = *pstreams;
	unsigned int num_streams = *pnum_streams;
	struct adouble *ad = NULL;
	bool ok;
	size_t rlen;
	int i;

	/*
	 * Check if there's a AFPRESOURCE_STREAM from the VFS streams backend
	 * and if yes, remove it from the list
	 */
	for (i = 0; i < num_streams; i++) {
		if (strequal_m(stream[i].name, AFPRESOURCE_STREAM)) {
			break;
		}
	}

	if (i < num_streams) {
		DBG_WARNING("Unexpected AFPRESOURCE_STREAM on [%s]\n",
			    smb_fname_str_dbg(smb_fname));

		ok = del_fruit_stream(mem_ctx, pnum_streams, pstreams,
				      AFPRESOURCE_STREAM);
		if (!ok) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_RSRC);
	if (ad == NULL) {
		return NT_STATUS_OK;
	}

	rlen = ad_getentrylen(ad, ADEID_RFORK);
	TALLOC_FREE(ad);

	if (rlen == 0) {
		return NT_STATUS_OK;
	}

	ok = add_fruit_stream(mem_ctx, pnum_streams, pstreams,
			      AFPRESOURCE_STREAM_NAME, rlen,
			      smb_roundup(handle->conn, rlen));
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fruit_streaminfo_rsrc(vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      const struct smb_filename *smb_fname,
				      TALLOC_CTX *mem_ctx,
				      unsigned int *pnum_streams,
				      struct stream_struct **pstreams)
{
	struct fruit_config_data *config = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	switch (config->rsrc) {
	case FRUIT_RSRC_STREAM:
		status = fruit_streaminfo_rsrc_stream(handle, fsp, smb_fname,
						      mem_ctx, pnum_streams,
						      pstreams);
		break;

	case FRUIT_RSRC_XATTR:
		status = fruit_streaminfo_rsrc_xattr(handle, fsp, smb_fname,
						     mem_ctx, pnum_streams,
						     pstreams);
		break;

	case FRUIT_RSRC_ADFILE:
		status = fruit_streaminfo_rsrc_adouble(handle, fsp, smb_fname,
						       mem_ctx, pnum_streams,
						       pstreams);
		break;

	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	return status;
}

static void fruit_filter_empty_streams(unsigned int *pnum_streams,
				       struct stream_struct **pstreams)
{
	unsigned num_streams = *pnum_streams;
	struct stream_struct *streams = *pstreams;
	unsigned i = 0;

	if (!global_fruit_config.nego_aapl) {
		return;
	}

	while (i < num_streams) {
		struct smb_filename smb_fname = (struct smb_filename) {
			.stream_name = streams[i].name,
		};

		if (is_ntfs_default_stream_smb_fname(&smb_fname)
		    || streams[i].size > 0)
		{
			i++;
			continue;
		}

		streams[i] = streams[num_streams - 1];
		num_streams--;
	}

	*pnum_streams = num_streams;
}

static NTSTATUS fruit_streaminfo(vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const struct smb_filename *smb_fname,
				 TALLOC_CTX *mem_ctx,
				 unsigned int *pnum_streams,
				 struct stream_struct **pstreams)
{
	struct fruit_config_data *config = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	DBG_DEBUG("Path [%s]\n", smb_fname_str_dbg(smb_fname));

	status = SMB_VFS_NEXT_STREAMINFO(handle, fsp, smb_fname, mem_ctx,
					 pnum_streams, pstreams);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fruit_filter_empty_streams(pnum_streams, pstreams);

	status = fruit_streaminfo_meta(handle, fsp, smb_fname,
				       mem_ctx, pnum_streams, pstreams);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = fruit_streaminfo_rsrc(handle, fsp, smb_fname,
				       mem_ctx, pnum_streams, pstreams);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static int fruit_ntimes(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct smb_file_time *ft)
{
	int rc = 0;
	struct adouble *ad = NULL;
	struct fruit_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return -1);

	if ((config->meta != FRUIT_META_NETATALK) ||
	    null_timespec(ft->create_time))
	{
		return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
	}

	DEBUG(10,("set btime for %s to %s\n", smb_fname_str_dbg(smb_fname),
		 time_to_asc(convert_timespec_to_time_t(ft->create_time))));

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_META);
	if (ad == NULL) {
		goto exit;
	}

	ad_setdate(ad, AD_DATE_CREATE | AD_DATE_UNIX,
		   convert_time_t_to_uint32_t(ft->create_time.tv_sec));

	rc = ad_set(ad, smb_fname);

exit:

	TALLOC_FREE(ad);
	if (rc != 0) {
		DEBUG(1, ("fruit_ntimes: %s\n", smb_fname_str_dbg(smb_fname)));
		return -1;
	}
	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int fruit_fallocate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   uint32_t mode,
			   off_t offset,
			   off_t len)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (fio == NULL) {
		return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	}

	/* Let the pwrite code path handle it. */
	errno = ENOSYS;
	return -1;
}

static int fruit_ftruncate_rsrc_xattr(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      off_t offset)
{
#ifdef HAVE_ATTROPEN
	return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
#endif
	return 0;
}

static int fruit_ftruncate_rsrc_adouble(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					off_t offset)
{
	int rc;
	struct adouble *ad = NULL;
	off_t ad_off;

	ad = ad_fget(talloc_tos(), handle, fsp, ADOUBLE_RSRC);
	if (ad == NULL) {
		DBG_DEBUG("ad_get [%s] failed [%s]\n",
			  fsp_str_dbg(fsp), strerror(errno));
		return -1;
	}

	ad_off = ad_getentryoff(ad, ADEID_RFORK);

	rc = ftruncate(fsp->fh->fd, offset + ad_off);
	if (rc != 0) {
		TALLOC_FREE(ad);
		return -1;
	}

	ad_setentrylen(ad, ADEID_RFORK, offset);

	rc = ad_fset(ad, fsp);
	if (rc != 0) {
		DBG_ERR("ad_fset [%s] failed [%s]\n",
			fsp_str_dbg(fsp), strerror(errno));
		TALLOC_FREE(ad);
		return -1;
	}

	TALLOC_FREE(ad);
	return 0;
}

static int fruit_ftruncate_rsrc_stream(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       off_t offset)
{
	return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
}

static int fruit_ftruncate_rsrc(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	int ret;

	if (fio == NULL) {
		DBG_ERR("Failed to fetch fsp extension");
		return -1;
	}

	switch (fio->config->rsrc) {
	case FRUIT_RSRC_XATTR:
		ret = fruit_ftruncate_rsrc_xattr(handle, fsp, offset);
		break;

	case FRUIT_RSRC_ADFILE:
		ret = fruit_ftruncate_rsrc_adouble(handle, fsp, offset);
		break;

	case FRUIT_RSRC_STREAM:
		ret = fruit_ftruncate_rsrc_stream(handle, fsp, offset);
		break;

	default:
		DBG_ERR("Unexpected rsrc config [%d]\n", fio->config->rsrc);
		return -1;
	}


	return ret;
}

static int fruit_ftruncate_meta(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				off_t offset)
{
	if (offset > 60) {
		DBG_WARNING("ftruncate %s to %jd",
			    fsp_str_dbg(fsp), (intmax_t)offset);
		/* OS X returns NT_STATUS_ALLOTTED_SPACE_EXCEEDED  */
		errno = EOVERFLOW;
		return -1;
	}

	/* OS X returns success but does nothing  */
	DBG_INFO("ignoring ftruncate %s to %jd\n",
		 fsp_str_dbg(fsp), (intmax_t)offset);
	return 0;
}

static int fruit_ftruncate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   off_t offset)
{
	struct fio *fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	int ret;

	DBG_DEBUG("Path [%s] offset [%"PRIdMAX"]\n", fsp_str_dbg(fsp),
		  (intmax_t)offset);

	if (fio == NULL) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
	}

	if (fio->type == ADOUBLE_META) {
		ret = fruit_ftruncate_meta(handle, fsp, offset);
	} else {
		ret = fruit_ftruncate_rsrc(handle, fsp, offset);
	}

	DBG_DEBUG("Path [%s] result [%d]\n", fsp_str_dbg(fsp), ret);
	return ret;
}

static NTSTATUS fruit_create_file(vfs_handle_struct *handle,
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
				  files_struct **result,
				  int *pinfo,
				  const struct smb2_create_blobs *in_context_blobs,
				  struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS status;
	struct fruit_config_data *config = NULL;
	files_struct *fsp = NULL;
	struct fio *fio = NULL;

	status = check_aapl(handle, req, in_context_blobs, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	status = SMB_VFS_NEXT_CREATE_FILE(
		handle, req, root_dir_fid, smb_fname,
		access_mask, share_access,
		create_disposition, create_options,
		file_attributes, oplock_request,
		lease,
		allocation_size, private_flags,
		sd, ea_list, result,
		pinfo, in_context_blobs, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp = *result;

	if (global_fruit_config.nego_aapl) {
		if (config->posix_rename && fsp->is_directory) {
			/*
			 * Enable POSIX directory rename behaviour
			 */
			fsp->posix_flags |= FSP_POSIX_FLAGS_RENAME;
		}
	}

	/*
	 * If this is a plain open for existing files, opening an 0
	 * byte size resource fork MUST fail with
	 * NT_STATUS_OBJECT_NAME_NOT_FOUND.
	 *
	 * Cf the vfs_fruit torture tests in test_rfork_create().
	 */
	if (global_fruit_config.nego_aapl &&
	    create_disposition == FILE_OPEN &&
	    smb_fname->st.st_ex_size == 0 &&
	    is_ntfs_stream_smb_fname(smb_fname) &&
	    !(is_ntfs_default_stream_smb_fname(smb_fname)))
	{
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	fio = (struct fio *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fio != NULL && pinfo != NULL && *pinfo == FILE_WAS_CREATED) {
		fio->created = true;
	}

	if (is_ntfs_stream_smb_fname(smb_fname)
	    || fsp->is_directory) {
		return status;
	}

	if (config->locking == FRUIT_LOCKING_NETATALK) {
		status = fruit_check_access(
			handle, *result,
			access_mask,
			map_share_mode_to_deny_mode(share_access, 0));
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	return status;

fail:
	DEBUG(10, ("fruit_create_file: %s\n", nt_errstr(status)));

	if (fsp) {
		close_file(req, fsp, ERROR_CLOSE);
		*result = fsp = NULL;
	}

	return status;
}

static NTSTATUS fruit_readdir_attr(struct vfs_handle_struct *handle,
				   const struct smb_filename *fname,
				   TALLOC_CTX *mem_ctx,
				   struct readdir_attr_data **pattr_data)
{
	struct fruit_config_data *config = NULL;
	struct readdir_attr_data *attr_data;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	if (!global_fruit_config.nego_aapl) {
		return SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
	}

	DEBUG(10, ("fruit_readdir_attr %s\n", fname->base_name));

	*pattr_data = talloc_zero(mem_ctx, struct readdir_attr_data);
	if (*pattr_data == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	attr_data = *pattr_data;
	attr_data->type = RDATTR_AAPL;

	/*
	 * Mac metadata: compressed FinderInfo, resource fork length
	 * and creation date
	 */
	status = readdir_attr_macmeta(handle, fname, attr_data);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Error handling is tricky: if we return failure from
		 * this function, the corresponding directory entry
		 * will to be passed to the client, so we really just
		 * want to error out on fatal errors.
		 */
		if  (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			goto fail;
		}
	}

	/*
	 * UNIX mode
	 */
	if (config->unix_info_enabled) {
		attr_data->attr_data.aapl.unix_mode = fname->st.st_ex_mode;
	}

	/*
	 * max_access
	 */
	if (!config->readdir_attr_max_access) {
		attr_data->attr_data.aapl.max_access = FILE_GENERIC_ALL;
	} else {
		status = smbd_calculate_access_mask(
			handle->conn,
			fname,
			false,
			SEC_FLAG_MAXIMUM_ALLOWED,
			&attr_data->attr_data.aapl.max_access);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	return NT_STATUS_OK;

fail:
	DEBUG(1, ("fruit_readdir_attr %s, error: %s\n",
		  fname->base_name, nt_errstr(status)));
	TALLOC_FREE(*pattr_data);
	return status;
}

static NTSTATUS fruit_fget_nt_acl(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	struct security_ace ace;
	struct dom_sid sid;
	struct fruit_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
					  mem_ctx, ppdesc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Add MS NFS style ACEs with uid, gid and mode
	 */
	if (!global_fruit_config.nego_aapl) {
		return NT_STATUS_OK;
	}
	if (!config->unix_info_enabled) {
		return NT_STATUS_OK;
	}

	/* First remove any existing ACE's with NFS style mode/uid/gid SIDs. */
	status = remove_virtual_nfs_aces(*ppdesc);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("failed to remove MS NFS style ACEs\n");
		return status;
	}

	/* MS NFS style mode */
	sid_compose(&sid, &global_sid_Unix_NFS_Mode, fsp->fsp_name->st.st_ex_mode);
	init_sec_ace(&ace, &sid, SEC_ACE_TYPE_ACCESS_DENIED, 0, 0);
	status = security_descriptor_dacl_add(*ppdesc, &ace);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("failed to add MS NFS style ACE\n"));
		return status;
	}

	/* MS NFS style uid */
	sid_compose(&sid, &global_sid_Unix_NFS_Users, fsp->fsp_name->st.st_ex_uid);
	init_sec_ace(&ace, &sid, SEC_ACE_TYPE_ACCESS_DENIED, 0, 0);
	status = security_descriptor_dacl_add(*ppdesc, &ace);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("failed to add MS NFS style ACE\n"));
		return status;
	}

	/* MS NFS style gid */
	sid_compose(&sid, &global_sid_Unix_NFS_Groups, fsp->fsp_name->st.st_ex_gid);
	init_sec_ace(&ace, &sid, SEC_ACE_TYPE_ACCESS_DENIED, 0, 0);
	status = security_descriptor_dacl_add(*ppdesc, &ace);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("failed to add MS NFS style ACE\n"));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fruit_fset_nt_acl(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uint32_t security_info_sent,
				  const struct security_descriptor *orig_psd)
{
	NTSTATUS status;
	bool do_chmod;
	mode_t ms_nfs_mode = 0;
	int result;
	struct security_descriptor *psd = NULL;
	uint32_t orig_num_aces = 0;

	if (orig_psd->dacl != NULL) {
		orig_num_aces = orig_psd->dacl->num_aces;
	}

	psd = security_descriptor_copy(talloc_tos(), orig_psd);
	if (psd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("fruit_fset_nt_acl: %s\n", fsp_str_dbg(fsp));

	status = check_ms_nfs(handle, fsp, psd, &ms_nfs_mode, &do_chmod);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("fruit_fset_nt_acl: check_ms_nfs failed%s\n", fsp_str_dbg(fsp)));
		TALLOC_FREE(psd);
		return status;
	}

	/*
	 * If only ms_nfs ACE entries were sent, ensure we set the DACL
	 * sent/present flags correctly now we've removed them.
	 */

	if (orig_num_aces != 0) {
		/*
		 * Are there any ACE's left ?
		 */
		if (psd->dacl->num_aces == 0) {
			/* No - clear the DACL sent/present flags. */
			security_info_sent &= ~SECINFO_DACL;
			psd->type &= ~SEC_DESC_DACL_PRESENT;
		}
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("fruit_fset_nt_acl: SMB_VFS_NEXT_FSET_NT_ACL failed%s\n", fsp_str_dbg(fsp)));
		TALLOC_FREE(psd);
		return status;
	}

	if (do_chmod) {
		if (fsp->fh->fd != -1) {
			result = SMB_VFS_FCHMOD(fsp, ms_nfs_mode);
		} else {
			result = SMB_VFS_CHMOD(fsp->conn,
					       fsp->fsp_name,
					       ms_nfs_mode);
		}

		if (result != 0) {
			DEBUG(1, ("chmod: %s, result: %d, %04o error %s\n", fsp_str_dbg(fsp),
				  result, (unsigned)ms_nfs_mode,
				  strerror(errno)));
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(psd);
			return status;
		}
	}

	TALLOC_FREE(psd);
	return NT_STATUS_OK;
}

static struct vfs_offload_ctx *fruit_offload_ctx;

struct fruit_offload_read_state {
	struct vfs_handle_struct *handle;
	struct tevent_context *ev;
	files_struct *fsp;
	uint32_t fsctl;
	DATA_BLOB token;
};

static void fruit_offload_read_done(struct tevent_req *subreq);

static struct tevent_req *fruit_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct fruit_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct fruit_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct fruit_offload_read_state) {
		.handle = handle,
		.ev = ev,
		.fsp = fsp,
		.fsctl = fsctl,
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
						fsctl, ttl, offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fruit_offload_read_done, req);
	return req;
}

static void fruit_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fruit_offload_read_state *state = tevent_req_data(
		req, struct fruit_offload_read_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
						state->handle,
						state,
						&state->token);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->fsctl != FSCTL_SRV_REQUEST_RESUME_KEY) {
		tevent_req_done(req);
		return;
	}

	status = vfs_offload_token_ctx_init(state->fsp->conn->sconn->client,
					    &fruit_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = vfs_offload_token_db_store_fsp(fruit_offload_ctx,
						state->fsp,
						&state->token);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS fruit_offload_read_recv(struct tevent_req *req,
					struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *token)
{
	struct fruit_offload_read_state *state = tevent_req_data(
		req, struct fruit_offload_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	token->length = state->token.length;
	token->data = talloc_move(mem_ctx, &state->token.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct fruit_offload_write_state {
	struct vfs_handle_struct *handle;
	off_t copied;
	struct files_struct *src_fsp;
	struct files_struct *dst_fsp;
	bool is_copyfile;
};

static void fruit_offload_write_done(struct tevent_req *subreq);
static struct tevent_req *fruit_offload_write_send(struct vfs_handle_struct *handle,
						TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						uint32_t fsctl,
						DATA_BLOB *token,
						off_t transfer_offset,
						struct files_struct *dest_fsp,
						off_t dest_off,
						off_t num)
{
	struct tevent_req *req, *subreq;
	struct fruit_offload_write_state *state;
	NTSTATUS status;
	struct fruit_config_data *config;
	off_t src_off = transfer_offset;
	files_struct *src_fsp = NULL;
	off_t to_copy = num;
	bool copyfile_enabled = false;

	DEBUG(10,("soff: %ju, doff: %ju, len: %ju\n",
		  (uintmax_t)src_off, (uintmax_t)dest_off, (uintmax_t)num));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return NULL);

	req = tevent_req_create(mem_ctx, &state,
				struct fruit_offload_write_state);
	if (req == NULL) {
		return NULL;
	}
	state->handle = handle;
	state->dst_fsp = dest_fsp;

	switch (fsctl) {
	case FSCTL_SRV_COPYCHUNK:
	case FSCTL_SRV_COPYCHUNK_WRITE:
		copyfile_enabled = config->copyfile_enabled;
		break;
	default:
		break;
	}

	/*
	 * Check if this a OS X copyfile style copychunk request with
	 * a requested chunk count of 0 that was translated to a
	 * offload_write_send VFS call overloading the parameters src_off
	 * = dest_off = num = 0.
	 */
	if (copyfile_enabled && num == 0 && src_off == 0 && dest_off == 0) {
		status = vfs_offload_token_db_fetch_fsp(
			fruit_offload_ctx, token, &src_fsp);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		state->src_fsp = src_fsp;

		status = vfs_stat_fsp(src_fsp);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		to_copy = src_fsp->fsp_name->st.st_ex_size;
		state->is_copyfile = true;
	}

	subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle,
					      mem_ctx,
					      ev,
					      fsctl,
					      token,
					      transfer_offset,
					      dest_fsp,
					      dest_off,
					      to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, fruit_offload_write_done, req);
	return req;
}

static void fruit_offload_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fruit_offload_write_state *state = tevent_req_data(
		req, struct fruit_offload_write_state);
	NTSTATUS status;
	unsigned int num_streams = 0;
	struct stream_struct *streams = NULL;
	unsigned int i;
	struct smb_filename *src_fname_tmp = NULL;
	struct smb_filename *dst_fname_tmp = NULL;

	status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(state->handle,
					      subreq,
					      &state->copied);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!state->is_copyfile) {
		tevent_req_done(req);
		return;
	}

	/*
	 * Now copy all remaining streams. We know the share supports
	 * streams, because we're in vfs_fruit. We don't do this async
	 * because streams are few and small.
	 */
	status = vfs_streaminfo(state->handle->conn, state->src_fsp,
				state->src_fsp->fsp_name,
				req, &num_streams, &streams);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (num_streams == 1) {
		/* There is always one stream, ::$DATA. */
		tevent_req_done(req);
		return;
	}

	for (i = 0; i < num_streams; i++) {
		DEBUG(10, ("%s: stream: '%s'/%zu\n",
			  __func__, streams[i].name, (size_t)streams[i].size));

		src_fname_tmp = synthetic_smb_fname(
			req,
			state->src_fsp->fsp_name->base_name,
			streams[i].name,
			NULL,
			state->src_fsp->fsp_name->flags);
		if (tevent_req_nomem(src_fname_tmp, req)) {
			return;
		}

		if (is_ntfs_default_stream_smb_fname(src_fname_tmp)) {
			TALLOC_FREE(src_fname_tmp);
			continue;
		}

		dst_fname_tmp = synthetic_smb_fname(
			req,
			state->dst_fsp->fsp_name->base_name,
			streams[i].name,
			NULL,
			state->dst_fsp->fsp_name->flags);
		if (tevent_req_nomem(dst_fname_tmp, req)) {
			TALLOC_FREE(src_fname_tmp);
			return;
		}

		status = copy_file(req,
				   state->handle->conn,
				   src_fname_tmp,
				   dst_fname_tmp,
				   OPENX_FILE_CREATE_IF_NOT_EXIST,
				   0, false);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("%s: copy %s to %s failed: %s\n", __func__,
				  smb_fname_str_dbg(src_fname_tmp),
				  smb_fname_str_dbg(dst_fname_tmp),
				  nt_errstr(status)));
			TALLOC_FREE(src_fname_tmp);
			TALLOC_FREE(dst_fname_tmp);
			tevent_req_nterror(req, status);
			return;
		}

		TALLOC_FREE(src_fname_tmp);
		TALLOC_FREE(dst_fname_tmp);
	}

	TALLOC_FREE(streams);
	TALLOC_FREE(src_fname_tmp);
	TALLOC_FREE(dst_fname_tmp);
	tevent_req_done(req);
}

static NTSTATUS fruit_offload_write_recv(struct vfs_handle_struct *handle,
				      struct tevent_req *req,
				      off_t *copied)
{
	struct fruit_offload_write_state *state = tevent_req_data(
		req, struct fruit_offload_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(1, ("server side copy chunk failed: %s\n",
			  nt_errstr(status)));
		*copied = 0;
		tevent_req_received(req);
		return status;
	}

	*copied = state->copied;
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static char *fruit_get_bandsize_line(char **lines, int numlines)
{
	static regex_t re;
	static bool re_initialized = false;
	int i;
	int ret;

	if (!re_initialized) {
		ret = regcomp(&re, "^[[:blank:]]*<key>band-size</key>$", 0);
		if (ret != 0) {
			return NULL;
		}
		re_initialized = true;
	}

	for (i = 0; i < numlines; i++) {
		regmatch_t matches[1];

		ret = regexec(&re, lines[i], 1, matches, 0);
		if (ret == 0) {
			/*
			 * Check if the match was on the last line, sa we want
			 * the subsequent line.
			 */
			if (i + 1 == numlines) {
				return NULL;
			}
			return lines[i + 1];
		}
		if (ret != REG_NOMATCH) {
			return NULL;
		}
	}

	return NULL;
}

static bool fruit_get_bandsize_from_line(char *line, size_t *_band_size)
{
	static regex_t re;
	static bool re_initialized = false;
	regmatch_t matches[2];
	uint64_t band_size;
	int ret;
	bool ok;

	if (!re_initialized) {
		ret = regcomp(&re,
			      "^[[:blank:]]*"
			      "<integer>\\([[:digit:]]*\\)</integer>$",
			      0);
		if (ret != 0) {
			return false;
		}
		re_initialized = true;
	}

	ret = regexec(&re, line, 2, matches, 0);
	if (ret != 0) {
		DBG_ERR("regex failed [%s]\n", line);
		return false;
	}

	line[matches[1].rm_eo] = '\0';

	ok = conv_str_u64(&line[matches[1].rm_so], &band_size);
	if (!ok) {
		return false;
	}
	*_band_size = (size_t)band_size;
	return true;
}

/*
 * This reads and parses an Info.plist from a TM sparsebundle looking for the
 * "band-size" key and value.
 */
static bool fruit_get_bandsize(vfs_handle_struct *handle,
			       const char *dir,
			       size_t *band_size)
{
#define INFO_PLIST_MAX_SIZE 64*1024
	char *plist = NULL;
	struct smb_filename *smb_fname = NULL;
	files_struct *fsp = NULL;
	uint8_t *file_data = NULL;
	char **lines = NULL;
	char *band_size_line = NULL;
	size_t plist_file_size;
	ssize_t nread;
	int numlines;
	int ret;
	bool ok = false;
	NTSTATUS status;

	plist = talloc_asprintf(talloc_tos(),
				"%s/%s/Info.plist",
				handle->conn->connectpath,
				dir);
	if (plist == NULL) {
		ok = false;
		goto out;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(), plist, NULL, NULL, 0);
	if (smb_fname == NULL) {
		ok = false;
		goto out;
	}

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	if (ret != 0) {
		DBG_INFO("Ignoring Sparsebundle without Info.plist [%s]\n", dir);
		ok = true;
		goto out;
	}

	plist_file_size = smb_fname->st.st_ex_size;

	if (plist_file_size > INFO_PLIST_MAX_SIZE) {
		DBG_INFO("%s is too large, ignoring\n", plist);
		ok = true;
		goto out;
	}

	status = SMB_VFS_NEXT_CREATE_FILE(
		handle,				/* conn */
		NULL,				/* req */
		0,				/* root_dir_fid */
		smb_fname,			/* fname */
		FILE_GENERIC_READ,		/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE, /* share_access */
		FILE_OPEN,			/* create_disposition */
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,				/* result */
		NULL,				/* psbuf */
		NULL, NULL);			/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("Opening [%s] failed [%s]\n",
			 smb_fname_str_dbg(smb_fname), nt_errstr(status));
		ok = false;
		goto out;
	}

	file_data = talloc_array(talloc_tos(), uint8_t, plist_file_size);
	if (file_data == NULL) {
		ok = false;
		goto out;
	}

	nread = SMB_VFS_NEXT_PREAD(handle, fsp, file_data, plist_file_size, 0);
	if (nread != plist_file_size) {
		DBG_ERR("Short read on [%s]: %zu/%zd\n",
			fsp_str_dbg(fsp), nread, plist_file_size);
		ok = false;
		goto out;

	}

	status = close_file(NULL, fsp, NORMAL_CLOSE);
	fsp = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("close_file failed: %s\n", nt_errstr(status));
		ok = false;
		goto out;
	}

	lines = file_lines_parse((char *)file_data,
				 plist_file_size,
				 &numlines,
				 talloc_tos());
	if (lines == NULL) {
		ok = false;
		goto out;
	}

	band_size_line = fruit_get_bandsize_line(lines, numlines);
	if (band_size_line == NULL) {
		DBG_ERR("Didn't find band-size key in [%s]\n",
			smb_fname_str_dbg(smb_fname));
		ok = false;
		goto out;
	}

	ok = fruit_get_bandsize_from_line(band_size_line, band_size);
	if (!ok) {
		DBG_ERR("fruit_get_bandsize_from_line failed\n");
		goto out;
	}

	DBG_DEBUG("Parsed band-size [%zu] for [%s]\n", *band_size, plist);

out:
	if (fsp != NULL) {
		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("close_file failed: %s\n", nt_errstr(status));
		}
		fsp = NULL;
	}
	TALLOC_FREE(plist);
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(file_data);
	TALLOC_FREE(lines);
	return ok;
}

struct fruit_disk_free_state {
	off_t total_size;
};

static bool fruit_get_num_bands(vfs_handle_struct *handle,
				char *bundle,
				size_t *_nbands)
{
	char *path = NULL;
	struct smb_filename *bands_dir = NULL;
	DIR *d = NULL;
	struct dirent *e = NULL;
	size_t nbands;
	int ret;

	path = talloc_asprintf(talloc_tos(),
			       "%s/%s/bands",
			       handle->conn->connectpath,
			       bundle);
	if (path == NULL) {
		return false;
	}

	bands_dir = synthetic_smb_fname(talloc_tos(),
					path,
					NULL,
					NULL,
					0);
	TALLOC_FREE(path);
	if (bands_dir == NULL) {
		return false;
	}

	d = SMB_VFS_NEXT_OPENDIR(handle, bands_dir, NULL, 0);
	if (d == NULL) {
		TALLOC_FREE(bands_dir);
		return false;
	}

	nbands = 0;

	for (e = SMB_VFS_NEXT_READDIR(handle, d, NULL);
	     e != NULL;
	     e = SMB_VFS_NEXT_READDIR(handle, d, NULL))
	{
		if (ISDOT(e->d_name) || ISDOTDOT(e->d_name)) {
			continue;
		}
		nbands++;
	}

	ret = SMB_VFS_NEXT_CLOSEDIR(handle, d);
	if (ret != 0) {
		TALLOC_FREE(bands_dir);
		return false;
	}

	DBG_DEBUG("%zu bands in [%s]\n", nbands, smb_fname_str_dbg(bands_dir));

	TALLOC_FREE(bands_dir);

	*_nbands = nbands;
	return true;
}

static bool fruit_tmsize_do_dirent(vfs_handle_struct *handle,
				   struct fruit_disk_free_state *state,
				   struct dirent *e)
{
	bool ok;
	char *p = NULL;
	size_t sparsebundle_strlen = strlen("sparsebundle");
	size_t bandsize = 0;
	size_t nbands;
	off_t tm_size;

	p = strstr(e->d_name, "sparsebundle");
	if (p == NULL) {
		return true;
	}

	if (p[sparsebundle_strlen] != '\0') {
		return true;
	}

	DBG_DEBUG("Processing sparsebundle [%s]\n", e->d_name);

	ok = fruit_get_bandsize(handle, e->d_name, &bandsize);
	if (!ok) {
		/*
		 * Beware of race conditions: this may be an uninitialized
		 * Info.plist that a client is just creating. We don't want let
		 * this to trigger complete failure.
		 */
		DBG_ERR("Processing sparsebundle [%s] failed\n", e->d_name);
		return true;
	}

	ok = fruit_get_num_bands(handle, e->d_name, &nbands);
	if (!ok) {
		/*
		 * Beware of race conditions: this may be a backup sparsebundle
		 * in an early stage lacking a bands subdirectory. We don't want
		 * let this to trigger complete failure.
		 */
		DBG_ERR("Processing sparsebundle [%s] failed\n", e->d_name);
		return true;
	}

	if (bandsize > SIZE_MAX/nbands) {
		DBG_ERR("tmsize overflow: bandsize [%zu] nbands [%zu]\n",
			bandsize, nbands);
		return false;
	}
	tm_size = bandsize * nbands;

	if (state->total_size + tm_size < state->total_size) {
		DBG_ERR("tmsize overflow: bandsize [%zu] nbands [%zu]\n",
			bandsize, nbands);
		return false;
	}

	state->total_size += tm_size;

	DBG_DEBUG("[%s] tm_size [%jd] total_size [%jd]\n",
		  e->d_name, (intmax_t)tm_size, (intmax_t)state->total_size);

	return true;
}

/**
 * Calculate used size of a TimeMachine volume
 *
 * This assumes that the volume is used only for TimeMachine.
 *
 * - readdir(basedir of share), then
 * - for every element that matches regex "^\(.*\)\.sparsebundle$" :
 * - parse "\1.sparsebundle/Info.plist" and read the band-size XML key
 * - count band files in "\1.sparsebundle/bands/"
 * - calculate used size of all bands: band_count * band_size
 **/
static uint64_t fruit_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *_bsize,
				uint64_t *_dfree,
				uint64_t *_dsize)
{
	struct fruit_config_data *config = NULL;
	struct fruit_disk_free_state state = {0};
	DIR *d = NULL;
	struct dirent *e = NULL;
	uint64_t dfree;
	uint64_t dsize;
	int ret;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data,
				return UINT64_MAX);

	if (!config->time_machine ||
	    config->time_machine_max_size == 0)
	{
		return SMB_VFS_NEXT_DISK_FREE(handle,
					      smb_fname,
					      _bsize,
					      _dfree,
					      _dsize);
	}

	d = SMB_VFS_NEXT_OPENDIR(handle, smb_fname, NULL, 0);
	if (d == NULL) {
		return UINT64_MAX;
	}

	for (e = SMB_VFS_NEXT_READDIR(handle, d, NULL);
	     e != NULL;
	     e = SMB_VFS_NEXT_READDIR(handle, d, NULL))
	{
		ok = fruit_tmsize_do_dirent(handle, &state, e);
		if (!ok) {
			SMB_VFS_NEXT_CLOSEDIR(handle, d);
			return UINT64_MAX;
		}
	}

	ret = SMB_VFS_NEXT_CLOSEDIR(handle, d);
	if (ret != 0) {
		return UINT64_MAX;
	}

	dsize = config->time_machine_max_size / 512;
	dfree = dsize - (state.total_size / 512);
	if (dfree > dsize) {
		dfree = 0;
	}

	*_bsize = 512;
	*_dsize = dsize;
	*_dfree = dfree;
	return dfree / 2;
}

static struct vfs_fn_pointers vfs_fruit_fns = {
	.connect_fn = fruit_connect,
	.disk_free_fn = fruit_disk_free,

	/* File operations */
	.chmod_fn = fruit_chmod,
	.chown_fn = fruit_chown,
	.unlink_fn = fruit_unlink,
	.rename_fn = fruit_rename,
	.rmdir_fn = fruit_rmdir,
	.open_fn = fruit_open,
	.pread_fn = fruit_pread,
	.pwrite_fn = fruit_pwrite,
	.pread_send_fn = fruit_pread_send,
	.pread_recv_fn = fruit_pread_recv,
	.pwrite_send_fn = fruit_pwrite_send,
	.pwrite_recv_fn = fruit_pwrite_recv,
	.stat_fn = fruit_stat,
	.lstat_fn = fruit_lstat,
	.fstat_fn = fruit_fstat,
	.streaminfo_fn = fruit_streaminfo,
	.ntimes_fn = fruit_ntimes,
	.ftruncate_fn = fruit_ftruncate,
	.fallocate_fn = fruit_fallocate,
	.create_file_fn = fruit_create_file,
	.readdir_attr_fn = fruit_readdir_attr,
	.offload_read_send_fn = fruit_offload_read_send,
	.offload_read_recv_fn = fruit_offload_read_recv,
	.offload_write_send_fn = fruit_offload_write_send,
	.offload_write_recv_fn = fruit_offload_write_recv,

	/* NT ACL operations */
	.fget_nt_acl_fn = fruit_fget_nt_acl,
	.fset_nt_acl_fn = fruit_fset_nt_acl,
};

static_decl_vfs;
NTSTATUS vfs_fruit_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fruit",
					&vfs_fruit_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_fruit_debug_level = debug_add_class("fruit");
	if (vfs_fruit_debug_level == -1) {
		vfs_fruit_debug_level = DBGC_VFS;
		DEBUG(0, ("%s: Couldn't register custom debugging class!\n",
			  "vfs_fruit_init"));
	} else {
		DEBUG(10, ("%s: Debug class number of '%s': %d\n",
			   "vfs_fruit_init","fruit",vfs_fruit_debug_level));
	}

	return ret;
}
