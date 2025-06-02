# Nexoedge CIFS

License: GPL 3.0 (Same as Samba)

## How to build the Nexoedge CIFS VFS module for Samba

Platform: Ubuntu 22.04

### Prepare the (client) libraries

Either make the required libraries and header files visible to Samba in the "Global" way or the "Local" way.

#### Global (Recommended)

Link the directory `ncloud/include/` as `/usr/local/include/ncloud`


Link the following libraries built for the Nexoedge prototype (in directory `[Nexoedge build folder]/lib`) to `/usr/local/lib/`

- from `libncloud_zmq.so` -> `/usr/local/lib/libncloud_zmq.so.0`
- from `libzmq.so.5.1.5` -> `/usr/local/lib/libzmq.so.5.1.5`


Create some additional links under `/usr/local/lib`

- from `/usr/local/lib/libzmq.so.5.1.5` -> `/usr/local/lib/libzmq.so.5`
- from `/usr/local/lib/libzmq.so.5` -> `/usr/local/lib/libzmq.so`
- from `/usr/local/lib/libncloud_zmq.so.0` -> `/usr/local/lib/libncloud_zmq.so`


Run `ldconfig -v | grep zmq` as root, and the libraries are listed as follows:

```
        libncloud_zmq.so -> libncloud_zmq.so.0
        libzmq.so.5 -> libzmq.so.5.1.5
```

#### Local (Not recommended)

Create a symbolic link to folder `ncloud/include`
```
$ ln -s [Nexoedge Samba root folder]/ncloud/include [Nexoedge Samba root folder]/ncloud/ncloud
```


Set the environment variables `CFLAGS` and `LDFLAGS` before configuration
```
$ export CFLAGS=-I[Nexoedge Samba root folder]/ncloud
$ export LDFLAGS=-L[Nexoedge build folder]/lib
```

### Compile the source code

1. Change the default python version back to 2.7
```
sudo update-alternatives --install /usr/bin/python python /usr/bin/python2.7 1
```

2. Install packages
```
$ sudo apt install g++ make python2.7-dev libffi-dev liblmdb-dev libjansson-dev libarchive-dev libacl1-dev libldap2-dev
```

3. Configure
```
$ ./configure --without-json-audit --without-ad-dc --without-pam --prefix=[install_dir]
```
Look for `vfs_ncloud` in the following line near the end of configuration messages to confirm the Nexoedge vfs module is included for build:
```
VFS_SHARED: ..., vfs_ncloud
```

4. Compile
```
$ make
```

5. Install
```
$ make install
```

6. Revert the change of default python version
```
sudo update-alternatives --remove python /usr/bin/python2.7
```

### Setup the environment

1. Copy the example configuration to `[install_dir]/samba/etc`
```
$ cp ncloud/example/smb.conf [install_dir]/samba/etc/
```

2. Create the temporary directory and make it accessible
```
$ mkdir /tmp/smb && chmod 777 /tmp/smb
```

3. Run the newly compiled `smbd`
```
$ cd [install_dir]/samba/sbin
$ sudo ./smbd
```

### Setup for first-time use

1. Start the `smbd` service
  - One-time connection (interactive): `$ sudo smbd -i`
  - As daemon: `$ sudo smbd`

2. Add the user that runs the proxy (for logon); Note that the samba password is separated from the OS ones, so the two can be different
```
$ cd [install_dir]/samba/bin
$ pdbedit -a [user]
```

3. If this is built using the "Local" way, link the following libraries of Nexoedge to `[install_dir]/lib`
```
$ ln -s [Nexoedge build folder]/lib/libncloud_zmq.so [install_dir]/lib/
$ ln -s [Nexoedge build folder]/lib/libzmq.so.5.1.5 [install_dir]/lib/
$ cd [install_dir]/lib
$ ln -s libzmq.so.5.1.5 libzmq.so.5
$ ln -s libzmq.so.5 libzmq.so
$ ln -s libncloud_zmq.so.0 libncloud_zmq.so
```

4. Mount the network drive and logon as the user
```
$ cd [install_dir]/samba/bin
$ ./smbclient -U [user] //127.0.0.1/test
```

### Configurations

#### Nexoedge specific parameters

- `ncloud:storage_class`: Storage class for writing files (see Nexoedge storage class definition for details)
- `ncloud:has_external_read_cache`: whether to use local files as read buffers (only possible when co-located with Proxy)
- `ncloud:has_external_write_cache`: whether to use local files as write buffers (only possible when co-located with Proxy)
- `ncloud:namespace_id`: specific namespace id for files; use Proxy's one if not specified
- `ncloud:port`: port number of Proxy's zero-mq interface; its default value is 59001 if not specified 
- `ncloud:ip`: IP of Proxy's zero-mq interface; its default value is "127.0.0.1" if not specified 

#### Useful samba parameters

- `log level`: level of message to print out (most information of Nexoedge VFS module are printed at level 3)
- `smb ports`: the ports to listen on (e.g., change to listen on ports after 1024 without any `sudo`)
- `vfs objects`: specify the stackable vfs modules to run, e.g., `ncloud`, `full_audit`

(More at [samba configuration doc][samba_config])


### Setup samba service using systemd
*Note that the `[install_dir]` has to be `/usr/local` in order to use the follow scripts*

1. Go to folder 'scripts/'
```
$ cd scripts
```

2. Execute the installation script
```
$ sudo bash install.sh
```

### Uninstall the samba service by systemd

1. Go to folder 'scripts/'
```
$ cd scripts
```

2. Execute the uninstallation script
```
$ sudo bash uninstall.sh
```


[samba_config]: https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html
