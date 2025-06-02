#/* 
# * Nexoedge SMB/CIFS 
# * Nexoedge SMB/CIFS service and vfs module uninstallation script.
# * Copyright (C) Helen Chan 2019-2025
# *
# * This program is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 3 of the License, or
# * (at your option) any later version.
# *  
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *  
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, see <http://www.gnu.org/licenses/>.
# */
#
#!/bin/bash

# check for root permission
if [ $UID -ne 0 ]; then
    echo "Please run the script as root"
    exit 1
fi

# stop the service
systemctl stop ncloud-cifs
# remove the service
systemctl disable ncloud-cifs
# remove the service script
rm /etc/systemd/system/ncloud-cifs.service
# reload service daemon
systemctl daemon-reload

