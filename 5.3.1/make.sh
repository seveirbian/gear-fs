#!/bin/bash

KERNEL_VERSION="5.3.1"
KERNEL_VERSION_EXPAND="linux-5.3.1"
	
make CONFIG_OVERLAY_FS=m -C /usr/src/$KERNEL_VERSION_EXPAND M=/usr/src/$KERNEL_VERSION_EXPAND/fs/overlayfs modules
	
cp /usr/src/$KERNEL_VERSION_EXPAND/fs/overlayfs/overlay.ko /lib/modules/$KERNEL_VERSION/kernel/fs/overlayfs/ 
	
depmod -a