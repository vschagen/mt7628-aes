#
# Copyright (C) 2006-2017 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mt7628_aes
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/crypto-hw-mt7628-aes/Default
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Cryptographic API modules
endef

define KernelPackage/crypto-hw-mt7628-aes
  $(call Package/crypto-hw-mt7628-aes/Default)
  SECTION:=kernel
  TITLE:=Kernel driver for HW AES ENGINE MT7628
  KCONFIG:= 
  FILES:=$(PKG_BUILD_DIR)/crypto-hw-mt7628-aes.ko
endef

define KernelPackage/crypto-hw-mt7628-aes/description
 New and improved full asynchronous Kernel module to enable
 AES HW Crypto Engine on the Mediatek MT76x8 (AES-128/192/256 EBC/CBC).
endef
  
define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
        CROSS_COMPILE="$(TARGET_CROSS)" \
        ARCH="$(LINUX_KARCH)" \
        SUBDIRS="$(PKG_BUILD_DIR)" \
        EXTRA_CFLAGS="$(BUILDFLAGS)" \
        modules
endef

$(eval $(call KernelPackage,crypto-hw-mt7628-aes))