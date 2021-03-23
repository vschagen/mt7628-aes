#
# Copyright (C) 2006-2017 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=crypto-hw-mtk-aes
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/crypto-hw-mtk-aes
  SECTION:=kernel
  SUBMENU:=Cryptographic API modules
  TITLE:=Kernel driver for Mediatek MT76x8 aes engine.
  DEPENDS:=@TARGET_ramips_mt76x8
  FILES:=$(PKG_BUILD_DIR)/crypto-hw-mtk-aes.ko
  AUTOLOAD:=$(call AutoProbe,crypto-hw-mtk-aes)
  $(call AddDepends/crypto)
endef

define KernelPackage/crypto-hw-mtk-aes/config
	select CRYPTO_HW
endef

define KernelPackage/crypto-hw-mtk-aes/description
 Kernel module to enable AES HW Crypto Engine on the Mediatek MT76x8
 (AES-128/192/256 EBC/CBC).
endef

define Build/Compile
  $(KERNEL_MAKE) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,crypto-hw-mtk-aes))
