include $(TOPDIR)/rules.mk

PKG_NAME:=avro-c
#PKG_VERSION:=1.8.2
PKG_VERSION:=1.11.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=@APACHE/avro/avro-$(PKG_VERSION)/c
PKG_SOURCE_URL:=https://downloads.apache.org/avro/avro-$(PKG_VERSION)/c
#PKG_HASH:=4639982b2b8fbd91fc7128fef672207129c959bb7900dd64b077ce4206edf10e
PKG_HASH:=7217caacfb7d5f34611766473a66c2e279bc7bfaf1ba298c7f04b3b2fba57365

PKG_MAINTAINER:=John Clark <inindev@gmail.com>

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/avro-c
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:=+jansson +zlib +liblzma
  TITLE:=Apache Avro C Library
  URL:=https://avro.apache.org
endef

define Package/avro-c/description
  This package contains the Apache Avro C library.
endef

CMAKE_OPTIONS += \
        -DCMAKE_BUILD_TYPE:STRING=MINSIZEREL

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/{lib,include}
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libavro.{a,so*} $(1)/usr/lib/
endef

define Package/avro-c/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libavro.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,avro-c))

