include $(TOPDIR)/rules.mk

PKG_NAME:=ruijie-auth
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Campus network user
PKG_LICENSE:=GPL-3.0-only

include $(INCLUDE_DIR)/package.mk

define Package/ruijie-auth
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Ruijie 802.1X EAP-MD5 client
  DEPENDS:=+libc
endef

define Package/ruijie-auth/description
  Reverse-engineered Ruijie 802.1X EAP-MD5 authentication client
  for campus networks, including the private Ruijie trailer.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/ruijie_auth \
		$(PKG_BUILD_DIR)/ruijie_auth.c -lm
endef

define Package/ruijie-auth/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ruijie_auth $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ruijie-auth.init $(1)/etc/init.d/ruijie-auth
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/ruijie-auth.config $(1)/etc/config/ruijie
endef

$(eval $(call BuildPackage,ruijie-auth))
