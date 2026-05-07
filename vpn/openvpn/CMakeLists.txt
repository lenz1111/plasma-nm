add_definitions(-DTRANSLATION_DOMAIN=\"plasmanetworkmanagement_openvpnui\")

find_package(PkgConfig REQUIRED)
pkg_check_modules(PKCS11_HELPER REQUIRED IMPORTED_TARGET libpkcs11-helper-1)
pkg_check_modules(P11KIT REQUIRED IMPORTED_TARGET p11-kit-1)

add_library(plasmanetworkmanagement_openvpnui MODULE)
target_sources(plasmanetworkmanagement_openvpnui PRIVATE
    openvpn.cpp
    openvpnwidget.cpp
    openvpnauth.cpp
    openvpnadvancedwidget.cpp
    openvpn.h
    openvpnwidget.h
    openvpnauth.h
    openvpnadvancedwidget.h
)
ecm_qt_declare_logging_category(plasmanetworkmanagement_openvpnui HEADER plasma_nm_openvpn.h IDENTIFIER PLASMA_NM_OPENVPN_LOG CATEGORY_NAME org.kde.plasma.nm.openvpn DESCRIPTION "Plasma NM (openvpn plugins)" EXPORT PLASMANM)
ki18n_wrap_ui(plasmanetworkmanagement_openvpnui openvpn.ui openvpnadvanced.ui)

target_link_libraries(plasmanetworkmanagement_openvpnui
    plasmanm_internal
    plasmanm_editor
    KF6::CoreAddons
    KF6::I18n
    KF6::WidgetsAddons
    KF6::KIOWidgets
    PkgConfig::PKCS11_HELPER
    PkgConfig::P11KIT
)

install(TARGETS plasmanetworkmanagement_openvpnui  DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn)
