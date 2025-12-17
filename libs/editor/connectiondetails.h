/*
    SPDX-FileCopyrightText: 2013-2018 Jan Grulich <jgrulich@redhat.com>
    SPDX-FileCopyrightText: 2025 Alexander Wilms <f.alexander.wilms@gmail.com>

    SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
*/

#ifndef PLASMA_NM_CONNECTION_DETAILS_H
#define PLASMA_NM_CONNECTION_DETAILS_H

#include "plasmanm_editor_export.h"

#include <NetworkManagerQt/Connection>
#include <NetworkManagerQt/Device>

#include <QList>
#include <QPair>
#include <QString>

namespace ConnectionDetails
{

struct ConnectionDetailSection {
    QString title;
    QList<QPair<QString, QString>> details;
};

/**
 * Gets the human-readable network adapter name from a device UDI.
 * Converts the NetworkManager UDI to Solid UDI format and looks up the display name.
 * @param deviceUdi The NetworkManager device UDI (e.g., /sys/devices/...)
 * @return The human-readable adapter name, or empty string if not found.
 */
PLASMANM_EDITOR_EXPORT QString getNetworkAdapterName(const QString &deviceUdi);

/**
 * Extracts detailed information about a network connection.
 * @param connection The NetworkManager connection.
 * @param device The network device.
 * @param cachedAdapterName Optional pre-computed human-readable network adapter name.
 *                          If provided, avoids expensive Solid/udev lookups.
 * @param accessPointPath Optional access point path for disconnected Wi-Fi networks.
 * @return A list of sections, each containing a title and an ordered list of label-value pairs.
 *         The order of sections and details within each section is preserved as defined.
 */
PLASMANM_EDITOR_EXPORT QList<ConnectionDetailSection> getConnectionDetails(const NetworkManager::Connection::Ptr &connection,
                                                                           const NetworkManager::Device::Ptr &device,
                                                                           const QString &cachedAdapterName = QString(),
                                                                           const QString &accessPointPath = QString());
}

#endif // PLASMA_NM_CONNECTION_DETAILS_H
