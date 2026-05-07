/*
    SPDX-FileCopyrightText: 2008 Will Stephenson <wstephenson@kde.org>
    SPDX-FileCopyrightText: 2013 Lukáš Tinkl <ltinkl@redhat.com>

    SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
*/

#include "openvpnwidget.h"
#include "openvpnadvancedwidget.h"
#include "plasma_nm_openvpn.h"

#include <QComboBox>
#include <QDBusMetaType>
#include <QLineEdit>
#include <QPointer>
#include <QUrl>

#include <KProcess>
#include <KUrlRequester>

#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <p11-kit/p11-kit.h>

#include "nm-openvpn-service.h"

static void pkcs11PopulateProviders(QComboBox *combo)
{
    CK_FUNCTION_LIST **modules = p11_kit_modules_load_and_initialize(0);
    if (!modules)
        return;
    for (int i = 0; modules[i] != NULL; i++) {
        int flags = p11_kit_module_get_flags(modules[i]);
        if (flags & P11_KIT_MODULE_TRUSTED)
            continue;
        char *path = p11_kit_module_get_filename(modules[i]);
        if (path) {
            CK_INFO info;
            QString label;
            if (modules[i]->C_GetInfo(&info) == CKR_OK) {
                QString manufacturer = QString::fromLatin1((char *)info.manufacturerID, 32).trimmed();
                QString description = QString::fromLatin1((char *)info.libraryDescription, 32).trimmed();
                if (!manufacturer.isEmpty() && !description.isEmpty())
                    label = manufacturer + QLatin1String(": ") + description;
                else if (!description.isEmpty())
                    label = description;
            }
            combo->addItem(label.isEmpty() ? QString::fromUtf8(path) : label, QString::fromUtf8(path));
            free(path);
        }
    }
    p11_kit_modules_finalize_and_release(modules);
}

static void pkcs11PopulateIds(QComboBox *combo, const QString &providerPath)
{
    combo->clear();
    combo->addItem(QString());
    if (providerPath.isEmpty())
        return;

    QByteArray path = providerPath.toUtf8();
    if (pkcs11h_initialize() != CKR_OK)
        return;
    pkcs11h_setLogLevel(0);

    if (pkcs11h_addProvider(path.constData(), path.constData(), TRUE, 0,
                            PKCS11H_SLOTEVENT_METHOD_AUTO, 0, FALSE) != CKR_OK) {
        pkcs11h_terminate();
        return;
    }

    pkcs11h_certificate_id_list_t certs = NULL;
    if (pkcs11h_certificate_enumCertificateIds(
            PKCS11H_ENUM_METHOD_CACHE_EXIST, NULL,
            PKCS11H_PROMPT_MASK_ALLOW_ALL, NULL, &certs) == CKR_OK) {
        for (auto cur = certs; cur != NULL; cur = cur->next) {
            size_t ser_len = 0;
            if (pkcs11h_certificate_serializeCertificateId(NULL, &ser_len, cur->certificate_id) != CKR_OK)
                continue;
            char *ser = (char *)malloc(ser_len);
            if (!ser) continue;
            if (pkcs11h_certificate_serializeCertificateId(ser, &ser_len, cur->certificate_id) == CKR_OK)
                combo->addItem(QString::fromUtf8(ser));
            free(ser);
        }
        pkcs11h_certificate_freeCertificateIdList(certs);
    }

    pkcs11h_removeProvider(path.constData());
    pkcs11h_terminate();
}

class OpenVpnSettingWidget::Private
{
public:
    Ui_OpenVPNProp ui;
    NetworkManager::VpnSetting::Ptr setting;
    class EnumConnectionType
    {
    public:
        enum ConnectionType {
            Certificates = 0,
            Psk,
            Password,
            CertsPassword,
            Pkcs11
        };
    };
    class EnumKeyDirection
    {
    public:
        enum KeyDirection {
            None = 0,
            D0,
            D1
        };
    };
};

OpenVpnSettingWidget::OpenVpnSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : SettingWidget(setting, parent)
    , d(new Private)
{
    qDBusRegisterMetaType<NMStringMap>();

    d->ui.setupUi(this);
    d->setting = setting;

    d->ui.x509KeyPassword->setPasswordOptionsEnabled(true);
    d->ui.x509KeyPassword->setPasswordNotRequiredEnabled(true);
    d->ui.passPassword->setPasswordOptionsEnabled(true);
    d->ui.passPassword->setPasswordNotRequiredEnabled(true);
    d->ui.x509PassKeyPassword->setPasswordOptionsEnabled(true);
    d->ui.x509PassKeyPassword->setPasswordNotRequiredEnabled(true);
    d->ui.x509PassPassword->setPasswordOptionsEnabled(true);
    d->ui.x509PassPassword->setPasswordNotRequiredEnabled(true);
    d->ui.pkcs11Pin->setPasswordOptionsEnabled(true);
    d->ui.pkcs11Pin->setPasswordNotRequiredEnabled(false);

    // Populate PKCS#11 providers and connect signal
    d->ui.pkcs11Providers->addItem(QString());
    pkcs11PopulateProviders(d->ui.pkcs11Providers);
    connect(d->ui.pkcs11Providers, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() {
        pkcs11PopulateIds(d->ui.pkcs11Id, d->ui.pkcs11Providers->currentData().toString());
    });

    // use requesters' urlSelected signals to set other requester's startDirs to save clicking
    // around the filesystem
    QList<const KUrlRequester *> requesters{
        d->ui.x509CaFile,
        d->ui.x509Cert,
        d->ui.x509Key,
        d->ui.pskSharedKey,
        d->ui.passCaFile,
        d->ui.x509PassCaFile,
        d->ui.x509PassCert,
        d->ui.x509PassKey,
        d->ui.pkcs11CaFile
    };
    for (const KUrlRequester *requester : requesters) {
        connect(requester, &KUrlRequester::urlSelected, this, &OpenVpnSettingWidget::updateStartDir);
    }

    connect(d->ui.btnAdvanced, &QPushButton::clicked, this, &OpenVpnSettingWidget::showAdvanced);

    // Connect for setting check
    watchChangedSetting();

    // Connect for validity check
    connect(d->ui.gateway, &QLineEdit::textChanged, this, &OpenVpnSettingWidget::slotWidgetChanged);
    connect(d->ui.cmbConnectionType, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &OpenVpnSettingWidget::slotWidgetChanged);
    connect(d->ui.pkcs11Providers, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &OpenVpnSettingWidget::slotWidgetChanged);
    connect(d->ui.pkcs11Id, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &OpenVpnSettingWidget::slotWidgetChanged);

    KAcceleratorManager::manage(this);

    if (setting && !setting->isNull()) {
        loadConfig(d->setting);
    }
}

OpenVpnSettingWidget::~OpenVpnSettingWidget()
{
    delete d;
}

void OpenVpnSettingWidget::loadConfig(const NetworkManager::Setting::Ptr &setting)
{
    Q_UNUSED(setting)

    // General settings
    const NMStringMap dataMap = d->setting->data();
    const QString cType = dataMap.value(NM_OPENVPN_KEY_CONNECTION_TYPE);

    if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
        d->ui.cmbConnectionType->setCurrentIndex(Private::EnumConnectionType::CertsPassword);
        d->ui.x509PassUsername->setText(dataMap[NM_OPENVPN_KEY_USERNAME]);
        d->ui.x509PassCaFile->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CA]));
        d->ui.x509PassCert->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CERT]));
        d->ui.x509PassKey->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_KEY]));
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_STATIC_KEY)) {
        d->ui.cmbConnectionType->setCurrentIndex(Private::EnumConnectionType::Psk);
        d->ui.pskSharedKey->setText(dataMap[NM_OPENVPN_KEY_STATIC_KEY]);
        if (dataMap.contains(NM_OPENVPN_KEY_STATIC_KEY_DIRECTION)) {
            switch (dataMap[NM_OPENVPN_KEY_STATIC_KEY_DIRECTION].toUInt()) {
            case 0:
                d->ui.cmbKeyDirection->setCurrentIndex(Private::EnumKeyDirection::D0);
                break;
            case 1:
                d->ui.cmbKeyDirection->setCurrentIndex(Private::EnumKeyDirection::D1);
                break;
            }
        } else {
            d->ui.cmbKeyDirection->setCurrentIndex(Private::EnumKeyDirection::None);
        }
        d->ui.pskRemoteIp->setText(dataMap[NM_OPENVPN_KEY_REMOTE_IP]);
        d->ui.pskLocalIp->setText(dataMap[NM_OPENVPN_KEY_LOCAL_IP]);
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD)) {
        d->ui.cmbConnectionType->setCurrentIndex(Private::EnumConnectionType::Password);
        d->ui.passUserName->setText(dataMap[NM_OPENVPN_KEY_USERNAME]);
        d->ui.passCaFile->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CA]));
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_TLS)) {
        d->ui.cmbConnectionType->setCurrentIndex(Private::EnumConnectionType::Certificates);
        d->ui.x509CaFile->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CA]));
        d->ui.x509Cert->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CERT]));
        d->ui.x509Key->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_KEY]));
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PKCS11)) {
        d->ui.cmbConnectionType->setCurrentIndex(Private::EnumConnectionType::Pkcs11);
        d->ui.pkcs11CaFile->setUrl(QUrl::fromLocalFile(dataMap[NM_OPENVPN_KEY_CA]));
        QString prov = QString(dataMap[NM_OPENVPN_KEY_PKCS11_PROVIDERS]).replace(QLatin1String("\\\\"), QLatin1String("\\"));
        int provIdx = d->ui.pkcs11Providers->findData(prov);
        if (provIdx >= 0) {
            d->ui.pkcs11Providers->blockSignals(true);
            d->ui.pkcs11Providers->setCurrentIndex(provIdx);
            d->ui.pkcs11Providers->blockSignals(false);
            pkcs11PopulateIds(d->ui.pkcs11Id, prov);
            QString id = QString(dataMap[NM_OPENVPN_KEY_PKCS11_ID]).replace(QLatin1String("\\\\"), QLatin1String("\\"));
            int idIdx = d->ui.pkcs11Id->findText(id);
            if (idIdx < 0) {
                /* ID not found in enumerated list — add it anyway,
                 * the PKCS#11 device may be unplugged. */
                d->ui.pkcs11Id->addItem(id);
                idIdx = d->ui.pkcs11Id->count() - 1;
            }
            d->ui.pkcs11Id->setCurrentIndex(idIdx);
        }
    }

    d->ui.gateway->setText(dataMap[NM_OPENVPN_KEY_REMOTE]);

    NetworkManager::Setting::SecretFlags type;

    if (cType == QLatin1String(NM_OPENVPN_CONTYPE_TLS)) {
        type = (NetworkManager::Setting::SecretFlags)dataMap[NM_OPENVPN_KEY_CERTPASS "-flags"].toInt();
        fillOnePasswordCombo(d->ui.x509KeyPassword, type);
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD)) {
        type = (NetworkManager::Setting::SecretFlags)dataMap[NM_OPENVPN_KEY_PASSWORD "-flags"].toInt();
        fillOnePasswordCombo(d->ui.passPassword, type);
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
        type = (NetworkManager::Setting::SecretFlags)dataMap[NM_OPENVPN_KEY_PASSWORD "-flags"].toInt();
        fillOnePasswordCombo(d->ui.x509PassPassword, type);
        type = (NetworkManager::Setting::SecretFlags)dataMap[NM_OPENVPN_KEY_CERTPASS "-flags"].toInt();
        fillOnePasswordCombo(d->ui.x509PassKeyPassword, type);
    } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PKCS11)) {
        type = (NetworkManager::Setting::SecretFlags)dataMap[NM_OPENVPN_KEY_CERTPASS "-flags"].toInt();
        fillOnePasswordCombo(d->ui.pkcs11Pin, type);
    }

    loadSecrets(setting);
}

void OpenVpnSettingWidget::loadSecrets(const NetworkManager::Setting::Ptr &setting)
{
    NetworkManager::VpnSetting::Ptr vpnSetting = setting.staticCast<NetworkManager::VpnSetting>();

    if (vpnSetting) {
        const QString cType = d->setting->data().value(NM_OPENVPN_KEY_CONNECTION_TYPE);
        const NMStringMap secrets = vpnSetting->secrets();

        if (cType == QLatin1String(NM_OPENVPN_CONTYPE_TLS)) {
            d->ui.x509KeyPassword->setText(secrets.value(NM_OPENVPN_KEY_CERTPASS));
        } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD)) {
            d->ui.passPassword->setText(secrets.value(NM_OPENVPN_KEY_PASSWORD));
        } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
            d->ui.x509PassPassword->setText(secrets.value(NM_OPENVPN_KEY_PASSWORD));
            d->ui.x509PassKeyPassword->setText(secrets.value(NM_OPENVPN_KEY_CERTPASS));
        } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PKCS11)) {
            d->ui.pkcs11Pin->setText(secrets.value(NM_OPENVPN_KEY_CERTPASS));
        }
    }
}

QVariantMap OpenVpnSettingWidget::setting() const
{
    NMStringMap data = d->setting->data();
    NMStringMap secretData = d->setting->secrets();
    NetworkManager::VpnSetting setting;
    setting.setServiceType(QLatin1String(NM_DBUS_SERVICE_OPENVPN));
    // required settings
    data.insert(QLatin1String(NM_OPENVPN_KEY_REMOTE), d->ui.gateway->text());

    QString contype;

    switch (d->ui.cmbConnectionType->currentIndex()) {
    case Private::EnumConnectionType::Certificates:
        contype = QLatin1String(NM_OPENVPN_CONTYPE_TLS);
        // qCDebug(PLASMA_NM_OPENVPN_LOG) << "saving VPN TLS settings as urls:" << d->ui.x509CaFile->url() << d->ui.x509Cert->url() << d->ui.x509Key->url();
        data.insert(QLatin1String(NM_OPENVPN_KEY_CA), d->ui.x509CaFile->url().toLocalFile());
        data.insert(QLatin1String(NM_OPENVPN_KEY_CERT), d->ui.x509Cert->url().toLocalFile());
        data.insert(QLatin1String(NM_OPENVPN_KEY_KEY), d->ui.x509Key->url().toLocalFile());
        // key password
        if (!d->ui.x509KeyPassword->text().isEmpty()) {
            secretData.insert(QLatin1String(NM_OPENVPN_KEY_CERTPASS), d->ui.x509KeyPassword->text());
        } else {
            secretData.remove(QLatin1String(NM_OPENVPN_KEY_CERTPASS));
        }
        handleOnePasswordType(d->ui.x509KeyPassword, QLatin1String(NM_OPENVPN_KEY_CERTPASS "-flags"), data);
        break;
    case Private::EnumConnectionType::Psk:
        contype = QLatin1String(NM_OPENVPN_CONTYPE_STATIC_KEY);
        data.insert(QLatin1String(NM_OPENVPN_KEY_STATIC_KEY), d->ui.pskSharedKey->url().toLocalFile());
        switch (d->ui.cmbKeyDirection->currentIndex()) {
        case Private::EnumKeyDirection::None:
            break;
        case Private::EnumKeyDirection::D0:
            data.insert(QLatin1String(NM_OPENVPN_KEY_STATIC_KEY_DIRECTION), QString::number(0));
            break;
        case Private::EnumKeyDirection::D1:
            data.insert(QLatin1String(NM_OPENVPN_KEY_STATIC_KEY_DIRECTION), QString::number(1));
            break;
        }
        // ip addresses
        data.insert(QLatin1String(NM_OPENVPN_KEY_REMOTE_IP), d->ui.pskRemoteIp->text());
        data.insert(QLatin1String(NM_OPENVPN_KEY_LOCAL_IP), d->ui.pskLocalIp->text());
        break;
    case Private::EnumConnectionType::Password:
        contype = QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD);
        // username
        if (!d->ui.passUserName->text().isEmpty()) {
            data.insert(QLatin1String(NM_OPENVPN_KEY_USERNAME), d->ui.passUserName->text());
        } else {
            data.remove(QLatin1String(NM_OPENVPN_KEY_USERNAME));
        }
        // password
        if (!d->ui.passPassword->text().isEmpty()) {
            secretData.insert(QLatin1String(NM_OPENVPN_KEY_PASSWORD), d->ui.passPassword->text());
        } else {
            secretData.remove(QLatin1String(NM_OPENVPN_KEY_PASSWORD));
        }
        handleOnePasswordType(d->ui.passPassword, QLatin1String(NM_OPENVPN_KEY_PASSWORD "-flags"), data);
        // ca
        data.insert(QLatin1String(NM_OPENVPN_KEY_CA), d->ui.passCaFile->url().toLocalFile());
        break;
    case Private::EnumConnectionType::CertsPassword:
        contype = QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD_TLS);
        // username
        if (!d->ui.x509PassUsername->text().isEmpty()) {
            data.insert(QLatin1String(NM_OPENVPN_KEY_USERNAME), d->ui.x509PassUsername->text());
        } else {
            data.remove(QLatin1String(NM_OPENVPN_KEY_USERNAME));
        }
        // ca
        data.insert(QLatin1String(NM_OPENVPN_KEY_CA), d->ui.x509PassCaFile->url().toLocalFile());
        // cert
        data.insert(QLatin1String(NM_OPENVPN_KEY_CERT), d->ui.x509PassCert->url().toLocalFile());
        // key file
        data.insert(QLatin1String(NM_OPENVPN_KEY_KEY), d->ui.x509PassKey->url().toLocalFile());
        // key password
        if (!d->ui.x509PassKeyPassword->text().isEmpty()) {
            secretData.insert(QLatin1String(NM_OPENVPN_KEY_CERTPASS), d->ui.x509PassKeyPassword->text());
        } else {
            secretData.remove(QLatin1String(NM_OPENVPN_KEY_CERTPASS));
        }
        handleOnePasswordType(d->ui.x509PassKeyPassword, QLatin1String(NM_OPENVPN_KEY_CERTPASS "-flags"), data);
        // password
        if (!d->ui.x509PassPassword->text().isEmpty()) {
            secretData.insert(QLatin1String(NM_OPENVPN_KEY_PASSWORD), d->ui.x509PassPassword->text());
        } else {
            secretData.remove(QLatin1String(NM_OPENVPN_KEY_PASSWORD));
        }
        handleOnePasswordType(d->ui.x509PassPassword, QLatin1String(NM_OPENVPN_KEY_PASSWORD "-flags"), data);
        break;
    case Private::EnumConnectionType::Pkcs11:
        contype = QLatin1String(NM_OPENVPN_CONTYPE_PKCS11);
        // ca
        data.insert(QLatin1String(NM_OPENVPN_KEY_CA), d->ui.pkcs11CaFile->url().toLocalFile());
        // pkcs11
        if (!d->ui.pkcs11Providers->currentData().toString().isEmpty()) {
            data.insert(QLatin1String(NM_OPENVPN_KEY_PKCS11_PROVIDERS), QString(d->ui.pkcs11Providers->currentData().toString()).replace(QLatin1String("\\"), QLatin1String("\\\\")));
        } else {
            data.remove(QLatin1String(NM_OPENVPN_KEY_PKCS11_PROVIDERS));
        }
        if (!d->ui.pkcs11Id->currentText().isEmpty()) {
            data.insert(QLatin1String(NM_OPENVPN_KEY_PKCS11_ID), QString(d->ui.pkcs11Id->currentText()).replace(QLatin1String("\\"), QLatin1String("\\\\")));
        } else {
            data.remove(QLatin1String(NM_OPENVPN_KEY_PKCS11_ID));
        }
        // key password
        if (!d->ui.pkcs11Pin->text().isEmpty()) {
            secretData.insert(QLatin1String(NM_OPENVPN_KEY_CERTPASS), d->ui.pkcs11Pin->text());
        } else {
            secretData.remove(QLatin1String(NM_OPENVPN_KEY_CERTPASS));
        }
        handleOnePasswordType(d->ui.pkcs11Pin, QLatin1String(NM_OPENVPN_KEY_CERTPASS "-flags"), data);
        break;
    }
    data.insert(QLatin1String(NM_OPENVPN_KEY_CONNECTION_TYPE), contype);

    setting.setData(data);
    setting.setSecrets(secretData);

    return setting.toMap();
}

void OpenVpnSettingWidget::updateStartDir(const QUrl &url)
{
    QList<KUrlRequester *> requesters;
    requesters << d->ui.x509CaFile << d->ui.x509Cert << d->ui.x509Key << d->ui.pskSharedKey << d->ui.passCaFile << d->ui.x509PassCaFile << d->ui.x509PassCert
               << d->ui.x509PassKey << d->ui.pkcs11CaFile;
    for (KUrlRequester *requester : std::as_const(requesters)) {
        requester->setStartDir(url.adjusted(QUrl::RemoveFilename | QUrl::StripTrailingSlash));
    }
}

void OpenVpnSettingWidget::setPasswordType(QLineEdit *edit, int type)
{
    edit->setEnabled(type == SettingWidget::EnumPasswordStorageType::Store);
}

void OpenVpnSettingWidget::fillOnePasswordCombo(PasswordField *passwordField, NetworkManager::Setting::SecretFlags type)
{
    if (type.testFlag(NetworkManager::Setting::None)) {
        passwordField->setPasswordOption(PasswordField::StoreForAllUsers);
    } else if (type.testFlag(NetworkManager::Setting::AgentOwned)) {
        passwordField->setPasswordOption(PasswordField::StoreForUser);
    } else if (type.testFlag(NetworkManager::Setting::NotSaved)) {
        passwordField->setPasswordOption(PasswordField::AlwaysAsk);
    } else if (type.testFlag(NetworkManager::Setting::NotRequired)) {
        passwordField->setPasswordOption(PasswordField::NotRequired);
    }
}

void OpenVpnSettingWidget::handleOnePasswordType(const PasswordField *passwordField, const QString &key, NMStringMap &data) const
{
    const PasswordField::PasswordOption option = passwordField->passwordOption();
    switch (option) {
    case PasswordField::StoreForAllUsers:
        data.insert(key, QString::number(NetworkManager::Setting::None));
        break;
    case PasswordField::StoreForUser:
        data.insert(key, QString::number(NetworkManager::Setting::AgentOwned));
        break;
    case PasswordField::AlwaysAsk:
        data.insert(key, QString::number(NetworkManager::Setting::NotSaved));
        break;
    case PasswordField::NotRequired:
        data.insert(key, QString::number(NetworkManager::Setting::NotRequired));
        break;
    }
}

void OpenVpnSettingWidget::showAdvanced()
{
    QPointer<OpenVpnAdvancedWidget> adv = new OpenVpnAdvancedWidget(d->setting, this);
    adv->setAttribute(Qt::WA_DeleteOnClose);
    adv->init();
    connect(adv.data(), &OpenVpnAdvancedWidget::accepted, [adv, this]() {
        NetworkManager::VpnSetting::Ptr advData = adv->setting();
        if (!advData.isNull()) {
            d->setting->setData(advData->data());
            d->setting->setSecrets(advData->secrets());
        }
    });
    adv->setModal(true);
    adv->show();
}

bool OpenVpnSettingWidget::isValid() const
{
    if (d->ui.gateway->text().isEmpty())
        return false;
    if (d->ui.cmbConnectionType->currentIndex() == Private::EnumConnectionType::Pkcs11) {
        if (d->ui.pkcs11Providers->currentData().toString().isEmpty())
            return false;
        if (d->ui.pkcs11Id->currentText().isEmpty())
            return false;
    }
    return true;
}

#include "moc_openvpnwidget.cpp"
