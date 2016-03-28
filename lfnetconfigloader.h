#ifndef LFNETCONFIGLOADER_H
#define LFNETCONFIGLOADER_H

#include <QObject>
#include <QString>
#include <QtNetwork/QNetworkReply>

class LFNetConfigLoader : public QObject
{
    Q_OBJECT
public:
    explicit LFNetConfigLoader(QString username, QString password, QString computerName, QString configLocation, QObject *parent = 0)
        : QObject(parent), _username(username), _password(password), _computerName(computerName), _configLocation(configLocation) {
    }

    void retrieveConfig();

private:
    QString _username;
    QString _password;
    QString _computerName;
    QString _configLocation;

private slots:
    void certificateRequestFinished(QNetworkReply* reply);
    void configurationReceived(QNetworkReply* reply);
    void caCertificateReceived(QNetworkReply* reply);
    void authenticationRequired(QNetworkReply* reply, QAuthenticator* authenticator);

signals:
    void notifyStatus(QString status);
    void finished();
};

#endif // LFNETCONFIGLOADER_H
