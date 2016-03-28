#include "lfnetconfigloader.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <QFile>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QAuthenticator>

void LFNetConfigLoader::retrieveConfig()
{
    this->notifyStatus("Loading OpenSSL stuff ...");
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    this->notifyStatus("Generating private key ...");

    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA* key = RSA_new();
    RSA_generate_key_ex(key, 4096, e, NULL);

    this->notifyStatus("Saving private key ...");

    BIO* privateKey = BIO_new_file((_configLocation + "/private.key").toLocal8Bit().data(), "w");
    PEM_write_bio_RSAPrivateKey(privateKey, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(privateKey);

    this->notifyStatus("Generating csr ...");

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, key);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_UTF8, (unsigned char*)"LF-Net", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_UTF8, (unsigned char*)"VPN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (unsigned char*)(_username.toUpper() + "_" + _computerName.toUpper()).toUtf8().data(), -1, -1, 0);

    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_version(req, 1);
    X509_REQ_sign(req, pkey, EVP_sha512());

    BIO* request = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(request, req);

    BUF_MEM* requestData;
    BIO_get_mem_ptr(request, &requestData);

    this->notifyStatus("Request certificate using generated csr ...");

    QNetworkAccessManager *mgr = new QNetworkAccessManager(this);
    connect(mgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(certificateRequestFinished(QNetworkReply*)));
    connect(mgr, SIGNAL(authenticationRequired(QNetworkReply*,QAuthenticator*)), this, SLOT(authenticationRequired(QNetworkReply*,QAuthenticator*)));

    QNetworkRequest netRequest(QUrl("https://mokoscha.lf-net.org/request_certificate"));
    netRequest.setHeader(QNetworkRequest::ContentTypeHeader, "text/plain");

    mgr->post(netRequest, QByteArray(requestData->data, requestData->length));

    this->notifyStatus("Cleaning up temporary data ...");
    BIO_free(request);
    X509_REQ_free(req);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    BN_free(e);

    this->notifyStatus("Waiting for certificate ...");
}

void LFNetConfigLoader::authenticationRequired(QNetworkReply *, QAuthenticator *authenticator) {
    this->notifyStatus("Authentication required ...");
    authenticator->setUser(_username);
    authenticator->setPassword(_password);
}

void LFNetConfigLoader::certificateRequestFinished(QNetworkReply *reply) {
    reply->deleteLater();

    if(reply->error() == QNetworkReply::NoError) {
        this->notifyStatus("Saving signed certificate ...");
        QByteArray certData = reply->readAll();
        QFile certFile(_configLocation + "/certificate.crt", this);
        certFile.open(QFile::WriteOnly);
        certFile.write(certData);
        certFile.close();

        this->notifyStatus("Requesting current configuration ...");

        QNetworkAccessManager* mgr = new QNetworkAccessManager(this);
        connect(mgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(configurationReceived(QNetworkReply*)));
        mgr->get(QNetworkRequest(QUrl("https://mokoscha.lf-net.org/openvpn.conf")));
    }
    else {
        this->notifyStatus("Error while retrieving certificate: " + reply->errorString());
        this->finished();
    }
}

void LFNetConfigLoader::configurationReceived(QNetworkReply* reply) {
    reply->deleteLater();

    if(reply->error() == QNetworkReply::NoError) {
#if WIN32
        QFile configFile(_configLocation + "/lf-net.ovpn");
#else
        QFile configFile(_configLocation + "/lf-net.conf");
#endif
        configFile.open(QFile::WriteOnly);
        configFile.write(reply->readAll());
        configFile.close();

        this->notifyStatus("Requesting current CA certificate ...");

        QNetworkAccessManager* mgr = new QNetworkAccessManager(this);
        connect(mgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(caCertificateReceived(QNetworkReply*)));
        mgr->get(QNetworkRequest(QUrl("https://mokoscha.lf-net.org/ca.crt")));
    }
    else {
        this->notifyStatus("Error while retrieving current configuration file: " + reply->errorString());
        this->finished();
    }
}

void LFNetConfigLoader::caCertificateReceived(QNetworkReply* reply) {
    reply->deleteLater();

    if(reply->error() == QNetworkReply::NoError) {
        QFile caCertFile(_configLocation + "/ca.crt");
        caCertFile.open(QFile::WriteOnly);
        caCertFile.write(reply->readAll());
        caCertFile.close();

        this->notifyStatus("Done. Have fun :)");
        this->finished();
    }
    else {
        this->notifyStatus("Error while retrieving CA certificate: " + reply->errorString());
        this->finished();
    }
}
