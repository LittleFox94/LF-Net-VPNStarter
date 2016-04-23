#-------------------------------------------------
#
# Project created by QtCreator 2016-03-28T17:18:07
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = lf-net-vpnstarter
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    lfnetconfigloader.cpp

HEADERS  += mainwindow.h \
    lfnetconfigloader.h

FORMS    += mainwindow.ui

LIBS     += -lssl -lcrypto
