#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "lfnetconfigloader.h"

#include <QFileDialog>
#include <QHostInfo>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->lineEditComputername->setText(QHostInfo::localHostName());
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButtonBrowseLocation_clicked()
{
    QFileDialog dlg;
    dlg.setFileMode(QFileDialog::DirectoryOnly);
    if(dlg.exec() == QFileDialog::Accepted) {
        ui->lineEditConfigLocation->setText(dlg.selectedFiles().first());
    }
}

void MainWindow::on_pushButtonCreateConfig_clicked()
{
    ui->pushButtonCreateConfig->hide();
    LFNetConfigLoader *loader = new LFNetConfigLoader(ui->lineEditUsername->text(), ui->lineEditPassword->text(), ui->lineEditComputername->text(), ui->lineEditConfigLocation->text(), this);
    connect(loader, SIGNAL(notifyStatus(QString)), ui->statusBar, SLOT(showMessage(QString)));
    connect(loader, SIGNAL(finished()), ui->pushButtonCreateConfig, SLOT(show()));
    loader->retrieveConfig();
}
