#ifndef SINGLEAPP_H
#define SINGLEAPP_H

#include "sdk/tdebug.h"
#include <QObject>
#include <QtNetwork>
#include <QThread>


class SingleApp : public QObject
{
Q_OBJECT
public:
    SingleApp();
    ~SingleApp();
    void test();
    bool isRunning();
    bool run();
signals:
    void newRunner();
private slots:
    void serverNewConnectionHandler();

    void socketReadyReadHandler()
    {
        /*
        QLocalSocket* socket = static_cast<QLocalSocket*>(sender());
        if (socket)
        {
            QTextStream stream(socket);
            qDebug() << "Read Data From Client:" << stream.readAll();

            QString response = "Hello Client";
            socket->write(response.toUtf8());
            socket->flush();
        }
        */
    }
private:
    QLocalServer *server;
};

#endif // SINGLEAPP_H
