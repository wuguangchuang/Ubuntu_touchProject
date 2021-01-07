#include "include/singleapp.h"

SingleApp::SingleApp()
{
}

SingleApp::~SingleApp()
{
}

bool SingleApp::isRunning()
{
    QLocalSocket *socket = new QLocalSocket(this);
    socket->connectToServer("touchassistant");
    bool a = socket->waitForConnected(1000);
    socket->close();
    delete socket;
    TINFO("isRunning: %d", a ? 1 : 0);
    return a;
}

void SingleApp::serverNewConnectionHandler()
{
    TINFO("new connect");
    QLocalSocket* socket = server->nextPendingConnection();
    QObject::connect(socket, SIGNAL(readyRead()), this, SLOT(socketReadyReadHandler()));
    QObject::connect(socket, SIGNAL(disconnected()), socket, SLOT(deleteLater()));
    emit newRunner();
}


bool SingleApp::run()
{
    if (isRunning())
        return false;
    TINFO("run server");
    server = new QLocalServer(this);
    QObject::connect(server, SIGNAL(newConnection()), this, SLOT(serverNewConnectionHandler()));
    QLocalServer::removeServer("touchassistant");
    server->listen("touchassistant");
    return true;
}

void SingleApp::test()
{
    TINFO("###############################");
    server = new QLocalServer(this);
    QObject::connect(server, SIGNAL(newConnection()), this, SLOT(serverNewConnectionHandler()));
    QLocalServer::removeServer("touchassistant_test");
    server->listen("touchassistant_test");
    QLocalSocket *socket = new QLocalSocket(this);
    socket->connectToServer("touchassistant_test");
    bool a = socket->waitForConnected(3000);//等待连接
    socket->close();
    delete socket;
    delete server;
    TINFO("connect to sever: %d", (a ? 1 : 0));
}
