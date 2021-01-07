#include "utils/tPrintf.h"

#include <QDir>
#include <QDateTime>
#include <QFileInfo>

#include <QTextStream>

TLOG_LEVEL TPrintf::level = TLOG_DEBUG;
QTextStream TPrintf::logOut(stdout);
QFile TPrintf::logFile("tPrintf.log");
TPrintf::TPrintf()
{
}
TPrintf::~TPrintf()
{
}

bool TPrintf::logConsole = false;
void TPrintf::logToConsole(bool console)
{
    TPrintf::logConsole = console;
}

void TPrintf::writeLogToFile(QString log)
{
    QString infos = QString("" + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + ":" + log + "\n");
    if (TPrintf::logConsole) {
        TPrintf::logOut << infos;
        return;
    }
    if (!TPrintf::logFile.isOpen()) {
        TPrintf::logFile.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Append);
        QString st = QString().sprintf("log file size: %ul", TPrintf::logFile.size());
        qDebug(st.toStdString().c_str());
        if (TPrintf::logFile.size() > 20 * 1024 * 1024) {
            QString toFile = "tPrintf_log_" + QDateTime::currentDateTime().toString("yyyy-MM-dd-hhmmss") + ".txt";
            bool result = TPrintf::logFile.rename(toFile);
            if (result) {
                TPrintf::logFile.close();
                TPrintf::logFile.setFileName("tPrintf.log");
                TPrintf::logFile.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Append);
            } else {
                qErrnoWarning(QString("rename log file failed," + toFile).toStdString().c_str());
            }
        }
    }

    if (TPrintf::logFile.isOpen()) {
        const char *msg = infos.toStdString().c_str();
        TPrintf::logFile.write(msg, qstrlen(msg));
    } else {
        TPrintf::logOut << infos;
    }
    TPrintf::logFile.close();

}

void TPrintf::verbose(QString message)
{
    if (TPrintf::level < TLOG_VERBOSE)
        return;
    qDebug(message.toStdString().c_str());
    writeLogToFile(message);

}
void TPrintf::debug(QString message)
{
    if (TPrintf::level < TLOG_DEBUG)
        return;
    qDebug(message.toStdString().c_str());
    writeLogToFile(message);

}
void TPrintf::info(QString message)
{
    if (TPrintf::level < TLOG_INFO)
        return;
    qInfo(message.toStdString().c_str());
//    writeLogToFile(message);
}
void TPrintf::warning(QString message)
{
    if (TPrintf::level < TLOG_WARNING)
        return;
    qWarning(message.toStdString().c_str());
    writeLogToFile("Warning: " + message);
}
void TPrintf::error(QString message)
{
    if (TPrintf::level < TLOG_ERROR)
        return;
    qErrnoWarning(("Error:" + message).toStdString().c_str());
    writeLogToFile("Error: " + message);
}
void TPrintf::setLogLevel(TLOG_LEVEL level)
{
    TPrintf::level = level;
}
TLOG_LEVEL TPrintf::getLogLevel()
{
    return TPrintf::level;
}
