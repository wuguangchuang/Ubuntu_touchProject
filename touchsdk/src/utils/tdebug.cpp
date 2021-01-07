#include "utils/tdebug.h"

#include <QDir>
#include <QDateTime>
#include <QFileInfo>

#include <QTextStream>

TLOG_LEVEL TDebug::level = TLOG_DEBUG;
QTextStream TDebug::logOut(stdout);
QFile TDebug::logFile("touch.log");
TDebug::TDebug()
{
}
TDebug::~TDebug()
{
}

bool TDebug::logConsole = false;
void TDebug::logToConsole(bool console)
{
    TDebug::logConsole = console;
}

void TDebug::writeLogToFile(QString log)
{
    QString infos = QString("" + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + ":" + log + "\n");
    if (TDebug::logConsole) {
        TDebug::logOut << infos;
        return;
    }
    if (!TDebug::logFile.isOpen()) {
        TDebug::logFile.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Append);
        QString st = QString().sprintf("log file size: %ul", TDebug::logFile.size());
        qDebug(st.toStdString().c_str());
        if (TDebug::logFile.size() > 20 * 1024 * 1024) {
            QString toFile = "touch_log_" + QDateTime::currentDateTime().toString("yyyy-MM-dd-hhmmss") + ".txt";
            bool result = TDebug::logFile.rename(toFile);
            if (result) {
                TDebug::logFile.close();
                TDebug::logFile.setFileName("touch.log");
                TDebug::logFile.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Append);
            } else {
                qErrnoWarning(QString("rename log file failed," + toFile).toStdString().c_str());
            }
        }
    }

    if (TDebug::logFile.isOpen()) {
        const char *msg = infos.toStdString().c_str();
        TDebug::logFile.write(msg, qstrlen(msg));
    } else {
        TDebug::logOut << infos;
    }

}

void TDebug::verbose(QString message)
{
    if (TDebug::level < TLOG_VERBOSE)
        return;
    qDebug(message.toStdString().c_str());
    writeLogToFile(message);

}
void TDebug::debug(QString message)
{
    if (TDebug::level < TLOG_DEBUG)
        return;
    qDebug(message.toStdString().c_str());
    writeLogToFile(message);

}
void TDebug::info(QString message)
{
    if (TDebug::level < TLOG_INFO)
        return;
    qInfo(message.toStdString().c_str());
//    writeLogToFile(message);
}
void TDebug::warning(QString message)
{
    if (TDebug::level < TLOG_WARNING)
        return;
    qWarning(message.toStdString().c_str());
    writeLogToFile("Warning: " + message);
}
void TDebug::error(QString message)
{
    if (TDebug::level < TLOG_ERROR)
        return;
    qErrnoWarning(("Error:" + message).toStdString().c_str());
    writeLogToFile("Error: " + message);
}
void TDebug::setLogLevel(TLOG_LEVEL level)
{
    TDebug::level = level;
}
TLOG_LEVEL TDebug::getLogLevel()
{
    return TDebug::level;
}
