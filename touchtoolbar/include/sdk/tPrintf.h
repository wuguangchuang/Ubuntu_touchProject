#ifndef TPRINTFG_H
#define TPRINTFG_H

#include <QDebug>
#include <QFile>
#include <QIODevice>
#include <QTextStream>

#include "/home/xjf/Desktop/touchProject/touch/touchsdk/include/touch_global.h"
#include "tdebug.h"

//#if defined(TOUCH_LIBRARY)
//#  define TOUCHSHARED_EXPORT Q_DECL_EXPORT
//#else
//#  define TOUCHSHARED_EXPORT Q_DECL_IMPORT
//#endif
class TPrintf
{
public:
    TOUCHSHARED_EXPORT TPrintf();
    TOUCHSHARED_EXPORT ~TPrintf();

    TOUCHSHARED_EXPORT static  void debug(QString message);
    TOUCHSHARED_EXPORT static void info(QString message);
    TOUCHSHARED_EXPORT static void warning(QString message);
    TOUCHSHARED_EXPORT static void error(QString message);
    TOUCHSHARED_EXPORT static void verbose(QString message);

    TOUCHSHARED_EXPORT static void setLogLevel(TLOG_LEVEL level);
    TOUCHSHARED_EXPORT static TLOG_LEVEL getLogLevel();
    static void writeLogToFile(QString log);
    TOUCHSHARED_EXPORT static void logToConsole(bool console);

private:
    static TLOG_LEVEL level;
    static QTextStream logOut;
    static QFile logFile;
    static bool logConsole;

};
#define TSHOW_LINE(format, ...) TPrintf::info(QString().sprintf("[%s %d]" format, __FILE__, __LINE__, ##__VA_ARGS__))
//#define TSHOW_LINE(format, ...)

#define TPVERBOSE(format, ...) TPrintf::verbose(QString().sprintf(format, ##__VA_ARGS__))
#define TPRINTF(format, ...) TPrintf::debug(QString().sprintf(format, ##__VA_ARGS__))
#define TPINFO(format, ...) TPrintf::info(QString().sprintf(format, ##__VA_ARGS__))
#define TPWARNING(format, ...) TPrintf::warning(QString().sprintf(format, ##__VA_ARGS__))
#define TPERROR(format, ...) TPrintf::error(QString().sprintf(format, ##__VA_ARGS__))

#endif // TPRINTFG_H
