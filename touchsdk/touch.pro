#-------------------------------------------------
#
# Project created by QtCreator 2016-08-20T09:43:55
#
#-------------------------------------------------

#QT       -= gui
QT += widgets

TARGET = touch
TEMPLATE = lib

DEFINES += TOUCH_LIBRARY

LIBS += /lib/x86_64-linux-gnu/libudev.so.1 \
    /lib/x86_64-linux-gnu/libudev.so.1.6.9

SOURCES += \
    src/utils/tdebug.cpp \
    src/TouchManager.cpp \
    src/Fireware.cpp \
    src/utils/CRC_32.cpp \
    src/hid.cpp \
    src/utils/tPrintf.cpp \
    src/commandthread.cpp

INCLUDEPATH += \
    include

DESTDIR += ../

HEADERS += \
    include/touch_global.h \
    include/Fireware.h \
    include/utils/CRC_32.h \
    include/utils/tPrintf.h

HEADERS += \
    include/hidapi.h \
    include/utils/tdebug.h \
    include/CommandThread.h \
    include/touch.h \
    include/TouchManager.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}
win32 {
    LIBS += -lsetupapi
}
