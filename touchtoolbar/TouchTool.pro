TEMPLATE = app

QT += qml quick widgets
# quickwidgets
CONFIG += c++11 plugin
#CONFIG += console

#QMAKE_CXXFLAGS += -DTEST_SDK
#QMAKE_CFLAGS += -DTEST_SDK
#TARGET = qmlqwidgetsplugin
SOURCES += src/presenter/touchpresenter.cpp \
    src/TouchTools.cpp \
    src/touchaging.cpp \
    src/test.cpp \
    main.cpp \
    src/drawpanel.cpp \
    src/tusbevent.cpp \
    src/singleapp.cpp

RESOURCES += qml.qrc \
    images.qrc \
    text.qrc

RC_FILE += icon.rc

# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH = qml/jbQuick/ qml/jbQuick/Charts qml config


TRANSLATIONS += \
    lang/zh_CN.ts \
    lang/zh_TW.ts

#    internationalization/language_English.ts \

INCLUDEPATH += \
    include

lupdate_only{
    SOURCES += *.qml *.cpp \
        qml/ui/*.qml \
        src/*.cpp \
        src/presenter/*.cpp
}

HEADERS += \
    include/presenter/touchpresenter.h \
    include/sdk/CommandThread.h \
    include/sdk/touch.h \
    include/TouchTools.h \
    include/touchaging.h \
    include/sdk/fireware.h \
    include/sdk/TouchManager.h \
    include/drawpanel.h \
    include/tusbevent.h \
    include/singleapp.h \
    include/sdk/hidapi.h \
    include/sdk/tPrintf.h \
    include/sdk/tdebug.h \
    include/sdk/commandthread.h \
    ../touchsdk/include/CommandThread.h

win32 {
    LIBS += -lhid -lsetupapi
}

LIBS += -L/home/xjf/Desktop/touchProject/touch /home/xjf/Desktop/touchProject/touch/libtouch.so
LIBS += -L/home/xjf/Desktop/touchProject/touch /home/xjf/Desktop/touchProject/touch/libtouch.so.1.0
LIBS += -L/home/xjf/Desktop/touchProject/touch /home/xjf/Desktop/touchProject/touch/libtouch.so.1
LIBS += -L/home/xjf/Desktop/touchProject/touch /home/xjf/Desktop/touchProject/touch/libtouch.so.1.0.0
LIBS += -lglut -lGLU


#LIBS += -L lib\ -lusb

#DISTFILES += \
#    lib/TouchAPID.dll \
#    lib/TouchDeviceD.dll \
#    lib/TouchSDKD.dll

#DISTFILES += \
#    lib/TouchAPI.dll \
#    lib/TouchDevice.dll \
#    lib/TouchSDK.dll

DISTFILES += \
    qml/jbQuick/Charts/QChartGallery.js \
    qml/jbQuick/Charts/QChart.qml \
    qml/ui/TestChart.qml \
    qml/ui/DeviceModel.qml \
    qml/ui/TDialog.qml \
    qml/ui/Aging.qml \
    qml/ui/DrawPanel.qml \
    qml/ui/Circle.qml \
    qml/ui/ColorPicker.qml \
    qml/ui/ColorPickerItem.qml \
    config/touch.qml \
    qml/jbQuick/Charts/SignalChart.js \
    qml/ui/Settings.qml \
    qml/ui/Calibration.qml \
    qml/ui/CalibrationPoint.qml \
    qml/ui/CaliTextEdit.qml \
    devices.json \
    qml/ui/PlateLoadTest.qml \
    qml/ui/OnboardTestInterface.qml \
    qml/ui/InformationSign.qml

# Default rules for deployment.
include(deployment.pri)

SUBDIRS += \
    TouchTest.pro


