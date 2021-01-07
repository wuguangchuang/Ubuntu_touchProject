#include "TouchTools.h"
#ifdef TEST_SDK
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include "stdio.h"
#include "TouchTools.h"
#include "presenter/touchpresenter.h"

#include <QtWidgets/QApplication>
#include <QtCore/QDir>
#include <QtQuick/QQuickView>
#include <QtQml/QQmlEngine>
#include <QtQml>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>

#include <QSysInfo>
using namespace Touch;
#include "sdk/tdebug.h"
#include "sdk/tPrintf.h"

void testCoordsEnable(TouchManager *tm, touch_device *dev, qint8 channel)
{
    int ret;
    qint8 setMode = COORDS_CHANNEL_DISABLE;
    TINFO("Test Coords: set enable %d", setMode);
    ret = tm->setCoordsEnabled(dev, channel, setMode);
    if (ret != 0) {
        TERROR("set coords enable %d command failed", setMode);
    } else {
        TINFO("set coords enable %d command success", setMode);
    }
    qint8 mode = setMode + 1;
    ret = tm->getCoordsEnabled(dev, channel, &mode);
    if (ret != 0) {
        TERROR("get coords failed");
    } else {
        TINFO("get coords command success");
        if (mode != setMode) {
            TERROR("get failed value, set %d, but get %d", setMode, mode);
        } else {
            TINFO("set coords enable %d success", setMode);
        }
    }

    setMode = COORDS_CHANNEL_ENABLE;
    TINFO("Test Coords: set enable %d", setMode);
    ret = tm->setCoordsEnabled(dev, channel, setMode);
    if (ret != 0) {
        TERROR("set coords enable command failed");
    } else {
        TINFO("set coords enable command success");
    }
    mode = !setMode;
    ret = tm->getCoordsEnabled(dev, channel, &mode);
    if (ret != 0) {
        TERROR("get coords command failed");
    } else {
        TINFO("get coords command success");
        if (mode != setMode) {
            TERROR("get failed value, set %d, but get %d", setMode, mode);
        } else {
            TINFO("set coords enabled success");
        }
    }
}

void doTestCoordsMode(TouchManager *tm, touch_device *dev, qint8 channel, qint8 setMode)
{
    int ret;
    ret = tm->setCoordsMode(dev, channel, setMode);
    TINFO("Test %d channel %d mode", channel, setMode);
    if (ret != 0) {
        TERROR("set coords mode command failed");
    } else {
        TINFO("set coords mode command success");
    }
    qint8 mode = 0xff;
    ret = tm->getCoordsMode(dev, channel, &mode);
    if (ret != 0) {
        TERROR("get coords mode command failed");
    } else {
        TINFO("get coords mode command success");
        if (mode != setMode) {
            TERROR("get failed value, set %d, but get %d", setMode, mode);
        } else {
            TINFO("set coords mode %d success", setMode);
        }
    }
}

void testCoordsUsbMode(TouchManager *tm, touch_device *dev)
{
    doTestCoordsMode(tm, dev, COORDS_CHANNEL_USB, COORDS_USB_MODE_MOUSE);
    doTestCoordsMode(tm, dev, COORDS_CHANNEL_USB, COORDS_USB_MODE_TOUCH);
}

void testCoordsSerialMode(TouchManager *tm, touch_device *dev)
{
    doTestCoordsMode(tm, dev, COORDS_CHANNEL_SERIAL, COORDS_SERIAL_MODE_TOUCH);
    doTestCoordsMode(tm, dev, COORDS_CHANNEL_SERIAL, COORDS_SERIAL_MODE_TOUCH_WITH_SIZE);
}

void doTestRotation(TouchManager *tm, touch_device *dev, qint8 *setValues)
{
    int ret;
    ret = tm->setRotation(dev, setValues);
    TINFO("Test roation: %d, %d", setValues[0], setValues[1]);
    if (ret != 0) {
        TERROR("set rotation %d, %d command failed", setValues[0], setValues[1]);
    } else {
        TINFO("set rotation %d, %d command success",  setValues[0], setValues[1]);
    }

    qint8 values[2], def[2];
    ret = tm->getRotation(dev, values, def);
    if (ret != 0) {
        TERROR("get rotation command failed");
    } else {
        TINFO("get rotation command success");
        if (values[0] != setValues[0] || values[1] != setValues[1]) {
            TERROR("set rotation return values failed. set[%d,%d], get[%d,%d]",
                   setValues[0], setValues[1], values[0], values[1]);
        } else {
            TINFO("set/get rotation done");
        }
    }
}

void doTestMirror(TouchManager *tm, touch_device *dev, qint8 *setValues)
{
    int ret;
    ret = tm->setMirror(dev, setValues);
    TINFO("Test reflection: %d, %d", setValues[0], setValues[1]);
    if (ret != 0) {
        TERROR("set reflection %d, %d command failed", setValues[0], setValues[1]);
    } else {
        TINFO("set reflection %d, %d command success",  setValues[0], setValues[1]);
    }

    qint8 values[2], def[2];
    ret = tm->getMirror(dev, values, def);
    if (ret != 0) {
        TERROR("get reflection command failed");
    } else {
        TINFO("get reflection command success");
        if (values[0] != setValues[0] || values[1] != setValues[1]) {
            TERROR("set reflection return values failed. set[%d,%d], get[%d,%d]",
                   setValues[0], setValues[1], values[0], values[1]);
        } else {
            TINFO("set/get reflection done");
        }
    }
}


void doTestMacOSMode(TouchManager *tm, touch_device *dev, qint8 mode)
{
    int ret;
    ret = tm->setMacOSMode(dev, mode);
    TINFO("Test Mac OS mode %d", mode);
    if (ret != 0) {
        TERROR("set Mac OS mode %d command failed", mode);
    } else {
        TINFO("set Mac OS mode %d command success", mode);
    }

    qint8 rMode = mode + 1;
    qint8 defMode = 0;
    ret = tm->getMacOSMode(dev, &rMode, &defMode);
    if (ret != 0) {
        TERROR("get Mac OS mode command failed");
    } else {
        TINFO("get Mac OS mode command success");
        if (rMode != mode) {
            TERROR("set Mac OS mode return values failed. set[%d], get[%d]",
                   mode, rMode);
        } else {
            TINFO("set/get Mac OS mode done");
        }
    }
}

void testMacOSMode(TouchManager *tm, touch_device *dev)
{
    for (int mode = 1; mode <= 2; mode++) {
        doTestMacOSMode(tm, dev, mode);
    }
}

void testRotation(TouchManager *tm, touch_device *dev)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 4; j++) {
            qint8 values[2] = {i, j};
            doTestRotation(tm, dev, values);
        }
    }
}
void testMirror(TouchManager *tm, touch_device *dev)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            qint8 values[2] = {i, j};
            doTestMirror(tm, dev, values);
        }
    }
}

void testCalibrationMode(TouchManager *tm, touch_device *dev)
{
    TINFO("%s", __func__);
    int ret;
    qint8 mode;
    for (int i = 0; i < 3; i++) {
        TINFO("%s %d", __func__, i);
        ret = tm->setCalibrationMode(dev, i);
        if (ret != 0) {
            TERROR("set mode %d failed", i);
        } else {
            mode = i - 1;
            ret = tm->getCalibrationMode(dev, &mode);
            if (ret != 0) {
                TERROR("get mode failed");
            } else {
                if (mode != i) {
                    TERROR("mode is not correct, set %d, but get %d", i, mode);
                } else {
                    TINFO("set mode %d success", i);
                }
            }
        }
    }
}

void testCalibrationData(TouchManager *tm, touch_device *dev)
{
    int ret;
    struct CalibrationData data;
    struct CalibrationData tempData, temp;
    TINFO("%s", __func__);
    for (int i = 1; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            ret = tm->getCalibrationPointData(dev, 1, j, &data);
            if (ret != 0) {
                TERROR("GET_CALI_POINT_DATA failed");
            } else if (i == 1){
                memcpy(&tempData, &data, sizeof(struct CalibrationData));
                tempData.targetX += 10;
                tempData.targetY += 10;
                tempData.collectX += 10;
                tempData.collectY += 10;
                ret = tm->setCalibrationPointData(dev, j, &tempData);
                if (ret != 0) {
                    TERROR("SET_CALI_POINT_DATA failed");
                } else {
                    tm->getCalibrationPointData(dev, i, j, &temp);
                    if (temp.targetX != tempData.targetX ||
                        temp.targetY != tempData.targetY ||
                        temp.collectX != tempData.collectX ||
                        temp.collectY != tempData.collectY ||
                        temp.maxX != tempData.maxX ||
                        temp.maxY != tempData.maxY) {
                        TERROR("set cali point tempData value failed");
                        TINFO("Get: tx=%d,ty=%d,cx=%d,cy=%d,mx=%d,my=%d",
                              temp.targetX, temp.targetY, temp.collectX, temp.collectY,
                              temp.maxX, temp.maxY);
                        TINFO("Set: tx=%d,ty=%d,cx=%d,cy=%d,mx=%d,my=%d",
                              tempData.targetX, tempData.targetY, tempData.collectX, tempData.collectY,
                              tempData.maxX, tempData.maxY);
                    } else {
                    }
                    ret = tm->setCalibrationPointData(dev, j, &data);
                }
            }
        }
    }
}

void doTouchTest()
{
    TPRINTF("test.cpp doTouchTest()");
    TouchManager tm;
    int ret;
    touch_device *dev = tm.firstConnectedDevice();
    if (dev == NULL || !dev->touch.connected) {
        TERROR("no device!");
        return;
    }
    TINFO("start test sdk api");
    TINFO("Test coords");
    TINFO("########################");
    TINFO("Test Coords: set usb mode disable");
    testCoordsEnable(&tm, dev, COORDS_CHANNEL_USB);
    TINFO("########################");
    TINFO("Test Coords: set serial mode disable");
    testCoordsEnable(&tm, dev, COORDS_CHANNEL_SERIAL);
    TINFO("########################");
    TINFO("Test coords mode");
    testCoordsUsbMode(&tm, dev);
    TINFO("########################");
    testCoordsSerialMode(&tm, dev);
    TINFO("########################");
    TINFO("Test Rotation");
    testRotation(&tm, dev);
    TINFO("########################");
    TINFO("Test Relection");
    testMirror(&tm, dev);
    TINFO("########################");
    TINFO("Test Mac OS mode");
    testMacOSMode(&tm, dev);

    // V 03, calibration
    TINFO("Test calibration");
    testCalibrationMode(&tm, dev);
    testCalibrationData(&tm, dev);
}
#endif
