#include "presenter/touchpresenter.h"


//#include <stdio.h>
#include "sdk/tdebug.h"
#include "sdk/tPrintf.h"
#include <QTime>
#include <QQmlProperty>
#include <QSysInfo>
#include "sdk/TouchManager.h"

TouchPresenter::TouchPresenter(QObject *parent, QObject *component) : QObject(parent),
    signalThread(this), sem(0), settings("newskyer", "TouchAssistant"),paintSem(0),touchManager(NULL),
    initSdkDone(false)
{

    this->component = component;
    if (component != NULL) {

        QObject::connect(component, SIGNAL(agingFinished(int)),
                         this, SIGNAL(agingFinished(int)));
        QObject::connect(this, SIGNAL(setUpgradeProgress(QVariant)),
                         component, SLOT(updateUpgradeProgress(QVariant)));
        QObject::connect(this, SIGNAL(setTestProgress(QVariant)),
                         component, SLOT(updateTestProgress(QVariant)));
        QObject::connect(this, SIGNAL(setMessageText(QVariant)),
                         component, SLOT(setText(QVariant)));
        QObject::connect(this, SIGNAL(appendMessageText(QVariant, QVariant)),
                         component, SLOT(appendText(QVariant, QVariant)));
        QObject::connect(this, SIGNAL(hotplug(QVariant)),
                         component, SLOT(onHotplug(QVariant)));
    }
}

QVariantMap TouchPresenter::getSignalItems()
{
    QVariantMap map;
    if (touch == NULL) {
        map.insert("result", 1);
        return map;
    }

    return touch->getSignalItems();
}

void TouchPresenter::startGetSignalDataBg(QVariant index)
{
    signalThread.running = true;
    signalThread.start();
}

QVariantMap TouchPresenter::getBoardAndLampData()
{
    return touch->getBoardAndLampData();
}

void TouchPresenter::debug(QVariant msg)
{
    TDebug::debug(msg.toString());
}

void TouchPresenter::error(QVariant msg)
{
    TDebug::error(msg.toString());
}

void TouchPresenter::GetSignalThread::run()
{
//    presenter->paintDefaultLock();
    TDEBUG("GetSignalThread thread start running");
    int index;
    int count = 0;
    bool ok;
#define FIXED_PERIOD (16) // 60Fps
    long period = FIXED_PERIOD;
    while (running) {

        QTime time;
        time.start();
        //TDEBUG("run start");
//        presenter->paintLock();
        QVariantList list = presenter->signalList;
        foreach (QVariant const &value, list) {
            index = value.toInt(&ok);
            if (!ok)
                continue;
            if (!running)
                break;
//            TDEBUG("get signal data");

            QVariantMap map = presenter->getSignalData(index, count);

            QMetaObject::invokeMethod(presenter->component, "updateSignalData",
                Q_ARG(QVariant, QVariant::fromValue(map)));
        }

//        presenter->paintUnlock();
        long delay = period - time.elapsed();
//        TDEBUG("consume: %d, delay: %d", time.elapsed(), delay);
//        qDebug("consume: %d, delay: %d", time.elapsed(), delay);
        if (delay > 0) {
            // excess
            if (!running)
                break;
            QThread::msleep(delay);
            period = FIXED_PERIOD;
        } else {
            // insufficient, need add this overtime
            period = FIXED_PERIOD + delay;
        }
    }
    finshed = true;
    TDEBUG("GetSignalThread thread end");
}

QVariantMap TouchPresenter::getSettingsInfos()
{
    QVariantMap map;
    qint8 val;
    int ret;
    touch_device *dev = touchManager->firstConnectedDevice();
    if (dev == NULL)
        return map;
    bool isXP = (int)QSysInfo::WindowsVersion == (int)QSysInfo::WV_XP;
    if (isXP) {
        map.insert("usbMode", 1);
        touchManager->setCoordsMode(dev, COORDS_CHANNEL_USB, COORDS_USB_MODE_MOUSE);
    } else {
        val = -1;
        ret = touchManager->getCoordsMode(dev, COORDS_CHANNEL_USB, &val);
        map.insert("usbMode", val);
        TVERBOSE("usbMode:%d", val);
    }

    val = -1;
    ret = touchManager->getCoordsMode(dev, COORDS_CHANNEL_SERIAL, &val);
    map.insert("serialMode", val);
    TVERBOSE("serial mode: %d", val);

    //获取旋转参数
    qint8 values[2] = {-1, -1}, defs[2];
    touchManager->getRotation(dev, values, defs);
    map.insert("touchRotation", values[0]);
    map.insert("screenRotation", values[1]);
    TVERBOSE("touch rotation: %d", values[0]);
    TVERBOSE("screen rotation: %d", values[1]);

    //获取触摸框坐标翻转参数
    values[0] = values[1] = -1;
    touchManager->getMirror(dev, values, defs);
    map.insert("xMirror", values[0]);
    map.insert("yMirror", values[1]);
    TVERBOSE("xMirror: %d", values[0]);
    TVERBOSE("yMirror: %d", values[1]);

    //获取MAC OS坐标模式的设定
    values[0] = -1;
    touchManager->getMacOSMode(dev, values, defs);
    map.insert("mac", values[0]);
    TVERBOSE("mac: %d", values[0]);

    //获取坐标通道是否已经使能
    qint8 enabled = 0;
    touchManager->getCoordsEnabled(dev, COORDS_CHANNEL_USB, &enabled);
    map.insert("usbEnabled", enabled);
    TVERBOSE("usb enabled: %d", enabled);

    touchManager->getCoordsEnabled(dev, COORDS_CHANNEL_SERIAL, &enabled);
    map.insert("serialEnabled", enabled);
    TVERBOSE("serial enabled: %d", enabled);

    //获取AGC锁定状态
    enabled = touchManager->isLockAGC(dev);
    map.insert("lockAGC", enabled);
    TINFO("LockAGC: %d", enabled);

    return map;
}

QVariant TouchPresenter::setSettings(QVariant key, QVariant value)
{
    const QString k = key.toString();
    touch_device *dev = touchManager->firstConnectedDevice();
    if (dev == NULL || !dev->touch.connected)
        return QVariant::fromValue(false);
    int ret;
    if (k == "usbMode") {
        ret = touchManager->setCoordsMode(dev, COORDS_CHANNEL_USB, (qint8)value.toInt());
        TVERBOSE("set usbMode %d, %d", value.toInt(), ret);
    } else if (k == "serialMode") {
        ret = touchManager->setCoordsMode(dev, COORDS_CHANNEL_SERIAL, (qint8)value.toInt());
        TVERBOSE("set serialMode %d, %d", value.toInt(), ret);
    } else if (k == "touchRotation") {
        qint8 values[2], defs[2];
        touchManager->getRotation(dev, values, defs);
        values[0] = value.toInt();
        ret = touchManager->setRotation(dev, values);
        TVERBOSE("set touch rotation %d, %d", value.toInt(), ret);
    } else if (k == "screenRotation") {
        qint8 values[2], defs[2];
        touchManager->getRotation(dev, values, defs);
        values[1] = value.toInt();
        ret = touchManager->setRotation(dev, values);
        TVERBOSE("set screen rotation %d, %d", value.toInt(), ret);
    } else if (k == "xMirror") {
        qint8 values[2], defs[2];
        touchManager->getMirror(dev, values, defs);
        values[0] = value.toInt();
        ret = touchManager->setMirror(dev, values);
        TVERBOSE("set x mirror%d, %d", value.toInt(), ret);
    } else if (k == "yMirror") {
        qint8 values[2], defs[2];
        touchManager->getMirror(dev, values, defs);
        values[1] = value.toInt();
        ret = touchManager->setMirror(dev, values);
        TVERBOSE("set y mirror%d, %d", value.toInt(), ret);
    } else if (k == "lockAGC") {
        int en = value.toInt();
        touchManager->setLockAGC(dev, en != 0 ? 1 : 0);
        TINFO("set lock: %d", en);
        TVERBOSE("set LockAGC %d", en);
    } else if (k == "mac") {
        ret = touchManager->setMacOSMode(dev, (qint8)value.toInt());
        TVERBOSE("set mac os %d, %d", value.toInt(), ret);
    }
    return QVariant::fromValue(ret == 0);
}

QVariantMap TouchPresenter::getSignalData(QVariant index, int count)
{
    if (touch == NULL) {
        QVariantMap map;
        map.insert("result", 1);
        return map;
    }
    return touch->getSignalData(index, count);
}

void TouchPresenter::updateFireware(QVariant path)
{
    //printf("update Fireware: %s\n", path.toString().toStdString().c_str());
    TDebug::info(path.toString());
    emit upgradeFireware(path.toString());
}

void TouchPresenter::showDialog(QString title, QString message, int type)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QVariant returnedValue;
    QMetaObject::invokeMethod(component, "showDialog",
    Q_RETURN_ARG(QVariant, returnedValue),
    Q_ARG(QVariant, title),
    Q_ARG(QVariant, message),
    Q_ARG(QVariant, type));
}

void TouchPresenter::setUpgradeButtonText(QString text)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setUpgradeButtonText",
    Q_ARG(QVariant, text));
}
void TouchPresenter::setTextButtonText(QString text)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setTextButtonText",
    Q_ARG(QVariant, text));
}

void TouchPresenter::setTestButtonEnable(bool enable)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setTestButtonEnable",
    Q_ARG(QVariant, enable));
}
void TouchPresenter::setTestButtonCheck(bool check)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setTestButtonCheck",
                              Q_ARG(QVariant, check));
}

void TouchPresenter::setVisibleValue()
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setVisibleValue");
}

void TouchPresenter::changeOnboardtestString(QString info)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "changeOnboardtestString",
                              Q_ARG(QVariant, info));
}

    void setUpgrading(bool u);
    void setTesting(bool t);
void TouchPresenter::setUpgrading(bool u)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setUpgrading",
    Q_ARG(QVariant, u));
}
void TouchPresenter::setTesting(bool t)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setTesting",
                              Q_ARG(QVariant, t));
}

void TouchPresenter::autoTestConnect()
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "autoTestConnect");
}

void TouchPresenter::clearTestInfo()
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "clearTestInfo");
}
void TouchPresenter::setUpgradeButtonEnable(bool enable)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setUpgradeButtonEnable",
                              Q_ARG(QVariant, enable));
}

void TouchPresenter::refreshOnboardTestData(QVariantMap map)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "refreshOnboardTestData",
                              Q_ARG(QVariant, map));
}


void TouchPresenter::setFileText(QString path)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setFileText",
                              Q_ARG(QVariant, path));
}

void TouchPresenter::setAutoUpgradeFile(QString path)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setUpgradeFile",
                              Q_ARG(QVariant, path));
}

void TouchPresenter::showToast(QString str)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "showToast",
                              Q_ARG(QVariant, str));
}


QVariant TouchPresenter::getRelativeInfo()
{
    return QVariant::fromValue(touch->getRelativeInfo());
}

bool TouchPresenter::whetherDeviceConnect()
{
    return touch->whetherDeviceConnect();
}

QVariant TouchPresenter::getDeviceInfoName()
{
    return QVariant::fromValue(touch->getDeviceInfoName());
}

QVariant TouchPresenter::getDeviceInfo()
{
    return QVariant::fromValue(touch->getDeviceInfo());
}
QVariant TouchPresenter::getSoftwareInfoName()
{
    return QVariant::fromValue(touch->getSoftwareInfoName());
}
QVariant TouchPresenter::getSoftwareInfo()
{
    return QVariant::fromValue(touch->getSoftwareInfo());
}


void TouchPresenter::setInfo(QString info)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setDeviceInfo",
                              Q_ARG(QVariant, info));
}

void TouchPresenter::onboardTestFinish(QString title, QString message, int type)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "onboardTestFinish",
                              Q_ARG(QVariant, title),Q_ARG(QVariant, message),Q_ARG(QVariant, type));
}

void TouchPresenter::onboardShowDialog(QString title, QString message, int type)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
     QMetaObject::invokeMethod(component, "onboardShowDialog",Q_ARG(QVariant, title),
                               Q_ARG(QVariant, message),Q_ARG(QVariant, type));
}

void TouchPresenter::setCurrentIndex(int index)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setCurrentIndex",Q_ARG(QVariant, index));
}

void TouchPresenter::setWindowHidden(bool visibled)
{
    if (component == NULL) {
        TDebug::warning("component is NULL");
        return;
    }
    QMetaObject::invokeMethod(component, "setCurrentIndex",Q_ARG(QVariant, visibled));
}

void TouchPresenter::updateSignalList(QVariant list)
{
    if (!list.canConvert<QVariantList>()) {
        TWARNING("%s invalid list", __func__);
    }
    signalMutex.lock();
    signalList = list.value<QVariantList>();
//    foreach (QVariant const &index, signalList) {
//    }
    signalMutex.unlock();
}


int TouchPresenter::getDeviceCount()
{
    if (component == NULL) {
        return 0;
    }
    QVariant returnedValue;
    QMetaObject::invokeMethod(component, "getDeviceCount",
        Q_RETURN_ARG(QVariant, returnedValue));
    return returnedValue.toInt();
}

void TouchPresenter::setAgingTime(int time)
{
    QMetaObject::invokeMethod(component, "setAgingTime",
        Q_ARG(QVariant, time));
//    QQmlProperty(component, "passAgingTime").write(time);
}

void TouchPresenter::setDeviceStatus(int index, int status)
{
    //setDeviceStatus
    if (component == NULL) {
        return;
    }
    QVariant returnedValue;
    QMetaObject::invokeMethod(component, "setDeviceStatus",
        Q_ARG(QVariant, index),
        Q_ARG(QVariant, status));
    return;
}

void TouchPresenter::startAgingTest()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "startAging");
    return;
}
void TouchPresenter::stopAgingTest()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "stopAging");
    return;
}

void TouchPresenter::refreshSettings()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "refreshSettings");
    return;
}

void TouchPresenter::newRunner()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "newRunner");
    return;
}

void TouchPresenter::destroyQml()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "onDestroyed");
    return;
}

void TouchPresenter::destroyDialog()
{
    if (component == NULL) {
        return;
    }
    QMetaObject::invokeMethod(component, "destroyDialog");
    return;
}

QVariant TouchPresenter::setCalibrationDatas(QVariantMap datas)
{
    if (touchManager == NULL) {
        TWARNING("%s: TouchManager is NULL", __func__);
        return QVariant::fromValue(false);
    }
    int ret;
    CalibrationData data;
    QVariantList list = datas.value("points").value<QVariantList>();
    for (int i = 0; i < datas.value("count", 0).toInt(); i++) {
        QVariantMap point = list.at(i).value<QVariantMap>();
        int index = point.value("index", -1).toInt();
        if (index == -1)
            return QVariant::fromValue(false);
        data.targetX = point.value("targetX", 0).toInt();
        data.targetY = point.value("targetY", 0).toInt();
        data.collectX = point.value("collectX", 0).toInt();
        data.collectY = point.value("collectY", 0).toInt();
        data.maxX = point.value("maxX", 0).toInt();
        data.maxY = point.value("maxY", 0).toInt();
        ret = touchManager->setCalibrationPointData(NULL,
                index, &data);
        if (ret != 0)
            return QVariant::fromValue(false);
    }
    return QVariant::fromValue(true);
}

QVariantMap TouchPresenter::getCalibrationDatas(QVariant where)
{
    QVariantMap map;
    if (touchManager == NULL) {
        TWARNING("%s: TouchManager is NULL", __func__);
        return map;
    }
    int ret;
    bool ok;
    int w = where.toInt(&ok);
    if (ok == false) {
        TWARNING("%s: where is bad", __func__);
        return map;
    }
    CalibrationSettings settings;
    ret = touchManager->getCalibrationSettings(NULL, &settings);
    if (ret != 0) {
        TWARNING("%s: get settings failed", __func__);
        return map;
    }
    CalibrationData data;
    map.insert("count", settings.pointCount);
    QVariantList points;
    for (int i = 0; i < settings.pointCount; i++) {
        ret = touchManager->getCalibrationPointData(NULL,
                    w, i, &data);
        QVariantMap point;
        point.insert("index", i);
        point.insert("targetX", data.targetX);
        point.insert("targetY", data.targetY);
        point.insert("collectX", data.collectX);
        point.insert("collectY", data.collectY);
        point.insert("maxX", data.maxX);
        point.insert("maxY", data.maxY);
        points.append(point);
    }
    map.insert("points", points);
    return map;
}

QVariant TouchPresenter::enterCalibrationMode()
{
    if (touchManager == NULL)
        return QVariant::fromValue(false);
    int ret;
    ret = touchManager->setCalibrationMode(NULL, CALIBRATION_MODE_COLLECT);
    if (ret != 0)
        return QVariant::fromValue(false);
    ret = touchManager->setCoordsEnabled(NULL, COORDS_CHANNEL_SERIAL, COORDS_CHANNEL_DISABLE);
    if (ret != 0)
        return QVariant::fromValue(false);
    ret = touchManager->setCoordsEnabled(NULL, COORDS_CHANNEL_USB, COORDS_CHANNEL_DISABLE);
    if (ret != 0)
        return QVariant::fromValue(false);

    return QVariant::fromValue(true);
}

QVariant TouchPresenter::exitCalibrationMode()
{
    TPRINTF("退出校准模式:");
    if (touchManager == NULL)
        return QVariant::fromValue(false);
    int ret;
    ret = touchManager->setCalibrationMode(NULL, CALIBRATION_MODE_CALIBRATION);
    if (ret != 0)
        return QVariant::fromValue(false);
    ret = touchManager->setCoordsEnabled(NULL, COORDS_CHANNEL_SERIAL, COORDS_CHANNEL_ENABLE);
    if (ret != 0)
        return QVariant::fromValue(false);
    ret = touchManager->setCoordsEnabled(NULL, COORDS_CHANNEL_USB, COORDS_CHANNEL_ENABLE);
    if (ret != 0)
        return QVariant::fromValue(false);

    return QVariant::fromValue(true);
}

QVariant TouchPresenter::setCalibrationPointData(QVariant index, QVariantMap data)
{
    bool result = false;
    int ret;
    if (touchManager == NULL)
        goto _set_cali_point_data_out;
    CalibrationData point;
    point.targetX = data.value("targetX", 0).toInt();
    point.targetY = data.value("targetY", 0).toInt();
    point.collectX = data.value("collectX", 0).toInt();
    point.collectY = data.value("collectY", 0).toInt();
    point.maxX = data.value("maxX", 0).toInt();
    point.maxY = data.value("maxY", 0).toInt();
    TDEBUG("%s: index: %d, tx:%d,ty:%d,cx:%d,cy:%d,mx:%d,my:%d",
           __func__, index.toInt(),
           point.targetX, point.targetY, point.collectX, point.collectY,
           point.maxX, point.maxY);
    ret = touchManager->setCalibrationPointData(NULL, index.toInt(), &point);
    result = ret == 0;
_set_cali_point_data_out:
    return QVariant::fromValue(result);
}

QVariant TouchPresenter::saveCalibration()
{
    if (touchManager == NULL)
        return QVariant::fromValue(false);
    int ret = touchManager->saveCalibrationData(NULL);
    if (ret != 0)
        return QVariant::fromValue(false);
    return QVariant::fromValue(true);
}

QVariant TouchPresenter::captureCalibrationIndex(QVariant index)
{
    if (touchManager == NULL)
        return QVariant::fromValue(false);
    int ret = touchManager->startCalibrationCapture(NULL, index.toInt());
    if (ret != 0)
        return QVariant::fromValue(false);
    return QVariant::fromValue(true);
}

QVariantMap TouchPresenter::getCalibrationCapture()
{
    QVariantMap map;
    if (touchManager == NULL) {
        TWARNING("%s: TouchManager is NULL", __func__);
        return map;
    }
    CalibrationCapture data;
    int ret = touchManager->getCalibrationCapture(NULL, &data);
    if (ret != 0)
        return map;
    map.insert("index", data.index);
    map.insert("finished", data.finished);
    map.insert("count", data.count);
    return map;
}

QVariant TouchPresenter::testCaliCapture(QVariant time)
{
    QVariantMap map;
    if (touchManager == NULL) {
        TWARNING("%s: TouchManager is NULL", __func__);
        return map;
    }
    touchManager->testCalibrationCapture(NULL, time.toInt());
    return QVariant::fromValue(true);
}

