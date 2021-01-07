#ifndef TOUCHPRESENTER_H
#define TOUCHPRESENTER_H

#include <QObject>
#include <QVariant>
#include <QQmlApplicationEngine>
//#include <QquickItem>
#include <QThread>
#include <QMutex>
#include <QSemaphore>
#include <QSettings>
#include <QProcess>
#include <QMessageBox>
#include <QLabel>
#include <QRect>

#include "sdk/TouchManager.h"
#include "sdk/commandthread.h"
#include "sdk/tdebug.h"
#include "sdk/tPrintf.h"


#define DIALOG_NOICON 0
#define DIALOG_QUESTION 4
#define DIALOG_INFO 1
#define DIALOG_WARNING 2
#define DIALOG_CRITICAL 3
class TouchInterface {
public:
    TouchInterface(){}
    virtual QVariantMap getSignalData(QVariant index, int count) = 0;
    virtual QVariantMap getSignalItems() = 0;
    virtual QVariant getRelativeInfo() = 0;
    virtual bool whetherDeviceConnect() = 0;
    virtual QVariant getDeviceInfoName() = 0;
    virtual QVariant getDeviceInfo() = 0;
    virtual QVariant getSoftwareInfoName() = 0;
    virtual QVariant getSoftwareInfo() = 0;
    virtual QVariantMap getBoardAndLampData() = 0;
};
class ProcessStarter : public QProcess {
    Q_OBJECT
public slots:
    void run(const QString &application) {
        TDEBUG("application start running");
        if (this->state() == QProcess::NotRunning)
            start(application);
        TDEBUG("application start end");
    }
};
//
class TouchPresenter : public QObject
{
    Q_OBJECT
public:
    explicit TouchPresenter(QObject *parent = 0, QObject *component = 0);
    void setComponent(QObject *component) {
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

    Q_INVOKABLE void updateFireware(QVariant path);
    Q_INVOKABLE QVariantMap getSignalData(QVariant index, int count = 0);
    Q_INVOKABLE QVariantMap getSignalItems();
    Q_INVOKABLE void startGetSignalDataBg(QVariant index);
    Q_INVOKABLE void stopGetSignalDataBg() { signalThread.running = false; }
    Q_INVOKABLE void stopGetSignalDataSync() {
        signalThread.running = false;
//        signalThread.wait();
    }
    Q_INVOKABLE void tPrintf(QString str,QString _func = NULL)
    {
        if(str == NULL)
            str = " ";
        if(_func == NULL)
            _func = " ";
        TPRINTF("%s %s",_func.toStdString().c_str() ,str.toStdString().c_str());
    }
    //onboard
    Q_INVOKABLE QVariantMap getBoardAndLampData();

    Q_INVOKABLE void msleep(QVariant time) {
        QThread::msleep(time.toInt());
    }
    Q_INVOKABLE void paintLock() {
        paintMutex.lock();
    }

    Q_INVOKABLE void paintUnlock() {
        paintMutex.unlock();;
    }
    Q_INVOKABLE void paintDefaultLock() {
        painDefaulttMutex.lock();
    }

    Q_INVOKABLE void paintDefaultUnlock() {
        painDefaulttMutex.unlock();;
    }

    Q_INVOKABLE void setTest(QVariant on) {
        if (touchManager) {
            int en = on.toInt();
//            TINFO("p %d", en);
            touchManager->setTesting(touchManager->firstConnectedDevice(), en == 1);
        }
    }
    Q_INVOKABLE void cancelTest(bool t)
    {
        emit setCancelTest(t);
    }
    Q_INVOKABLE void setTestThreadToStop(bool stop)
    {
        emit setTestThreadStop(stop);
    }

    Q_INVOKABLE void enterSignalMode(QVariantMap datas) {
        if (touchManager) {
            int enterTest = datas.value("setTest", 0).toInt();
            TDEBUG("test: %d " , enterTest);
            if (enterTest && touchManager->firstConnectedDevice()) {
                touchManager->setTesting(touchManager->firstConnectedDevice(), enterTest);
            }
        }
    }
    Q_INVOKABLE void exitSignalMode(QVariantMap datas) {
        if (touchManager) {
            touchManager->setTesting(touchManager->firstConnectedDevice(), 0);
        }
    }

    Q_INVOKABLE QVariantMap getSettingsInfos();
    Q_INVOKABLE QVariant setSettings(QVariant key, QVariant value);

    Q_INVOKABLE QVariant getRelativeInfo();
    Q_INVOKABLE bool whetherDeviceConnect();
    Q_INVOKABLE QVariant getDeviceInfoName();
    Q_INVOKABLE QVariant getDeviceInfo();
    Q_INVOKABLE QVariant getSoftwareInfoName();
    Q_INVOKABLE QVariant getSoftwareInfo();

    Q_INVOKABLE void signalInit(QVariant mode) {
        if (touchManager) {
            touchManager->signalInit(touchManager->firstConnectedDevice(), (qint8)mode.toInt());
        }
    }

    Q_INVOKABLE QVariant getSettingsValue(QVariant key) {
        return settings.value(key.toString());
    }
    Q_INVOKABLE QVariant getSettingsBool(QVariant key) {
        return settings.value(key.toString()).toBool();
    }

    Q_INVOKABLE void setSettingsValue(QVariant key, QVariant value) {
        if (value.canConvert<QVariantList>()) {
            value = value.value<QVariantList>();
        }
        settings.setValue(key.toString(), value);
    }

    // calibration
    Q_INVOKABLE QVariantMap getCalibrationDatas(QVariant where);
    Q_INVOKABLE QVariant setCalibrationDatas(QVariantMap datas);
    Q_INVOKABLE QVariant enterCalibrationMode();
    Q_INVOKABLE QVariant exitCalibrationMode();
    Q_INVOKABLE QVariant setCalibrationPointData(QVariant index, QVariantMap data);
    Q_INVOKABLE QVariant captureCalibrationIndex(QVariant index);
    Q_INVOKABLE QVariantMap getCalibrationCapture();
    Q_INVOKABLE QVariant saveCalibration();

    Q_INVOKABLE QVariant testCaliCapture(QVariant time = QVariant::fromValue(2000));
    Q_INVOKABLE QVariant testMultiPoint() {
        touchManager->testMultiPointDraw(NULL, 1);
    }

    Q_INVOKABLE void debug(QVariant msg);
    Q_INVOKABLE void error(QVariant msg);

    Q_INVOKABLE QVariant isDeviceConnected() {
        bool result = true;
        if (touchManager == NULL) {
            result = false;
        } else {
            touch_device *dev = touchManager->firstConnectedDevice();
            if (dev == NULL || dev->touch.booloader) {
                result = false;
            } else {
                result = dev->touch.connected == 1;
            }
        }
        return QVariant::fromValue(result);
    }

    // coords
    Q_INVOKABLE void setCoordsEnabled(QVariant channel, QVariant enabled)
    {
        if (touchManager == NULL)
            return;
        TDEBUG("%s %d %d", __func__, channel.toInt(), enabled.toInt());
        touchManager->setCoordsEnabled(NULL,
            (qint8)channel.toInt(), (qint8)enabled.toInt());
    }
    Q_INVOKABLE bool isCoordsEnables(QVariant channel) {
        if (touchManager == NULL)
            return false;
        qint8 status;
        int ret = touchManager->getCoordsEnabled(NULL, (qint8)channel.toInt(), &status);
        if (ret < 0)
            return status;
        TDEBUG("%s %d %d", __func__, channel.toInt(), status);
        return (status > 0);
    }

    Q_INVOKABLE void updateSignalList(QVariant list);
    Q_INVOKABLE int getAppType() { return appType; }
    Q_INVOKABLE void setAppType(int type) { appType = type; }

    Q_INVOKABLE void run(QVariant app) {
        starter.run(app.toString());
    }

    // factory reset
    Q_INVOKABLE int resetXYOrientation() {
        qint8 cur[2], def[2];
        touchManager->getMirror(NULL, cur, def);
        touchManager->setMirror(NULL, def);
        return (def[1] << 8) | def[0];
    }

    Q_INVOKABLE int resetTouchRotation() {
        qint8 cur[2], def[2];
        touchManager->getRotation(NULL, cur, def);
        def[1] = cur[1];
        touchManager->setRotation(NULL, def);
        return def[0];
    }

    Q_INVOKABLE int resetScreenRotation() {
        qint8 cur[2], def[2];
        touchManager->getRotation(NULL, cur, def);
        def[0] = cur[0];
        touchManager->setRotation(NULL, def);
        return def[1];
    }

    Q_INVOKABLE int resetMacOs() {
        qint8 cur[2], def[2];
        touchManager->getMacOSMode(NULL, cur, def);
        touchManager->setMacOSMode(NULL, def[0]);
        return def[0];
    }
    //closing window
    Q_INVOKABLE void showExitMessage()
    {
        TDEBUG("ready show message!!!");
        QMessageBox msgBox;
        msgBox.setText("正在退出...");
        msgBox.resize(100,100);
        msgBox.show();
        msleep(3000);
        msgBox.hide();
    }
     Q_INVOKABLE void emitStopAll()
    {
        signalThread.running = false;
        emit stopAll();
        TDEBUG("send stop thread  signal finshed");
    }
    Q_INVOKABLE bool isrunning()
    {
//        TDEBUG("There are still threads running ");
//        bool totplugThreadState = touchManager->mHotplugThread.getHotplugThread();
//        if(!totplugThreadState || touchManager->commandThread != NULL
//                || !signalThread.finshed)
//        {
//            if(!totplugThreadState)
//                TDEBUG("touchManager->mHotplugThread.getHotplugThread() isn't finshed");
//            if(touchManager->commandThread != NULL)
//                TDEBUG("touchManager->commandThread != NULL");
//            if(!signalThread.finshed)
//                TDEBUG("!signalThread.finshed");
//            return true;
//        }


        if(touchManager->mHotplugThread.isRunning())
        {
             TDEBUG("touchManager->mHotplugThread.isRunning()");
             return true;
        }
        if(touchManager->commandThread != NULL)
        {
            if(touchManager->commandThread->isRunning())
            {
                TDEBUG("touchManager->commandThread->isRunning()");
                return true;
            }
        }
        else
            TDEBUG("touchManager->commandThread == NULL");

        if(signalThread.isRunning())
        {
            TDEBUG("signalThread.isRunning()");
            return true;
        }
        return false;
    }

    QObject* getComponent() { return component;}
    void setTouchManager(TouchManager *tm) {touchManager = tm;}


    // call qml
    void showDialog(QString title, QString message, int type = 0);
    void setFileText(QString path);
    void setAutoUpgradeFile(QString path);
    void showToast(QString str);
    void setTouchInterface(TouchInterface *interface){touch = interface;}
    void setTestButtonEnable(bool enable);
    void setTestButtonCheck(bool check);
    void setVisibleValue();
    void changeOnboardtestString(QString info);
    void setUpgradeButtonEnable(bool enable);
    void setUpgradeButtonCheck(bool check);
    void refreshOnboardTestData(QVariantMap map);

    void setUpgrading(bool u);
    void setTesting(bool t);
    void autoTestConnect();
    void clearTestInfo();
    void setUpgradeButtonText(QString text);
    void setTextButtonText(QString text);
    void refreshSettings();
    void destroyQml();
    void destroyDialog();


    void startAgingTest();
    void stopAgingTest();
    void setDeviceStatus(int index, int status);
    int getDeviceCount();
    void setAgingTime(int time);

    void setInfo(QString info);

    void onboardTestFinish(QString title, QString message, int type = 0);
    void onboardShowDialog(QString title, QString message, int type = 0);
    void setCurrentIndex(int index);
    void setWindowHidden(bool visibled);

signals:
    void agingFinished(int index);
    void setUpgradeProgress(QVariant p);
    void setTestProgress(QVariant p);

    void upgradeFireware(QString path);
    void startUpgrade();
    void setCancelTest(bool t);
    void setUpgradeFile(QString path);
    void clearComboBoxData();

    void setMessageText(QVariant message);
    void appendMessageText(QVariant message, QVariant type);

    void hotplug(QVariant in);

    void startTest();
    void getSignalDataDone(QVariantMap datas);

    void stopAll();
    void setTestThreadStop(bool stop);
    void setUpdatePath(QString path);

public slots:
    void newRunner();

private:
    class GetSignalThread : public QThread {
    public:
        GetSignalThread(TouchPresenter *tp) : presenter(tp), running(false) {}
        TouchPresenter *presenter;
        bool running;
        QVariant index;
        bool finshed = false;
    protected:
        void run();
    };

private:
    QObject *component;
    QSemaphore sem;
    QMutex paintMutex;
    QMutex painDefaulttMutex;
    QSemaphore paintSem;

    char datas[10];
    TouchInterface *touch;
    GetSignalThread signalThread;
    QVariantList signalList;
    QMutex signalMutex;
    int appType;
    TouchManager *touchManager;

    QSettings settings;
    ProcessStarter starter;
public:
    bool initSdkDone;
};

#endif // TOUCHPRESENTER_H
