#ifndef TouchTools_H
#define TouchTools_H
#include "sdk/hidapi.h"

#include <QTimer>
#include <QDateTime>
#include <QThread>
#include "presenter/touchpresenter.h"
#include "sdk/TouchManager.h"
#include "touchaging.h"
#include <QTranslator>


namespace Touch {

#define en_US 0
#define zh_CN 1

struct TouchData {
    unsigned char report_id;
    unsigned char data[HID_REPORT_DATA_LENGTH];
};

#define APP_VERSION_NAME ("v1.12.24")
#define APP_VERSION_CODE (15)

//#define THIS_APP_TYPE (APP_FACTORY)
#define THIS_APP_TYPE (APP_CLIENT)
//#define THIS_APP_TYPE (APP_RD)
//#define THIS_APP_TYPE (APP_PCBA)
// see also: main.qml(appFactory...)
typedef enum {
    APP_FACTORY = 0,
    APP_CLIENT,
    APP_RD,
    APP_PCBA,
}AppType;



class TouchTools : public QObject, public CommandThread::CommandListener,
        public TouchManager::HotplugListener, public TouchInterface,public TouchManager::Trans
{
    Q_OBJECT
public:
    int argc;
    char **argv;
    QTimer *argcTimer;
    static int language;
    static void setLanguage(int lu);
    static bool autoTestSwitch;
    explicit TouchTools(QObject *parent = 0, TouchPresenter *p = 0,int argc = 0,char *argv[] = 0);
    ~TouchTools();
    bool stopTestIsFinished;
    void addTouchManagerTr();
    void setUpgradeProgess(int progess);
    void setTestProgess(int progess) {emit presenter->setTestProgress(progess);}
    void doUpgradeFireware();
    void restoreUpgradeFile();

    void doTest();
    static void setAutoTestSwitch(bool autoTestSwitch);
    void autoTestConnect(touch_device *dev);
    void clearTestInfo();
    AppType getAppType() { return appType; }
    void setAppType(AppType type) { appType = type; if (presenter) presenter->setAppType((int)appType);}

    void setAgingTime(int time) { touchAging.setAgingTime(time);}
    TouchPresenter *getTouchPresenter() {
        return presenter;
    }

    void onCommandDone(touch_device *dev, touch_package *require, touch_package *reply);
    QString getTr(QString str);
    void onTouchHotplug(touch_device* dev, const int attached, const void *val);
    void setHotplugInterval(unsigned int interval) {
        hotplugInterval = interval;
    }

    QVariantMap getSignalData(QVariant index, int count = 0);
    QVariantMap getSignalItems();
    QVariant getRelativeInfo();
    bool whetherDeviceConnect();
    QVariant getDeviceInfoName();
    QVariant getDeviceInfo();
    QVariant getSoftwareInfoName();
    QVariant getSoftwareInfo();
    bool getTestIsFinished();
    //onboard
    QVariantMap map;
    QVariantMap getBoardAttribyteData();
    QVariantMap getBoardAndLampData()
    {
        return map;
    }
    void showFirewareInfo(int type);
    signals:
    void showMessage(QString title, QString message, int type = 0);
public slots:
    void upgradeFireware(QString path);
    void startUpgrade();
    void setUpdatePath(QString path);
    void setUpgradeFile(QString path);
    void clearComboBoxData();
    void showMessageDialog(QString title, QString message, int type = 0);

    void triggerUsbHotplug();

    void startTest();
    void onStopAll();
    void onSetTestThreadStop(bool stop);
    void setTestThreadCancel(bool t);
    void timeoutWorking();
    void exitProject();

private:
    touch_device *mCurDevice;
    int mDeviceCount;
    TouchManager *mTouchManager;
    AppType appType;
    unsigned int hotplugInterval;

    QString upgradePath;

    class InitSdkThread : public QThread {
    public:
        InitSdkThread(TouchTools *tool);
    protected:
        void run();
        TouchTools *touchTool;
    };
//    class AutoUpdateThread:public QThread{
//    public:
//        AutoUpdateThread(TouchTools *tool){
//            touchTool = tool;
//        }
//    protected:
//        void run();
//        TouchTools *touchTool;
//    };

    class UpgradeThread : public QThread {
    public:
        UpgradeThread(TouchTools *tool) : touchTool(tool), running(false), waiting(false){}
        bool isWaiting() { return waiting; }
        void setWaiting(bool wait) { waiting = wait; }
        void setCancel() { cancel = true;}
        bool isCanceled() { return cancel;}
    protected:
        void run();
        TouchTools *touchTool;
    private:
        bool waiting;
        bool running;
        bool cancel;
    };
    class TestThread : public QThread {
    public:
        TestThread(TouchTools *tool) : touchTool(tool),cancel(false){}
        void setCancel(bool t) { cancel = t;}
        bool isCanceled() { return cancel;}
    protected:
        void run();
        TouchTools *touchTool;
    private:
        bool cancel;
    };

    class TestListener : public TouchManager::TestListener{
    public:
        TestListener(TouchTools *manager) { this->manager = manager;}
        void inProgress(int progress, QString message);
        void onTestDone(bool result, QString message,bool stop,bool isSupport);
        void setNewWindowVisable();
        void changeOnboardtestString(QString info);
        void showTestMessageDialog(QString title,QString message,int type = 0);
        void destroyDialog();
        void refreshOnboardTestData(QVariantMap map);
        void showOnboardFailItem(QString message);
        void showFirewareInfo(int type);

    private:
        TouchTools *manager;
    };

    class UpgradeListener : public TouchManager::UpgradeListener {
    public:
        UpgradeListener(TouchTools *manager) { this->manager = manager;}
        void inProgress(int progress);
        void onUpgradeDone(bool result, QString message);
        void showUpdateMessageDialog(QString title,QString message,int type = 0);
        void destroyDialog();
    private:
        TouchTools *manager;
    };


    TestListener mTestLstener;
    UpgradeListener mUpgradeListener;
    InitSdkThread initSdkThread;
    UpgradeThread upgradeThread;
    TestThread testThread;

    TouchPresenter *presenter;
    TouchAging touchAging;
    CommandThread *command;
    QTimer *timer;
//    AutoUpdateThread autoUpdateThread;

    void appendMessageText(QString message = "", int type = 0)
    {
        presenter->appendMessageText(
                    QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + ": " +
                    message.toStdString().c_str(), type);
    }
    void hotplug(bool plugin) {

    }

    void setMessageText(QString message) {presenter->setMessageText(message);}

private :
    QList<QString> autoUpdatePath;
     bool firstTimeUpdate;

};

} // namespace


#endif // TouchTools_H
