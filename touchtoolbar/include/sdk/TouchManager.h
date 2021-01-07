#ifndef TOUCHMANAGER_H
#define TOUCHMANAGER_H

#include "sdk/tdebug.h"
#include "touch.h"
#include "commandthread.h"
//#include "sdk/commandThread.h"
#define MAX_TOUCH_COUNT 9
#define ROOT_PASSWD_LENGTH 128

#ifdef TOUCHSHARED_EXPORT
#undef TOUCHSHARED_EXPORT
#endif
#define TOUCHSHARED_EXPORT

typedef enum {
    Standard_Factory = STE_FACTORY_TEST,
    Standard_Client = STE_END_USER_TEST,
    Standard_RD = STE_DEV_TEST,
    Standard_PCBA = STE_PCBA_CUSTOMER_TEST,
}StandardType;
typedef struct _onboard_test_data_result
{
    QVariantList downLampState;
    QVariantList leftLampState;
    QVariantList upLampState;
    QVariantList rightLampState;
    QVariantList downBoardState;
    QVariantList leftBoardState;
    QVariantList upBoardState;
    QVariantList rightBoardState;
}onboard_test_data_result;
class TouchTestData {
public:
    TouchTestData();
    QVariantList datas;
    qint32 count;
    qint32 f_min;
    qint32 f_max;
    qint32 c_min;
    qint32 c_max;
    qint32 number;
};

struct CalibrationSettings {
    qint8 mode;
    qint8 pointCount;
    qint8 defMode;
    qint8 defPointCount;
};

struct CalibrationData {
    qint32 targetX;
    qint32 targetY;
    qint32 collectX;
    qint32 collectY;
    qint32 maxX;
    qint32 maxY;
};
struct CalibrationCapture {
    qint8 index;
    qint16 finished;
    qint16 count;
};
typedef void (*touch_hotplug_func)(touch_device *, const int attached, const void *value);
class TouchManager : public CommandThread::CommandListener
{

public:
    class Trans
    {
    public:
        virtual QString getTr(QString str) = 0;
    };

    class HotplugListener {
    public:
        virtual void onTouchHotplug(touch_device* dev, const int attached, const void *val) = 0;
    };
    class SendCallback {
    public:
        virtual void onSendCallback(touch_device* dev, touch_package *reply) = 0;
    };
    class TestListener {
    public:
        virtual void inProgress(int progress, QString message) = 0;
        virtual void onTestDone(bool result, QString message,bool stop,bool isSupport) = 0;
        virtual void setNewWindowVisable() = 0;
        virtual void changeOnboardtestString(QString info) = 0;
        virtual void showTestMessageDialog(QString title,QString message,int type = 0) = 0;
        virtual void destroyDialog() = 0;
        virtual void refreshOnboardTestData(QVariantMap map) = 0;
        virtual void showOnboardFailItem(QString message) = 0;
        virtual void showFirewareInfo(int type) = 0;
    };
    class UpgradeListener {
    public:
        virtual void inProgress(int progress) = 0;
        virtual void onUpgradeDone(bool result, QString message) = 0;
        virtual void showUpdateMessageDialog(QString title,QString message,int type = 0) = 0;
        virtual void destroyDialog() = 0;
    };

    class HotplugThread : public QThread
    {
    public:
        HotplugThread(TouchManager *manager) : manager(manager), mStop(false) {}
        void stopThread() { mStop = true;}
        bool getHotplugThread(){return finshed;}

    protected:
        void run();
    private:
        TouchManager *manager;
        bool mStop;
        bool finshed = false;
    };

    class UpgradeThread : public QThread
    {
    public:
        UpgradeThread(TouchManager *manager);
        QString path;

    protected:
        void run();
    private:
        TouchManager *manager;
    };

    TOUCHSHARED_EXPORT class TestThread : public QThread
        {
        public:
            TestThread(TouchManager *manager);
            void setStandardType(StandardType st = Standard_Factory) { standardType = st; }
            StandardType standardType;

        protected:
            void run();
        private:
            TouchManager *manager;

        };
private:
    TouchManager();
    static int instanceCount;
    static TouchManager* mTouchManager;
public:
    static char rootPasswd[ROOT_PASSWD_LENGTH];
public:
    TOUCHSHARED_EXPORT static TouchManager* getInstance();
    TOUCHSHARED_EXPORT static void freeInstance();
    virtual ~TouchManager();
    void setTr(Trans *translator);
    int registerHotplug(HotplugListener *listener);
    TOUCHSHARED_EXPORT void setHotplugByEvent(bool b);
    TOUCHSHARED_EXPORT void triggerHotplugEvent(void);

    /**
     * @brief sendPackage
     * @param package
     * @param reply NULL, if don't need reply, but also can get reply in *listener->onCommandDone scope
     * @param device
     * @param async
     * @param listener
     * @return
     */
    int sendPackage(touch_package *package,touch_package *reply = NULL,
                    touch_device *device = NULL,int async = 0,
       CommandThread::CommandListener *listener = NULL,CommandItem *item = NULL);

    static int sendPackageToDevice(touch_package *package,touch_package *reply = NULL,
                            touch_device *device = NULL);


    int startUpgrade(QString path, UpgradeListener *listener = NULL);
    void doUpgrade(QString path);

    void onCommandDone(touch_device *dev, touch_package *require, touch_package *reply);

    bool startTest(touch_device *device, TestListener *listener, StandardType st = Standard_Factory);

    void doTest();
    void checkOnboardtestDataAbnormal(onboard_test_data_result *onboardTestData,
                                      unsigned char *onboardTestItem,int count);

    int getDeviceCount();
    touch_device *getDevices() { return mDevices;}
    static bool addTouchDeviceInfo(touch_vendor_info *info);
    static bool freeAllTouchDeviceInfo();

    static bool isSameDeviceInPort(touch_device *a, touch_device *b);

    /**
     * @brief device get the default(first) device
     * @return
     */
    touch_device *device() { return mDevices;}

    touch_device *firstConnectedDevice();

    /**
     * @brief deviceByPath get device byt path
     * @param path
     * @return
     */
    touch_device *deviceByPath(const char *path);

    /**
     * @brief deviceBySerial not work now
     * @param serial
     * @return
     */
    touch_device *deviceBySerial(const char *serial);

    // commands wrap
    int reset(touch_device *device, int dst = RESET_DST_APP, int delay = 0, int async = 0);

    int getFirewareInfo(touch_device *device, touch_fireware_info *info);
    int getStringInfo(touch_device *device, int type, char *str, int max);
    TOUCHSHARED_EXPORT int getSignalTestItems(touch_device *device, unsigned char *items,
                                              int max, uint32_t mode = STE_ALL_ITEMS);
    TOUCHSHARED_EXPORT int getSignalTestStandard(touch_device *device, unsigned char index,
                    touch_test_standard *standard, uint32_t mode = STE_ALL_ITEMS);
    int getSignalTestData(touch_device *device, unsigned char testIndex, unsigned char *data,
                          int count, int *actualCount);
    //onboard
    TOUCHSHARED_EXPORT bool setOnboardTeststatus(touch_device *device,unsigned char *buffer);
    TOUCHSHARED_EXPORT int getOnboardTestboardCount(touch_device *device,unsigned char *items);
    TOUCHSHARED_EXPORT int getOnboardTestBoardAttribute(touch_device *device,unsigned char index,
                                                        get_board_attribute *boardAttribute);
    TOUCHSHARED_EXPORT int getOnboardTestItems(touch_device *device, unsigned char *items,int max, uint32_t mode = STE_ALL_ITEMS);
    TOUCHSHARED_EXPORT int getOnboardTestItemStandard(touch_device *device, unsigned char item,onboard_test_standard *itemStandard, uint32_t mode = STE_ALL_ITEMS);
    TOUCHSHARED_EXPORT bool touchOnboardTest(touch_device *device, unsigned char item,onboard_test_data_result *onboardTestData ,uint32_t mode = STE_ALL_ITEMS);
    TOUCHSHARED_EXPORT int getOnboardTestData(touch_device *device,unsigned char item,unsigned char *itemData,unsigned short max);
    TOUCHSHARED_EXPORT bool checkOnboardTestResult(touch_device *device,unsigned char *buffer);
    TOUCHSHARED_EXPORT int sendOnboardTestDataToQML(onboard_test_data_result *onboardTestData);

    int getMcuInfo(touch_device *device, mcu_info *info);

    int setTLed(touch_device *device, int on = 1);
    int isTLedOn(touch_device *device);

    TOUCHSHARED_EXPORT int setTesting(touch_device *device, int on = 1);
    TOUCHSHARED_EXPORT int isTesting(touch_device *device);

    TOUCHSHARED_EXPORT int setLockAGC(touch_device *device, int on = 1);
    TOUCHSHARED_EXPORT int isLockAGC(touch_device *device);

    int setIndicatorLed(touch_device *device, int mode);

    int setAging(touch_device *device, bool on);
    int isAging(touch_device *device);
    TOUCHSHARED_EXPORT int signalInit(touch_device *device, qint8 mode);


    TOUCHSHARED_EXPORT int getCoordsEnabled(touch_device *device, qint8 channel, qint8 *mode);
    TOUCHSHARED_EXPORT int setCoordsEnabled(touch_device *device, qint8 channel, qint8 enable);
    TOUCHSHARED_EXPORT int getCoordsMode(touch_device *device, qint8 channel, qint8 *mode);
    TOUCHSHARED_EXPORT int setCoordsMode(touch_device *device, qint8 channel, qint8 mode);
    TOUCHSHARED_EXPORT int getRotation(touch_device *device, qint8 *current, qint8 *def);
    TOUCHSHARED_EXPORT int setRotation(touch_device *device, qint8 *values);
    TOUCHSHARED_EXPORT int getMirror(touch_device *device, qint8 *cur, qint8 *def);
    TOUCHSHARED_EXPORT int setMirror(touch_device *device, qint8 *values);
    TOUCHSHARED_EXPORT int getMacOSMode(touch_device *device, qint8 *cur, qint8 *def);
    TOUCHSHARED_EXPORT int setMacOSMode(touch_device *device, qint8 mode);

    // V_03
    TOUCHSHARED_EXPORT int getCalibrationMode(touch_device *device, qint8 *mode);
    TOUCHSHARED_EXPORT int setCalibrationMode(touch_device *device, qint8 mode);
    TOUCHSHARED_EXPORT int getCalibrationSettings(touch_device *device, struct CalibrationSettings *data);
    TOUCHSHARED_EXPORT int setCalibrationSettings(touch_device *device, struct CalibrationSettings *data);
    TOUCHSHARED_EXPORT int getCalibrationPointData(touch_device *device,
                                qint8 where, qint8 index, struct CalibrationData *data);
    TOUCHSHARED_EXPORT int setCalibrationPointData(touch_device *device,
                                qint8 index, struct CalibrationData *data);
    TOUCHSHARED_EXPORT int startCalibrationCapture(touch_device *device, qint8 index);
    TOUCHSHARED_EXPORT int getCalibrationCapture(touch_device *device, struct CalibrationCapture *data);
    TOUCHSHARED_EXPORT int saveCalibrationData(touch_device *device);

    TOUCHSHARED_EXPORT int testSinglePointDraw(touch_device *device, qint8 delay = 5);
    TOUCHSHARED_EXPORT int testMultiPointDraw(touch_device *device, qint8 delay = 5);
    TOUCHSHARED_EXPORT int testCalibrationCapture(touch_device *device, qint32 time = 2000);

    TouchTestData *getSignalDatas(touch_device *device, qint32 index,
                                int dataCount = 0, bool useOldData = false);

    //config
    static void setShowTestData(bool show);
    static void setIgnoreFailedTestItem(bool ignore);
    static void setIgnoreFailedOnboardTestItem(bool ignore);
    static void setSwitchOnboardTest(bool enable);
    static void setContinueOnboardTest(bool _continueOnboardTest);
    TOUCHSHARED_EXPORT void setHutplugCheckInterval(unsigned int interval);
    static void test(void);
private:

    int addPackageToQueue(touch_package *require, touch_package *reply, touch_device *device,
                          int async, CommandThread::CommandListener *listener);
    int startHotplugService();

    int compareTouchDevice(touch_device *tda, touch_device *tdb);

    void freeHidDevice(touch_device *dev);

    int checkCommandReply(touch_package *require, touch_package *reply);
    int isCommandReplySuccessful(touch_package *require, touch_package *reply, int ret = 0, const char *func = "");

    void initDeviceInfo(touch_device *dev);
    void deepCloneDevice(touch_device *dst, touch_device *src);

    // IAP: In Application Program
    int startIAP(touch_device *dev, const struct FirewareHeader *header);
    int IAPDownload(touch_device *dev, qint32 index, const unsigned char *data, int count);
    int IAPVerify(touch_device *dev, qint32 dataLength, qint8 verifyLength, const unsigned char *verifyData);
    int IAPSetFinished(touch_device *dev);

    bool isBootloaderDevice(touch_device *dev);

    bool testSignal(touch_device *device, int testNo);


private:
    touch_device *mDevices;
    int mCount;
    hid_device_info *mRoot;

    HotplugListener *mHotplugListener;


    UpgradeThread *upgradeThread;

    TestListener *mTestListener;
    touch_device *mTestDevice;
    bool mTesting;

    UpgradeListener *mUpgradeListener;
    bool mUpgrading;

    // config
    static bool mShowTestData;
    static bool mIgnoreFailedTestItem;
    static bool mIgnoreFailedOnboardTestItem;
    static bool switchOnboardTest;
    static bool continueOnboardTest;

public:
    Trans *translator;
    HotplugThread mHotplugThread;
    CommandThread *commandThread;
    TestThread *testThread;
    bool mtestStop;
    TOUCHSHARED_EXPORT void setStop(bool stop);
    TOUCHSHARED_EXPORT static QString executeLinuxCmd(QString strCmd);
    //onboard
    int boardCount = 0;
    unsigned char boardIndexBuf[128];
};

#endif // TOUCHMANAGER_H
