#include "TouchManager.h"
#include "hidapi.h"

#include "utils/tdebug.h"
#include "utils/tPrintf.h"
#include "Fireware.h"

#include <QTime>
#include <QThread>
#include <QtEndian>
#include <QObject>
#include <QProcess>
#include <QStringList>

#define SERVICE_NAME "touch_hotplug"
#undef TVERBOSE
#define TVERBOSE(format, ...)

static char *signal_test_name[] = {
    "ADC_X_TB",
    "ADC_Y_TB",
    "ADC_X_TM",
    "ADC_Y_TM",
    "ADC_X_TF",
    "ADC_Y_TF",
    "ORG_X_TB",
    "ORG_Y_TB",
    "ORG_X_TM",
    "ORG_Y_TM",
    "ORG_X_TF",
    "ORG_Y_TF",
    "RAT_X_TB",
    "RAT_Y_TB",
    "RAT_X_TM",
    "RAT_Y_TM",
    "RAT_X_TF",
    "RAT_Y_TF",
    "TAGC_X_TB",
    "TAGC_Y_TB",
    "TAGC_X_TM",
    "TAGC_Y_TM",
    "TAGC_X_TF",
    "TAGC_Y_TF",
    "UNT_X_TB",
    "UNT_Y_TB",
    "UNT_X_TM",
    "UNT_Y_TM",
    "UNT_X_TF",
    "UNT_Y_TF",
    "RVR_X_TB",
    "RVR_Y_TB",
    "RVR_X_TM",
    "RVR_Y_TM",
    "RVR_X_TF",
    "RVR_Y_TF",
    "ADC_X_TB_ALL",
    "ADC_Y_TB_ALL",
    "ADC_X_TM_ALL",
    "ADC_Y_TM_ALL",
    "ADC_X_TF_ALL",
    "ADC_Y_TF_ALL",
    "ORG_X_TB_ALL",
    "ORG_Y_TB_ALL",
    "ORG_X_TM_ALL",
    "ORG_Y_TM_ALL",
    "ORG_X_TF_ALL",
    "ORG_Y_TF_ALL",
    "RAT_X_TB_ALL",
    "RAT_Y_TB_ALL",
    "RAT_X_TM_ALL",
    "RAT_Y_TM_ALL",
    "RAT_X_TF_ALL",
    "RAT_Y_TF_ALL",
    "AGC_X_TB_ALL",
    "AGC_Y_TB_ALL",
    "AGC_X_TM_ALL",
    "AGC_Y_TM_ALL",
    "AGC_X_TF_ALL",
    "AGC_Y_TF_ALL",
    "",
    "",
    "RSTA_X_TM",
    "RSTA_Y_TM",
    "",
    "",
    "RUNT_X_TB",
    "RUNT_Y_TB",
    "RUNT_X_TM",
    "RUNT_Y_TM",
    "RUNT_X_TF",
    "RUNT_Y_TF",
    "TLED_X",
    "TLED_Y",
    "RLED_X",
    "RLED_Y",
    "",
    "",
    "RAGC_X_TB",
    "RAGC_Y_TB",
    "RAGC_X_TM",
    "RAGC_Y_TM",
    "RAGC_X_TF ",
    "RAGC_Y_TF"
};

//static char *onboardTestItemName[] = {
//    "OTI_TLED_MASTER",
//    "OTI_TLED_ADJACENT",
//    "OTI_TLED_OPPOSITE",
//    "OTI_TLED_OPS_ADJ",
//    "OTI_RLED_MASTER",
//    "OTI_RLED_ADJACENT",
//    "OTI_RLED_OPPOSITE",
//    "OTI_RLED_OPS_ADJ",
//    "OTI_BOARD_MASTER",
//    "OTI_BOARD_ADJACENT",
//    "OTI_BOARD_OPPOSITE",
//    "OTI_BOARD_OPS_ADJ"
//};

static char *onboardTestItemName[] = {
    "底边的发射灯",
    "左边的发射灯",
    "上边的发射灯",
    "右边的发射灯",
    "底边的接收灯",
    "左边的接收灯",
    "上边的接收灯",
    "右边的接收灯",
    "底边的灯板",
    "左边的灯板",
    "上边的灯板",
    "右边的灯板"
};


#define get_standard_for_type(sd_min, sd_max, standard, type) \
    do { \
        if (type == Standard_Client) { \
            *(sd_max) = (standard)->client_max; \
            *(sd_min) = (standard)->client_min; \
        } else { \
            *(sd_max) = (standard)->factory_max; \
            *(sd_min) = (standard)->factory_min; \
        } \
    } while (false);

static const char *signalIndexToString(int index)
{
    int max = sizeof(signal_test_name) / sizeof(char*);
    if (index < 0 || (index >= max)) {
        TDEBUG("index=%d, max=%d", index, max);
        return "";
//        return QString().sprintf("%x", index).toStdString().c_str();
    }
    return signal_test_name[index];
}
static const char *onboardTestItemToString(int index)
{
    int max = sizeof(onboardTestItemName) / sizeof(char*);
    if (index < 0 || (index >= max)) {
        TDEBUG("index=%d, max=%d", index, max);
        return "";
    }
    return onboardTestItemName[index];
}
#define TEST_DEBUG(format, ...) \
    if (mShowTestData) TDebug::debug(QString().sprintf(format, ##__VA_ARGS__));

#define TEST_DEBUG_STR(str) \
    if (mShowTestData) TDebug::debug(str);


static void byteToStr(char *bytes, char *str, int len) {
    QString info;
    for (int i = 0; i < len; i++) {
        info += QString().sprintf("%02x", (unsigned char)bytes[i]);
    }
    strncpy(str, info.toStdString().c_str(), len);
}

TouchManager* TouchManager::mTouchManager = NULL;
int TouchManager::instanceCount = 0;
TouchManager* TouchManager::getInstance()
{
    if (mTouchManager == NULL) {
        mTouchManager = new TouchManager();
        TDEBUG("getInstance mTouchManager : %p", mTouchManager);
    }
    instanceCount++;
    return mTouchManager;
}
void TouchManager::freeInstance()
{
    if (instanceCount <= 0)
        return;
    instanceCount--;
    if (instanceCount == 0 && mTouchManager != NULL) {
        delete mTouchManager;
        mTouchManager = NULL;
    }
}
char TouchManager::rootPasswd[ROOT_PASSWD_LENGTH] = "123456";
TouchManager::TouchManager() : mTesting(false), mUpgrading(false),
    mHotplugThread(this), mHotplugListener(NULL), untDataBuf(NULL),
    mDevices(NULL), mCount(0), hotplugInterval(800), hotplugSem(0),
    mPauseHotplug(false),mtestStop(false),translator(NULL)
{
#if 1
    //mDevices = hid_find_touchdevice(&mCount);
    //TDEBUG("Found device = %d[%x]", mCount, mDevices);
    TDEBUG("TouchManager() this:%p", this);

    TDEBUG("start upgrade test command thread.");

    upgradeThread = new UpgradeThread(this);
    testThread = new TestThread(this);
    TDEBUG("TouchManager::TouchManager(): TestThread  = %p",testThread);
    commandThread = new CommandThread();
    commandThread->start();

    TDEBUG("start hogplug service");
    startHotplugService();

    //touch_device *tmp = mDevices;
    //while (tmp) {
        //initDeviceInfo(tmp);
        //tmp = tmp->next;
    //}
    TDEBUG("init %s", __func__);
#endif
}


TouchManager::~TouchManager()
{
#if 1

    delete upgradeThread;
    delete testThread;
    mHotplugThread.stopThread();
    mHotplugThread.wait();
    CommandThread *ct = commandThread;
    commandThread = NULL;
    ct->stopRun();
    int stop = ct->getStopVal();

    ct->wait();
    delete ct;
    ct = NULL;
    touch_device *device = devices();
    TDEBUG("free %d devices", getDeviceCount());
    while (device) {
        TDEBUG("free: %s", device->touch.id_str);
        device = device->next;
    }
    device = devices();
    free_touchdevice(device);
    UntData *unt = untDataBuf, *tmp;
    while (unt) {
        tmp = unt->next;
        free(unt->buf);
        free(unt);
        unt = tmp;
    }
    TDEBUG("upgradeThread and testThread and commandThread to be delete");
#endif
}

void TouchManager::setTr(TouchManager::Trans *translator)
{
   this->translator = translator;
}

void TouchManager::freeAllTouchDeviceInfo()
{
    touch_vendor_remove_all();
}

bool TouchManager::addTouchDeviceInfo(touch_vendor_info *info)
{
    return touch_vendor_add(info) == 0;
}

void TouchManager::test()
{
    TouchManager *tm = new TouchManager();
    delete tm;
}

void TouchManager::onCommandDone(touch_device *dev, touch_package *require, touch_package *reply)
{
    TDEBUG("%s", __func__);

    if (reply) {
#if 0
        TDEBUG("master: %x, sub: %x", reply->master_cmd, reply->sub_cmd);
        for (int i = 0; i < reply->data_length; i++) {
            TDEBUG("DATA # %x", (unsigned int)reply->data[i] & 0xff);
        }
#endif
    }
    if (require) {
        putPackage(require);
    }
    if (reply)
        putPackage(reply);
}

int TouchManager::registerHotplug(HotplugListener *listener)
{
    mHotplugListener = listener;
}


bool TouchManager::startTest(touch_device *device, TestListener *listener, StandardType st)
{
    if (mTesting || device == NULL) return false;
    mTesting = true;
    mTestListener = listener;
    mTestDevice = device;
    testThread->setStandardType(st);
    testThread->start();
}
TouchTestData *TouchManager::getSignalDatas(touch_device *device, qint32 index, int dataCount,
                                            bool useOldData)
{
    if (device == NULL || index < 0)
        return NULL;
    TouchTestData *data = new TouchTestData;
    touch_test_standard standard;
    int ret;
    unsigned char buf[1024];
    int tledState = isTLedOn(device);
//    TDEBUG("LED: 0x%x", tledState);
    if (tledState < 0)
        tledState = TLED_ON;

    if (dataCount <= 0) {
        ret = getSignalTestStandard(device, index, &standard);
        if (ret != 0) {
            TWARNING("get signal test standard failed %d", index);
            delete data;
            return NULL;
        }

        dataCount = toWord(standard.count_l, standard.count_h);
    }
    if (dataCount < 0) {
        TWARNING("data count < 0");
        delete data;
        return NULL;
    }

    int count;
    int setTled = isTestTledOn(standard);

    int isRepeat = isTestRepeat(standard);

    int testMethod = getTestMethod(standard);

    if (standard.method_enum == 0) {

        if (isRVR(index)) {
            if (tledState == TLED_ON) {
                setTLed(device, 0);
            }
        } else {
            if (tledState == TLED_OFF) {
                setTLed(device, 1);
            }
        }

        if (isUNT(index)) {
            unsigned char *bufData;
            const int TEST_COUNT = 25;
            int get_count = TEST_COUNT;
            bufData = (unsigned char*)malloc(TEST_COUNT * dataCount);
            unsigned char *oneBuf = bufData;
            unsigned char *untData;
            QString debugInfo("");
            UntData *unt = untDataBuf, *tmp;
            while (unt) {
                if (unt->index == index)
                    break;
                unt = unt->next;
            }
            int retVal;
            if (useOldData) {
                if (unt == NULL) {
                    unt = (UntData*)malloc(sizeof(UntData));
                    unt->buf = (unsigned char*)malloc(TEST_COUNT * dataCount);
                    unt->index = index;
                    unt->next = untDataBuf;
                    untDataBuf = unt;
                } else {
                    get_count = 1;
                }
            }

            // get all datas, TEST_COUNT * dataCount
            for (int ti = 0; ti < get_count; ti++) {
                untData = oneBuf + (dataCount * ti);
                retVal = getSignalTestData(device, index,
                                           oneBuf + (dataCount * ti), dataCount, &count);
                if (retVal != 0) {
                    TWARNING("test number 0x%02x, get data command failed[%d]", index, retVal);
                    count = dataCount;
                    free(bufData);
                    goto get_datas_end;
                } else {
#if 0
                    if (mShowTestData) {
                        debugInfo = QString().sprintf("UNT data %d\n", ti);

                        for (int di = 0; di < dataCount; di++) {
                            debugInfo += QString().sprintf(" 0x%02x", untData[di]);
                            if (di % 10 == 9) {
                                debugInfo += "\n";
                            }
                        }
                        TEST_DEBUG_STR(debugInfo);
                    }
#endif
                }
            }

            if (useOldData) {
                if (get_count == 1) {
                    // not the first time
                    memcpy(bufData + dataCount, unt->buf, (TEST_COUNT - 1) * dataCount);
                    memcpy(unt->buf, bufData, TEST_COUNT * dataCount);
                } else {
                    // first time, copy all data
                    memcpy(unt->buf, bufData, TEST_COUNT * dataCount);
                }
            }


            debugInfo = "";
            // delta
            for (int ti = 0; ti < dataCount; ti++) {
                unsigned char vMax = 0, vMin = 0xff;
                unsigned char tmpVal = 0;
                // find dataCount max, min
                for (int i = 0; i < TEST_COUNT; i++) {
                    tmpVal = bufData[i * dataCount + ti];
                    //TEST_DEBUG("test number 0x%02x, index %d: 0x%02x", testNo, i, tmpVal);
                    if (tmpVal > vMax)
                        vMax = tmpVal;
                    else if (tmpVal < vMin)
                        vMin = tmpVal;
                }

                unsigned char delta = vMax - vMin;

                debugInfo += QString().sprintf(" 0x%02x", delta);
                data->datas.append(delta);
            }
            if (mShowTestData)
                TDebug::debug(debugInfo);
            free(bufData);
        } else {

            ret = getSignalTestData(device, index, buf, dataCount, &count);
            if (ret != 0) {
                TWARNING("get signal test datas failed");
                delete data;
                return NULL;
            }
            for (int i = 0; i < dataCount; i++) {
                data->datas.append(buf[i]);
            }
        }


    } else {

//        TDEBUG("peter testMethod:%d", testMethod);
        switch (testMethod) {
        case STM_MAX_MIN_DIFF: {
            TDEBUG("MAX MIN");
            unsigned char *bufData;
            const int TEST_COUNT = isRepeat ? 25 : 1;
            int get_count = TEST_COUNT;
            bufData = (unsigned char*)malloc(TEST_COUNT * dataCount);
            unsigned char *oneBuf = bufData;
            unsigned char *untData;
            QString debugInfo("");
            UntData *unt = untDataBuf, *tmp;
            while (unt) {
                if (unt->index == index)
                    break;
                unt = unt->next;
            }
            int retVal;
            if (useOldData) {
                if (unt == NULL) {
                    unt = (UntData*)malloc(sizeof(UntData));
                    unt->buf = (unsigned char*)malloc(TEST_COUNT * dataCount);
                    unt->index = index;
                    unt->next = untDataBuf;
                    untDataBuf = unt;
                } else {
                    get_count = 1;
                }
            }

            // get all datas, TEST_COUNT * dataCount
            for (int ti = 0; ti < get_count; ti++) {
                untData = oneBuf + (dataCount * ti);
                retVal = getSignalTestData(device, index,
                                           oneBuf + (dataCount * ti), dataCount, &count);
                if (retVal != 0) {
                    TWARNING("test number 0x%02x, get data command failed[%d]", index, retVal);
                    count = dataCount;
                    free(bufData);
                    goto get_datas_end;
                } else {
#if 0
                    if (mShowTestData) {
                        debugInfo = QString().sprintf("UNT data %d\n", ti);

                        for (int di = 0; di < dataCount; di++) {
                            debugInfo += QString().sprintf(" 0x%02x", untData[di]);
                            if (di % 10 == 9) {
                                debugInfo += "\n";
                            }
                        }
                        TEST_DEBUG_STR(debugInfo);
                    }
#endif
                }
            }

            if (useOldData) {
                if (get_count == 1) {
                    // not the first time
                    memcpy(bufData + dataCount, unt->buf, (TEST_COUNT - 1) * dataCount);
                    memcpy(unt->buf, bufData, TEST_COUNT * dataCount);
                } else {
                    // first time, copy all data
                    memcpy(unt->buf, bufData, TEST_COUNT * dataCount);
                }
            }


            debugInfo = "";
            // delta
            for (int ti = 0; ti < dataCount; ti++) {
                unsigned char vMax = 0, vMin = 0xff;
                unsigned char tmpVal = 0;
                // find dataCount max, min
                for (int i = 0; i < TEST_COUNT; i++) {
                    tmpVal = bufData[i * dataCount + ti];
                    //TEST_DEBUG("test number 0x%02x, index %d: 0x%02x", testNo, i, tmpVal);
                    if (tmpVal > vMax)
                        vMax = tmpVal;
                    if (tmpVal < vMin)
                        vMin = tmpVal;
                }

                unsigned char delta = vMax - vMin;

                debugInfo += QString().sprintf(" 0x%02x", delta);
                data->datas.append(delta);
            }
            if (mShowTestData)
                TDebug::debug(debugInfo);
            free(bufData);

        }
            break;
        case STM_RAW_RANGE:
        default: {
//            TDEBUG("RAW RANGE");

            ret = getSignalTestData(device, index, buf, dataCount, &count);

            if (ret != 0) {
                TWARNING("get signal test datas failed");
                delete data;
                return NULL;
            }
            for (int i = 0; i < dataCount; i++) {
                data->datas.append(buf[i]);
            }
        }
            break;
        }

    }
get_datas_end:

    setTLed(device, tledState);
    data->count = dataCount;
    data->f_max = standard.factory_max;
    data->f_min = standard.factory_min;
    data->c_min = standard.client_min;
    data->c_max = standard.client_max;
    data->number = index;

    return data;
}


bool TouchManager::testSignal(touch_device *device, int testNo, StandardType standardType)
{
    int dataCount, readDataCount;
    touch_test_standard standard;
    const int testDataMax = 2048;
    unsigned char testData[testDataMax];
    bool result = true, allTestResult = true;
    unsigned char standardMin, standardMax;
    int retVal;
    int tledState = isTLedOn(mTestDevice);
    if (tledState < 0)
        tledState = 1;

    retVal = getSignalTestStandard(
                mTestDevice,
                testNo, &standard, standardType);
//    if(retVal == -3)
//        goto test_signal_end;

    int setTled = isTestTledOn(standard);
    int isRepeat = isTestRepeat(standard);
    unsigned int testMethod = getTestMethod(standard);
    unsigned int testSwitch = getTestSwitch(standard);

    TDEBUG("test 0x%02x: method enum= %d, test switch = 0x%x, test method = %d",
           testNo, standard.method_enum, testSwitch, testMethod);
    if (retVal >= 0) {
        if (standard.max == 0) {
            get_standard_for_type(&standardMin, &standardMax, &standard, standardType);
        } else {
            standardMin = standard.min;
            standardMax = standard.max;
        }
        dataCount = toWord(standard.count_l, standard.count_h);
        TDEBUG("Test Number=0x%02x, Count=%d, standard[%d - %d]", testNo,
               dataCount,
               standardMin, standardMax);

        // old method
        if (standard.method_enum == 0 && !mtestStop) {
        if (isSingleSignalTest(testNo)) {
            setTLed(mTestDevice, 1);
            result = true;

            retVal = getSignalTestData(mTestDevice, testNo, testData, dataCount, &readDataCount);
            if (retVal != 0) {
                TWARNING("test no 0x%02x, get datas failed[%d]", testNo, retVal);
                result = false;
                goto test_signal_end;
            }

            for (int i = 0; i < readDataCount && !mtestStop; i++) {
                if (testData[i] < standardMin || testData[i] > standardMax) {
                    result = false;
                    if (mIgnoreFailedTestItem == false) {
                        TWARNING("test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                                 testNo, (result ? "pass" : "failed"),
                                 standardMin, standardMax, i, testData[i]);
                        goto test_signal_end;
                    } else {
                        // 1 failed means all failed
                        if (result == false)
                            allTestResult = false;
                    }
                }
                TEST_DEBUG("test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                             testNo, (result ? "pass" : "failed"),
                             standardMin, standardMax, i, testData[i]);

            }
        } else if (isUNT(testNo) && !mtestStop) {
            setTLed(mTestDevice, 1);
            unsigned char *bufData;
            const int TEST_COUNT = 25;
            bufData = (unsigned char*)malloc(TEST_COUNT * dataCount);
            unsigned char *oneBuf = bufData;
            unsigned char *untData;
            QString debugInfo("");
            // get all datas, TEST_COUNT * dataCount
            for (int ti = 0; ti < TEST_COUNT ; ti++) {
                if(mtestStop)
                {
                    free(bufData);
                    goto test_signal_end;
                }
                untData = oneBuf + (dataCount * ti);
                retVal = getSignalTestData(mTestDevice, testNo,
                        oneBuf + (dataCount * ti), dataCount, &readDataCount);
                if (retVal != 0) {
                    TWARNING("test number 0x%02x, get data command failed[%d]", testNo, retVal);
                    result = false;
                    free(bufData);
                    goto test_signal_end;
                } else {
                    debugInfo += QString().sprintf("UNT data %d", ti);

                    for (int di = 0; di < dataCount; di++) {
                        debugInfo += QString().sprintf(" 0x%02x", untData[di]);
                        if (di % 10 == 9) {
                            debugInfo += "\n";
                        }
                    }
                }
            }

            TEST_DEBUG_STR(debugInfo);

            debugInfo = "";
            // delta
            for (int ti = 0; ti < dataCount && !mtestStop; ti++) {
                unsigned char vMax = 0, vMin = 0xff;
                unsigned char tmpVal = 0;
                // find dataCount max, min
                for (int i = 0; i < TEST_COUNT; i++) {
                    tmpVal = bufData[i * dataCount + ti];
                    //TEST_DEBUG("test number 0x%02x, index %d: 0x%02x", testNo, i, tmpVal);
                    if (tmpVal > vMax)
                        vMax = tmpVal;
                    else if (tmpVal < vMin)
                        vMin = tmpVal;
                }

                unsigned char delta = vMax - vMin;
                if (delta < standardMin || delta > standardMax) {
                    result = false;
                }

                debugInfo += QString().sprintf("UNT test number 0x%02x %s, min: 0x%02x, max: 0x%02x, Delta value[%d]: 0x%02x\n",
                           testNo, (result ? "pass" : "failed"),
                           standardMin, standardMax,
                           ti, delta);
                if (!mShowTestData && result == false) {
                    TWARNING("UNT test number 0x%02x %s, min: 0x%02x, max: 0x%02x, Delta val: 0x%02x",
                        testNo, (result ? "pass" : "failed"),
                        standardMin, standardMax, delta);
                }
                        if (mIgnoreFailedTestItem == false) {
                    if (result == false) {
                        free(bufData);
                        goto test_signal_end;
                    }
                } else {
                    // 1 failed means all failed
                        if (result == false)
                            allTestResult = false;
                }
            }
            TEST_DEBUG_STR(debugInfo);
            free(bufData);

        } else if (isRVR(testNo) &&  !mtestStop) {
            setTLed(mTestDevice, 0);

            retVal = getSignalTestData(mTestDevice, testNo, testData, dataCount, &readDataCount);
            if (retVal != 0) {
                TWARNING("RVR test no 0x%02x, get datas failed[%d]", testNo, retVal);
                result = false;
                goto test_signal_end;
            }
            for (int i = 0; i < readDataCount; i++) {
                if (testData[i] < standardMin || testData[i] > standardMax) {
                    result = false;
                    if (mIgnoreFailedTestItem == false) {
                        TDEBUG("RVR test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                                 testNo, (result ? "pass" : "failed"),
                                 standardMin, standardMax, i, testData[i]);
                        goto test_signal_end;
                    } else {
                        // 1 failed means all failed
                        if (result == false)
                            allTestResult = false;
                    }
                }
                TEST_DEBUG("RVR test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                             testNo, (result ? "pass" : "failed"),
                             standardMin, standardMax, i, testData[i]);
            }
        } else {
            TWARNING("Unknown test no 0x%02x", testNo);
            result = false;

        }
        } else {
        // new method
            if(mtestStop)
            {
                goto test_signal_end;
            }
            setTLed(mTestDevice, setTled);
            switch (testMethod) {
            case STM_RAW_RANGE: {
                int testCount = isRepeat ? 25 : 1;
                for (int tc = 0; tc < testCount &&  !mtestStop; tc++) {
                    retVal = getSignalTestData(mTestDevice, testNo, testData, dataCount, &readDataCount);
                    if (retVal != 0) {
                        TWARNING("RAW RANGE test no 0x%02x, get datas failed[%d]", testNo, retVal);
                        result = false;
                        goto test_signal_end;
                    }
                    for (int i = 0; i < readDataCount && !mtestStop; i++) {
                        if (testData[i] < standardMin || testData[i] > standardMax) {
                            result = false;
                            if (mIgnoreFailedTestItem == false) {
                                TDEBUG("RAW RANGE test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                                       testNo, (result ? "pass" : "failed"),
                                       standardMin, standardMax, i, testData[i]);
                                goto test_signal_end;
                            } else {
                                // 1 failed means all failed
                                if (result == false)
                                    allTestResult = false;
                            }
                        }
                        TEST_DEBUG("RAW RANGE test number 0x%02x %s, min: 0x%02x, max: 0x%02x, read %d val: 0x%02x",
                                   testNo, (result ? "pass" : "failed"),
                                   standardMin, standardMax, i, testData[i]);
                    }
                }
            }
                break;
            case STM_MAX_MIN_DIFF: {
                unsigned char *bufData;
                const int TEST_COUNT = isRepeat ? 25 : 1;
                bufData = (unsigned char*)malloc(TEST_COUNT * dataCount);
                unsigned char *oneBuf = bufData;
                unsigned char *untData;
                QString debugInfo("");
                // get all datas, TEST_COUNT * dataCount
                for (int ti = 0; ti < TEST_COUNT && !mtestStop; ti++) {
                    untData = oneBuf + (dataCount * ti);
                    retVal = getSignalTestData(mTestDevice, testNo,
                                               oneBuf + (dataCount * ti), dataCount, &readDataCount);
                    if (retVal != 0) {
                        TWARNING("test number 0x%02x, get data command failed[%d]", testNo, retVal);
                        result = false;
                        free(bufData);
                        goto test_signal_end;
                    } else {
                        debugInfo += QString().sprintf("UNT data %d", ti);

                        for (int di = 0; di < dataCount; di++) {
                            debugInfo += QString().sprintf(" 0x%02x", untData[di]);
                            if (di % 10 == 9) {
                                debugInfo += "\n";
                            }
                        }
                    }
                }

                TEST_DEBUG_STR(debugInfo);

                debugInfo = "";
                // delta
                for (int ti = 0; ti < dataCount && !mtestStop; ti++) {
                    unsigned char vMax = 0, vMin = 0xff;
                    unsigned char tmpVal = 0;
                    // find dataCount max, min
                    for (int i = 0; i < TEST_COUNT; i++) {
                        tmpVal = bufData[i * dataCount + ti];
                        //TEST_DEBUG("test number 0x%02x, index %d: 0x%02x", testNo, i, tmpVal);
                        if (tmpVal > vMax)
                            vMax = tmpVal;
                        // else if (tmpVal < vMin). for repeat off
                        if (tmpVal < vMin)
                            vMin = tmpVal;
                    }

                    unsigned char delta = vMax - vMin;
                    if (delta < standardMin || delta > standardMax) {
                        result = false;
                    }

                    debugInfo += QString().sprintf("UNT test number 0x%02x %s, min: 0x%02x, max: 0x%02x, Delta value[%d]: 0x%02x\n",
                                                   testNo, (result ? "pass" : "failed"),
                                                   standardMin, standardMax,
                                                   ti, delta);
                    if (!mShowTestData && result == false) {
                        TWARNING("UNT test number 0x%02x %s, min: 0x%02x, max: 0x%02x, Delta val: 0x%02x",
                                 testNo, (result ? "pass" : "failed"),
                                 standardMin, standardMax, delta);
                    }
                    if (mIgnoreFailedTestItem == false) {
                        if (result == false) {
                            free(bufData);
                            goto test_signal_end;
                        }
                    } else {
                        // 1 failed means all failed
                        if (result == false)
                            allTestResult = false;
                    }
                }
                TEST_DEBUG_STR(debugInfo);
                free(bufData);
            }
                break;
            default: {
                TWARNING("Unknown test no 0x%02x", testNo);
                result = false;
                goto test_signal_end;
            }
            }
        }

    } else {
        TWARNING("test no 0x%02x, get standard failed", testNo);
        result = false;
        goto test_signal_end;
    }
test_signal_end:
    setTLed(mTestDevice, tledState);

    if (mIgnoreFailedTestItem) {
        result = allTestResult;
    }
    return result;
}

void TouchManager::doTest()
{
    TPRINTF("%s 测试过程中",__FUNCTION__);
    TDEBUG("TouchManager::doTest()： manager->testThread = %p,this = %p", testThread, this);
    // get test info
    int testCount = 0;
    unsigned char items[128];
    int testNo;
    onboard_test_data_result onboardTestDataResult;
    onboard_test_data_result onboardTestData;
    bool onboardTestResult = true;
    int retVal;
    bool result = true;
    bool finalResult = true;
    QString info = "";
    QString errTmp;
    int retryCount = 4;
    int maxTestItem = sizeof(signal_test_name) / sizeof(char *);
    int maxOnboardTestItem = sizeof(onboardTestItemName) / sizeof(char *);
    unsigned char onboardTestItem[64];
    QVariantList failResult;
    int failItem = 0;
    bool failFlag = false;
    int onboardTestItemCount = 0;
    int touchIndex  = 0;
    unsigned char testItem;
    bool isSupport = false;
    int i = 0;
    unsigned char buffer[6];
    unsigned char onboardResult[3];
    int firewareVersion = 0;
    touch_fireware_info firewareInfo;

    if (mTestListener != NULL)
        mTestListener->inProgress(0,"");




    if(switchOnboardTest)
    {
        if(getFirewareInfo(mTestDevice,&firewareInfo) == 0)
        {
            firewareVersion = toWord(firewareInfo.version_l,firewareInfo.version_h);
        }
        if(firewareVersion >= 0x0007)
        {
            buffer[0] = ONBOARD_TEST_SWITCH_START;
            buffer[1] = ONBOARD_TEST_MODE_CLOSE;
            qToLittleEndian(testThread->standardType, &(buffer[2]));
            isSupport = setOnboardTeststatus(mTestDevice,buffer);
        }

    }

    if(isSupport)
    {
        if(!mtestStop)
            mTestListener->setNewWindowVisable();

        TDEBUG("support onboard test");

    }

    mTestListener->showTestMessageDialog("test",translator->getTr("Being detected! Do not touch!"),4);
    mTestListener->showFirewareInfo(2);

    signalInit(mTestDevice, SIGNAL_INIT_COMPLETE);

test_retry:
    if(mtestStop)
        goto do_test_end;
    QThread::msleep(1000); 
    testCount = getSignalTestItems(
                    mTestDevice,
                    items, sizeof(items), testThread->standardType);
    if (testCount <= 0) {
        if (retryCount > 0 && !mtestStop) {
            retryCount--;
            goto test_retry;
        }
        info = translator->getTr("Failed to get test item");
        finalResult = false;
        goto do_test_end;
    }
    if(mtestStop)
    {
        goto do_test_end;
    }
    //======================================================
    //======================================================
    //启动板载测试无触摸模式
    if(isSupport)
    {
        buffer[0] = ONBOARD_TEST_SWITCH_START;
        buffer[1] = ONBOARD_TEST_MODE_NOTOUCH;
        qToLittleEndian(testThread->standardType, &(buffer[2]));
        setOnboardTeststatus(mTestDevice,buffer);
    }

    if(isSupport)
    {

       retryCount = 4;
onboard_test_retry:

        onboardTestItemCount = getOnboardTestItems(mTestDevice,onboardTestItem,sizeof(onboardTestItem),testThread->standardType);
        if(onboardTestItemCount <= 0)
        {
            if (retryCount > 0) {
                retryCount--;
                goto onboard_test_retry;
            }
            info = translator->getTr("Failed to get onboard test item");
            finalResult = false;
            goto do_test_end;
        }
        TDEBUG("###onboardTestItemCount = %d",onboardTestItemCount);
        for(i = 0;i < onboardTestItemCount;i++)
        {
            TDEBUG("###onboardTestItem[%d] = %d",i,onboardTestItem[i]);
        }
    }

    //======================================================
    //======================================================
    qint8 usb_status, serial_status;
    retVal = getCoordsEnabled(mTestDevice, COORDS_CHANNEL_USB, &usb_status);
    if (retVal != 0) {
        if (retryCount > 0 && !mtestStop) {
            retryCount--;
            goto test_retry;
        }
        TERROR("%s usb coords status failed, %d", __func__, retVal);
        info = translator->getTr("Failed to get coordinate status");
        finalResult = false;
        usb_status = -1;
        serial_status = -1;
        goto do_test_end;
    }
    retVal = getCoordsEnabled(mTestDevice, COORDS_CHANNEL_SERIAL, &serial_status);
    if (retVal != 0) {
        if (retryCount > 0 && !mtestStop) {
            retryCount--;
            goto test_retry;
        }
        TERROR("%s serial coords status failed, %d", __func__, retVal);
        info = translator->getTr("Failed to get coordinate status");
        finalResult = false;
        usb_status = -1;
        serial_status = -1;
        goto do_test_end;
    }
    TDEBUG("%s get coords status, usb status=%d, serial status=%d",
           __func__, usb_status, serial_status);

    enableCoords(mTestDevice, false);

    for (int index = 0; index < testCount && !mtestStop; index++) {
        testNo = items[index];
        TDEBUG("TouchManager :manager->mtestStop = %d, %p",mtestStop, testThread);
//        TDEBUG("TouchManager :testThread->m_stop = %d", testThread->getTestStopped());

        if (mIgnoreFailedTestItem) {
            result = testSignal(mTestDevice, testNo, testThread->standardType);
            if (finalResult && !result)
                finalResult = result;
            if (!result) {
                if (testNo >= 0 && testNo < maxTestItem) {
                    errTmp = QString().sprintf("%s %s",(signalIndexToString((int)testNo & 0xff)),translator->getTr("test failed").toStdString().c_str());
                } else {
                    info = QString().sprintf("找不到0x%x测试项, 最大0x%x", testNo, maxTestItem);
                }
                TWARNING("%s", errTmp.toStdString().c_str());
            } else  {
                errTmp = "";
            }
            if (mTestListener != NULL)
            {
                if(isSupport)
                    mTestListener->inProgress((index + 1) * 90 / testCount, errTmp);
                else
                    mTestListener->inProgress((index + 1) * 100 / testCount, errTmp);
            }

        } else {
            if (testSignal(mTestDevice, testNo, testThread->standardType)) {
                if (mTestListener != NULL)
                {
                    if(isSupport)
                        mTestListener->inProgress((index + 1) * 90 / testCount, NULL);
                    else
                        mTestListener->inProgress((index + 1) * 100 / testCount, NULL);
                }

            } else {
                if (testNo >= 0 && testNo < maxTestItem) {
                    info = QString().sprintf("%s %s",(signalIndexToString((int)testNo & 0xff)),translator->getTr("test failed").toStdString().c_str());
                } else {
                    info = QString().sprintf("找不到0x%x测试项, 最大0x%x", testNo, maxTestItem);
                }
                TDEBUG("Test %d faild", testNo);
                TDEBUG("%s", info.toStdString().c_str());
                finalResult = false;

                goto do_test_end;
            }
        }

    }


    //======================================================
    //======================================================
    if(isSupport && !continueOnboardTest && !finalResult)
    {
        isSupport = false;
        for(touchIndex = 0;touchIndex < onboardTestItemCount && !mtestStop;touchIndex++)
        {
            testItem = onboardTestItem[touchIndex];
            if(mIgnoreFailedTestItem)
            {
                onboardTestResult = touchOnboardTest(mTestDevice,testItem,&onboardTestDataResult,testThread->standardType);
            }
            else
            {
                onboardTestResult = touchOnboardTest(mTestDevice,testItem,&onboardTestDataResult,testThread->standardType);
                if(!onboardTestResult)
                {
                     goto do_test_end;
                }

            }

        }
        //将板载测试数据发送给qml
        onboardTestData = onboardTestDataResult;
        sendOnboardTestDataToQML(&onboardTestData);

    }
    //切换到有触摸测试状态
    if(isSupport)
    {
        //判断无触摸测试进度是否到达100%
        while(!mtestStop)
        {
            result = checkOnboardTestResult(mTestDevice,onboardResult);
            if(!result)
            {
                TDEBUG("checkOnboardTestResult error");
                info = translator->getTr("Check the onboard test result failed");
                finalResult = false;
                goto do_test_end;
            }
            if((int)onboardResult[2] < 100)
            {
                QThread::msleep(20);
            }
            else
            {
                break;
            }

        }


        mTestListener->destroyDialog();

        memset(buffer,0,sizeof(buffer));
        buffer[0] = ONBOARD_TEST_SWITCH_START;
        buffer[1] = ONBOARD_TEST_MODE_TOUCH;
        qToLittleEndian(testThread->standardType, &(buffer[2]));
        isSupport = setOnboardTeststatus(mTestDevice,buffer);
        if(!isSupport)
        {
            errTmp = translator->getTr("Failed to switch to touch mode");
            finalResult = false;
            goto do_test_end;
        }
        if(!mtestStop)
        {
             mTestListener->showTestMessageDialog("test",translator->getTr("Please draw a picture around the touch frame"),5);
        }
        else
            goto do_test_end;

        setTLed(mTestDevice, 1);
        failResult.clear();
        while(!mtestStop )
        {

            for(touchIndex = 0;touchIndex < onboardTestItemCount && !mtestStop;touchIndex++)
            {
                testItem = onboardTestItem[touchIndex];
                if(mIgnoreFailedTestItem)
                {
                    onboardTestResult = touchOnboardTest(mTestDevice,testItem,&onboardTestDataResult,testThread->standardType);
                }
                else
                {
                    onboardTestResult = touchOnboardTest(mTestDevice,testItem,&onboardTestDataResult,testThread->standardType);
                    if(!onboardTestResult)
                    {
                         goto do_test_end;
                    }

                }

            }
            //将板载测试数据发送给qml
            onboardTestData = onboardTestDataResult;
            sendOnboardTestDataToQML(&onboardTestData);

            //检测板载测试是否完成
            result = checkOnboardTestResult(mTestDevice,onboardResult);
            if(!result)
            {
                TDEBUG("checkOnboardTestResult error");
                info = translator->getTr("Check the onboard test result failed");
                finalResult = false;
                goto do_test_end;
            }

            if(onboardResult[0] == 0x00)
            {
                info = translator->getTr("The onboard test function is not activated");
                finalResult = false;

                goto do_test_end;
            }
            else if(onboardResult[0] == 0x01)
            {
//                TDEBUG("@@onboard test not finished");
                continue;
            }
            else if(onboardResult[0] == 0x02)
            {
                info = translator->getTr("Onboard test failed");
                finalResult = false;

                goto do_test_end;
            }
            else if(onboardResult[0] == 0x03)
            {
                info = translator->getTr("Onboard test passed");
                finalResult &= true;

                goto do_test_end;
            }
        }

    }
    //======================================================
    //======================================================
do_test_end:
    if(!mtestStop)
        mTestListener->inProgress(100, "");   

    //检测每个项是否正常
    checkOnboardtestDataAbnormal(&onboardTestDataResult,onboardTestItem,onboardTestItemCount);

    mTestListener->destroyDialog();
    memset(buffer,0,sizeof(buffer));
    buffer[0] = ONBOARD_TEST_SWITCH_STOP;
    buffer[1] = ONBOARD_TEST_MODE_CLOSE;
    qToLittleEndian(testThread->standardType, &(buffer[2]));
    setOnboardTeststatus(mTestDevice,buffer);

    TDEBUG("%s resume coords status, usb status=%d, serial status=%d",
           __func__, usb_status, serial_status);
    setCoordsEnabled(mTestDevice, COORDS_CHANNEL_USB, usb_status);
    setCoordsEnabled(mTestDevice, COORDS_CHANNEL_SERIAL, serial_status);

    if (mTestListener != NULL)
        mTestListener->onTestDone(finalResult, info,mtestStop,isSupport);
    mTesting = false;

}

void TouchManager::checkOnboardtestDataAbnormal(onboard_test_data_result *onboardTestData,unsigned char *onboardTestItem,int count)
{
    int i = 0;
    int item = 0;
    QString errTmp;

    for(item = 0;item < count;item++)
    {
        if(onboardTestItem[item] == 0x00 || onboardTestItem[item] == 0x04)
        {
            for(i = 0;i < onboardTestData->downLampState.length();i++)
            {
                if(onboardTestData->downLampState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x01 || onboardTestItem[item] == 0x05)
        {
            for(i = 0;i < onboardTestData->leftLampState.length();i++)
            {
                if(onboardTestData->leftLampState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x02 || onboardTestItem[item] == 0x06)
        {
            for(i = 0;i < onboardTestData->upLampState.length();i++)
            {
                if(onboardTestData->upLampState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x03 || onboardTestItem[item] == 0x04)
        {
            for(i = 0;i < onboardTestData->rightLampState.length();i++)
            {
                if(onboardTestData->rightLampState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x08 )
        {
            for(i = 0;i < onboardTestData->downBoardState.length();i++)
            {
                if(onboardTestData->downBoardState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x09 )
        {
            for(i = 0;i < onboardTestData->leftBoardState.length();i++)
            {
                if(onboardTestData->leftBoardState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x0A )
        {
            for(i = 0;i < onboardTestData->upBoardState.length();i++)
            {
                if(onboardTestData->upBoardState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }
        else if(onboardTestItem[item] == 0x0B )
        {
            for(i = 0;i < onboardTestData->rightBoardState.length();i++)
            {
                if(onboardTestData->rightBoardState.at(i)!= 4)
                {
                    errTmp = QString().sprintf("%s %s",(onboardTestItemToString((int)onboardTestItem[item] & 0xff)),translator->getTr("test failed").toStdString().c_str());
                    mTestListener->showOnboardFailItem(errTmp);
                    break;
                }
            }
        }

    }

}

int TouchManager::enableCoords(touch_device *device, bool enable)
{
    qint8 mode = enable ? COORDS_CHANNEL_ENABLE : COORDS_CHANNEL_DISABLE;
    setCoordsEnabled(device, COORDS_CHANNEL_USB, mode);
    setCoordsEnabled(device, COORDS_CHANNEL_SERIAL, mode);
}

int TouchManager::startHotplugService()
{
    mHotplugThread.start();
}

int TouchManager::compareTouchDevice(touch_device *tda, touch_device *tdb)
{
    return wcscmp(tda->info->serial_number, tdb->info->serial_number) == 0;
}

touch_device *TouchManager::deviceByPath(const char *path)
{
    touch_device *tmp = devices();
    while (tmp) {
        if (strcmp(path, tmp->info->path) == 0)
            break;
        tmp = tmp->next;
    }
    return tmp;
}

touch_device *TouchManager::deviceBySerial(const char *serial)
{
    return devices();
}

int TouchManager::getDeviceCount()
{
    int count = 0;
    touch_device *tmp = devices();
    while (tmp) {
        tmp = tmp->next;
        count++;
    }
    return count;
}

void TouchManager::freeHidDevice(touch_device *dev)
{
    if (dev != NULL) {
        dev->info->next = NULL;
        hid_free_enumeration(dev->info);
    }
}

void TouchManager::setHutplugCheckInterval(unsigned int interval)
{
    hotplugInterval = interval;
}
void TouchManager::setHotplugByEvent(bool b)
{
    hotplugEvent = b;
}
//触发热插拔事件
void TouchManager::triggerHotplugEvent()
{
    mHotplugThread.triggerHotplugEvent();
}
//运行热插拔线程、监视是否有硬件设备的插入，如果有新的设备，那么将设备添加到设备链表touch_device
void TouchManager::HotplugThread::run()
{
    int ret;
    int found_old = 0;
    touch_device *device; //= (touch_device*)malloc(MAX_TOUCH_COUNT * sizeof(touch_device));
    touch_device *tmp, *tmp2, *cur, *last = NULL;
    hid_device_info *root;
    int try_check, try_max = 5;
    int count;

    TDEBUG("hotplug thread running");
    msleep(100);
//#define DEBUG_HOTPLUG
#ifdef DEBUG_HOTPLUG
#define hotplug_dbg(fmt, ...) TDEBUG(fmt, ##__VA_ARGS__)
#else
#define hotplug_dbg(fmt, ...)
#endif

//#define HOTPLUG_SHOW_COMSUME
    TDEBUG("hotplug thread run: %d", manager->hotplugInterval);

    manager->hotplugSem.release();
    bool stopSem;

    while (!mStop) {
//        this->msleep(manager->hotplugInterval);

        stopSem = manager->hotplugSem.tryAcquire(1, manager->hotplugInterval);
        if (mStop && stopSem == true) {
            break;
        } else if (stopSem == false && manager->hotplugEvent) {
            continue;
        }
        if (manager->mPauseHotplug)
            continue;

        {
#ifdef HOTPLUG_SHOW_COMSUME
        QTime time;
        time.start();
        TDEBUG("start check devices");
#endif

        tmp = manager->devices();

        // find plugout, check every device
        while (tmp ) {
            //hotplug_dbg("#--connected: %d", tmp->touch.connected);
            if (tmp->hid != NULL && tmp->touch.connected) {
                bool exist = false;
                for (try_check = 0; try_check < try_max; try_check++) {
                    exist = manager->checkDevice(tmp);
                    if (exist)
                        break;
                }
//                hotplug_dbg("get product string=%d", ret);
                if (!exist) {
//                    hotplug_dbg("unplug####################");
                    TDEBUG("unplug####################");
                    tmp->touch.connected = 0;
//                    hid_close(tmp->hid);

                    if (manager->mHotplugListener != NULL) {
                        tmp->touch.connected = 0;
                        manager->mHotplugListener->onTouchHotplug(tmp, 0, NULL);
                    }
                }
            }

            last = tmp;
            tmp = tmp->next;
        }

        // find plugin, enumerate hid again, get new devices
        count = 0;
        device = hid_find_touchdevice(manager->devices(),&count);
//        TDEBUG("found %d devices", count);
        hotplug_dbg("found %d devices", count);
        hotplug_dbg("last: %x", last);
        // @device: new devices
        // @tmp: old devices
        bool same = false;
        while (device) {
            cur = device;
            same = false;
            // find device in lists
            tmp = manager->devices();
            found_old = 0;

            manager->initDeviceInfo(cur);
            while (tmp) {
//                hotplug_dbg("tmp=%d, device=%d", tmp->touch.connected, device->touch.connected);
//                if (tmp->touch.connected)
//                    continue;
                //判断两个设备是否相同，相同返回true
                if (TouchManager::isSameDeviceInPort(tmp, device)) {
                    if (tmp->touch.connected) {
                        same = true;
                        break;
                    }
//                    tmp->mutex.lock();
                    TDEBUG("old one device with same usb port, %x", tmp);
//                    device->touch.connected = 1;

//                    manager->freeHidDevice(tmp);    // free old device
                    //将设备device信息复制给tmp
                    manager->deepCloneDevice(tmp, device);
//                    tmp->mutex.unlock();

                    tmp2 = cur->next;
                    cur = tmp;
//                    cur->touch.connected = 1;
//                    device->hid = NULL;
//                    device->info = NULL;
//                    free(device); // free old device
                    device = tmp2;          // device, the next new device

                    found_old = 1;
                    break;
                } else {
                    tmp = tmp->next;
                }
            }
            if (same) {
                device = device->next;
                continue;
            }

            // new one
            if (found_old == 0 && !same) {
                hotplug_dbg("new one device");
                if (last == NULL) {
                    manager->setDevices(device);
                    device = device->next;
                } else {
                    last->next = device;
                    last = device;
                    device = device->next;
                }
            }
            hotplug_dbg("init device info");
            if (!same && manager->mHotplugListener != NULL) {
                cur->touch.connected = 1;
                manager->mHotplugListener->onTouchHotplug(cur, 1, NULL);
            }
device_each_out:
            hotplug_dbg("next device: %p", device);

        }
#ifdef HOTPLUG_SHOW_COMSUME
        TDEBUG("hotplug check comsume: %dms", time.elapsed());
#endif
        }
    }
    finshed = true;
    TDEBUG("hotplug thread end");
    exit(0);
}
//初始化设备信息
void TouchManager::initDeviceInfo(touch_device *dev)
{
    TDEBUG("initDeviceInfo");
    memset(dev->touch.model, 0, sizeof(dev->touch.model));
//    QThread::msleep(10000);
    getStringInfo(dev, TOUCH_STRING_TYPE_MODEL, dev->touch.model, sizeof(dev->touch.model));
    memset(&dev->touch.mcu, 0, sizeof(mcu_info));
    getMcuInfo(dev, &dev->touch.mcu);
    byteToStr(dev->touch.mcu.id, dev->touch.id_str, sizeof(dev->touch.id_str) - 1);
    dev->touch.id_str[sizeof(dev->touch.id_str) - 1] = '\0';
    TDEBUG("initDeviceInfo finished");
}


int TouchManager::sendPackage(touch_package *package,touch_package *reply,
                touch_device *device,int async, CommandThread::CommandListener *listener)
{

    if (device == NULL) {
        device = firstConnectedDevice();
    }
    if (device == NULL) {
        TDebug::error("no device for sendData");
        return -1;
    }
    package->report_id = device->touch.report_id;
    package->version = 0x01;
//    package->magic = (int)package & 0xff;
    package->magic = 1;
    package->flow = 1;

    int ret = addPackageToQueue(package, reply, device, async, listener);

    return ret;
}

int TouchManager::addPackageToQueue(touch_package *require, touch_package *reply,
                                    touch_device *device,int async, CommandThread::CommandListener *listener)
{
    if (commandThread == NULL)
        return -1;
    int ret = commandThread->addCommandToQueue(device, require, reply, async, listener);
    return ret;
}
//发送数据包package给某一个设备,并将设备的应答数据保存到reply中
int TouchManager::sendPackageToDevice(touch_package *package, touch_package *reply, touch_device *device)
{
    if (device == NULL || device->touch.connected == 0 || device->hid == NULL) {
        TDebug::error("no device for sendPackageToDevice");
        return -1;
    }

//    TINFO("device: %s, %d" + device->touch.connected);
    if (!device->touch.connected)
        return -1;
    int ret = hid_send_data(device->hid, (struct hid_report_data*)package, (struct hid_report_data*)reply);
    return ret;
}

int TouchManager::wait_time_out(hid_device *dev, unsigned char *reply, size_t length, int milliseconds)
{
    int ret = hid_read_timeout(dev, reply, length, milliseconds);
    return ret;
}
touch_device *TouchManager::firstConnectedDevice()
{
    touch_device *tmp = devices();
    int index = 0;
    while (tmp) {
        //TDEBUG("%p: %d @%d", tmp, tmp->touch.connected, index++);
        if (tmp->touch.connected)
            return tmp;
        tmp = tmp->next;
    }
    return NULL;
}

//-------------------


TouchManager::UpgradeThread::UpgradeThread(TouchManager *mg)
{
    manager = mg;
}

int TouchManager::startUpgrade(QString path, UpgradeListener *listener)
{
    if (mUpgrading) return -1;
    mUpgrading = true;
    mUpgradeListener = listener;
    upgradeThread->path = path;
    upgradeThread->start();
    return 0;
}


bool TouchManager::isBootloaderDevice(touch_device *dev)
{
#if 1
    if (dev == NULL)
        return false;
    return !!dev->touch.booloader == 1;
#else
    if (dev && dev->touch.connected && dev->info->vendor_id == 0xAED7 && dev->info->product_id == 0xFEDC) {
//    if (dev && dev->touch.connected) {
        return true;
    }
    return false;
#endif
}

#define show_line() TDEBUG("%s [%d]", __func__, __LINE__)

void TouchManager::doUpgrade(QString path)
{
    QString upgradePath = path.replace(0, 7, "");
    TDEBUG("upgradePath = %s",upgradePath.toStdString().c_str());
    Fireware fireware(upgradePath);
    const FirewareHeader *firewareHeader;
    const FirewareFileHeader *fileHeader;
    bool result = true;
    touch_device *dev;
    QString info = "";
    int pIndex = 0, fIndex = 0;
    int ret = 0;
    unsigned char buf[64];
    int packageCount = 0;
    int firewareCount = 0;
    int allPackageIndex = 0;
    int allPackageCount = 0;
    int precent, tmpPrecent;
    const long waitBootloaderTime = 10 * 1000;
    QTime time;

    const FirewarePackage *package;
//    mUpgradeListener->showUpdateMessageDialog(" ","正在升级!请勿断开设备!",6);
    if (!fireware.isReady()) {
        result = false;
        info = translator->getTr("Firmware error");
        goto do_upgrade_end;
    }

    fileHeader = fireware.getFileHeader();
    firewareCount = fileHeader->firewareCount;
    for (fIndex = 0; fIndex < firewareCount; fIndex++) {
        package = fireware.getFirewarePackage(fIndex);
        allPackageCount += package->header.packCount;
    }
    allPackageCount += 10;

    precent = 1;
    if (mUpgradeListener != NULL)
        mUpgradeListener->inProgress(precent);
    TVERBOSE("fireware is ok, start wait bootloader");

    reset(firstConnectedDevice(), RESET_DST_BOOLOADER, 1);
    QThread::msleep(100); // wait for reset

    precent = 2;
    if (mUpgradeListener != NULL)
        mUpgradeListener->inProgress(precent);

    time.start();
    while (!isBootloaderDevice(firstConnectedDevice())) {
        if (time.elapsed() > waitBootloaderTime)
            break;
        QThread::msleep(100);
    }
    TVERBOSE("booloader ? %d", isBootloaderDevice(firstConnectedDevice()));
    dev = firstConnectedDevice();
    precent = 3;
    if (mUpgradeListener != NULL)
        mUpgradeListener->inProgress(precent);
    if (!isBootloaderDevice(dev)) {
        result = false;
        info = translator->getTr("Failed to switch to upgrade mode");
        goto do_upgrade_end;
    }
    for (fIndex = 0; fIndex < firewareCount; fIndex++) {
        package = fireware.getFirewarePackage(fIndex);
        TDEBUG("uprade: findex = %d,firewarePackage.header.packSize = %d,firewarePackage.header.packCount = %d",fIndex,
               package->header.packSize,package->header.packCount);
        firewareHeader = &package->header;
        if (firewareHeader->packSize + 4 + 1 > dev->touch.output_report_length) {
            TERROR("package size is bigger than report length");
            result = false;
            info = translator->getTr("The firmware package size is larger than the report package");
            goto do_upgrade_end;
        }

        TDEBUG("start IAP");
        ret = startIAP(dev, firewareHeader);
        if (ret) {
            TWARNING("startIAP failed, return %d", ret);
            result = false;
            info = translator->getTr("IAP failed");
            goto do_upgrade_end;
        }
        packageCount = package->header.packCount;
        for (pIndex = 0; pIndex < packageCount; pIndex++) {
            memcpy(buf, package->data + (pIndex * package->header.packSize), package->header.packSize);
            ret = IAPDownload(dev, pIndex, buf, package->header.packSize);
            TVERBOSE("IAP download %d", pIndex);
            if (ret != 0) {
                TWARNING("IAP Download %d packaged failed", pIndex);
                result = false;
                info = translator->getTr("Failed to download firmware");
                goto do_upgrade_end;
            }

            allPackageIndex++;

            tmpPrecent = (int)(allPackageIndex * 97 / allPackageCount) + 3;
            if (precent != tmpPrecent) {
                precent = tmpPrecent;
                if (mUpgradeListener != NULL)
                    mUpgradeListener->inProgress(precent);
            }
        }
        TDEBUG("IAP vVerify");
        ret = IAPVerify(dev, package->header.packCount * package->header.packSize,
                  package->header.verifyCodeSize, (const unsigned char *)package->header.verifyCode);
        if (ret != 0) {
            TWARNING("IAP Verify %d packaged failed", pIndex);
            result = false;
            info = translator->getTr("Failed to verify firmware");
            goto do_upgrade_end;
        }
    }

    TDEBUG("IAP set finished");
    ret = IAPSetFinished(dev);
    if (ret != 0) {
        TWARNING("IAP Set Finished failed");
        result = false;
        info = "IAP FINISHED " + translator->getTr("failed");
        goto do_upgrade_end;
    }
    TDEBUG("reset to app");
    reset(dev, RESET_DST_APP, 0);
    QThread::msleep(2300);
    if (mUpgradeListener != NULL)
        mUpgradeListener->inProgress(100);

do_upgrade_end:
//    mUpgradeListener->destroyDialog();
    if (mUpgradeListener != NULL) {
        mUpgradeListener->onUpgradeDone(result, info);
    }
    mUpgrading = false;
}

void TouchManager::UpgradeThread::run()
{
    TDebug::debug("run upgrade thread");
    manager->doUpgrade(path);
    TDebug::debug("upgrade thread end");
}
TouchManager::TestThread::TestThread(TouchManager *mg) :
    standardType(Standard_Factory)
{
    manager = mg;
}

void TouchManager::setStop(bool stop)
{
    TDEBUG("TouchManager::TestThread::setStop");
    mtestStop = stop;
    TDEBUG("TestThread:stop = %d",mtestStop);
    TDEBUG("this: %p", this);


}

QString TouchManager::executeLinuxCmd(QString strCmd)
{
    QProcess p;
    p.start("bash",QStringList()<< "-c" << strCmd);
    p.waitForFinished();
    QString strResult = p.readAllStandardOutput();
    return strResult;
}
void TouchManager::TestThread::run()
{
    TDebug::debug("run test thread");

    manager->doTest();
    TDebug::debug("test thread end");
}

// commands
int TouchManager::reset(touch_device *device, int dst, int delay, int async)
{
    unsigned char data[2];
    data[0] = dst;
    data[1] = delay;
    // will free by this::onCommandDone;
    touch_package *package = getPackage(TOUCH_M_CMD_FIREWARE_UPGRADE,
                                        TOUCH_S_CMD_RESET_DEVICE,
                                        2, data);
    return sendPackage(package, NULL, device, async, this);
}

int TouchManager::setTLed(touch_device *device, int on)
{
    unsigned char data = (on == TLED_ON || on == 1) ? TLED_ON : TLED_OFF;
    touch_package *package = getPackage(TOUCH_M_CMD_HARDWARE,
                                        TOUCH_S_CMD_SET_TLED,
                                        1, &data);
    touch_package *reply = getPackage(0, 0, 0, 0);
    int ret = sendPackage(package, reply, device);
    if (ret < 0) return ret;
    ret = !touch_reponse_ok(reply);

    putPackage(package);
    putPackage(reply);
    return ret;
}

int TouchManager::isTLedOn(touch_device *device)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_GET_TLED, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }

    return reply.data[0] == TLED_ON ? TLED_ON : TLED_OFF;
}

int TouchManager::setTesting(touch_device *device, int on)
{
    unsigned char data = (on == TESTING_ON || on == 1) ? TESTING_ON : TESTING_OFF;
    touch_package *package = getPackage(TOUCH_M_CMD_HARDWARE,
                                        TOUCH_S_CMD_SET_TESTING,
                                        1, &data);
    touch_package *reply = getPackage(0, 0, 0, 0);
    int ret = sendPackage(package, reply, device);
    if (ret < 0) return ret;
    ret = !touch_reponse_ok(reply);
    TINFO("set test : %d", on);

    putPackage(package);
    putPackage(reply);
    return ret;
}

int TouchManager::isTesting(touch_device *device)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_GET_TESTING, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }

    return reply.data[0] == TESTING_ON ? TESTING_ON : TESTING_OFF;
}

int TouchManager::setLockAGC(touch_device *device, int on)
{
    unsigned char data = (on == LOCK_AGC_ENABLE || on == 1) ? LOCK_AGC_ENABLE : LOCK_AGC_DISABLE;
    touch_package *package = getPackage(TOUCH_M_CMD_HARDWARE,
                                        TOUCH_S_CMD_SET_LOCK_AGC,
                                        1, &data);
    touch_package *reply = getPackage(0, 0, 0, 0);
    int ret = sendPackage(package, reply, device);
    if (ret < 0) return ret;
    ret = !touch_reponse_ok(reply);
    TINFO("set lock AGC: %d", on);

    putPackage(package);
    putPackage(reply);
    return ret;
}

int TouchManager::isLockAGC(touch_device *device)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_GET_LOCK_AGC, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }

    return reply.data[0] == LOCK_AGC_ENABLE ? LOCK_AGC_ENABLE : LOCK_AGC_DISABLE;
}


bool TouchManager::checkDevice(touch_device *dev)
{
    if (dev == NULL) {
        TDEBUG("checkDevice == NULL");
        return false;
    }
    int exist = hid_check(dev);
//    TDEBUG("check = %d\n", exist);
    return exist == 1;
#if 0
    struct hid_report_data data;
    int re = hid_read_timeout(dev->hid, (unsigned char*)&data, 0, 100);
    TDEBUG("#########ret: %d", re);
    if (re >= 0) {
        return true;
    }
    return false;
//#else
    touch_package require, reply;
    memset(&require, 0, sizeof(touch_package));
    memset(&reply, 0, sizeof(touch_package));
    require.master_cmd = TOUCH_M_CMD_DEVICE_INFO;
    require.magic = 0xaa;
    require.sub_cmd = TOUCH_S_CMD_GET_MCU_INFO;
    require.data_length = 1;
    require.data[0] = TOUCH_STRING_TYPE_VENDOR;

    int ret = sendPackage(&require, &reply, dev);
    if (ret < 0)
        return false;

//    qDebug("%x %x = %x", reply.master_cmd, reply.magic, require.magic);
    if (reply.magic == require.magic) {
        return true;
    }
    return false;
#endif
}

int TouchManager::getStringInfo(touch_device *device, int type, char *str, int max)
{
    if (device == NULL || str == NULL) {
        return -1;
    }
    touch_package require, reply;
    memset(&require, 0, sizeof(touch_package));
    memset(&reply, 0, sizeof(touch_package));
    require.master_cmd = TOUCH_M_CMD_DEVICE_INFO;
    require.sub_cmd = TOUCH_S_CMD_GET_STRING_INFO;
    require.data_length = 1;
    require.data[0] = type;

    int ret = sendPackage(&require, &reply, device);

    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(str, &reply.data[2], max > reply.data_length ? max : (reply.data_length - 1));

    int strLen = reply.data_length - 1;//reply.data[1];
    if (strLen < max)
        str[strLen - 1] = '\0';
//    TINFO("%s: %s", __func__, str);
    return 0;
}

int TouchManager::getFirewareInfo(touch_device *device, touch_fireware_info *info)
{
    if (device == NULL || info == NULL) {
        return -1;
    }
    touch_package require, reply;
    memset(&require, 0, sizeof(touch_fireware_info));
    memset(&reply, 0, sizeof(touch_fireware_info));
    require.master_cmd = TOUCH_M_CMD_DEVICE_INFO;
    require.sub_cmd = TOUCH_S_CMD_GET_FIRMWARE_INFO;

    int ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }

    memcpy(info, reply.data, sizeof(touch_fireware_info));
#if 0
    unsigned char *i = (unsigned char*)reply.data;
    for (int j = 0; j < reply.data_length; j++) {
        TDEBUG("## %x", i[j]);
    }
#endif
    return 0;
}

int TouchManager::getSignalTestItems(touch_device *device, unsigned char *items,
            int max, uint32_t mode)
{
    if (device == NULL || items == NULL) {
        return -1;
    }
    unsigned char *temp = items;
    unsigned char buffer[64];
    int remain, count = 0;
    int perGetCount = 50;
    int ret;
    buffer[0] = 0;
    buffer[1] = perGetCount;
    qToLittleEndian(mode, &(buffer[2]));

    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_SIGNAL_TEST_ITEM, 6, buffer);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    ret = sendPackage(&require, &reply, device);
    //TDEBUG("read %d, count: %d, actual: %d", 0, reply.data[0], reply.data[2]);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(items, &reply.data[3], reply.data[2]);
    remain = max > reply.data[0] ? reply.data[0] : max;
    remain -= reply.data[2];
    count += reply.data[2];
//    TDEBUG("count:%d, remain:%d", count, remain);
#if 1 // TODO: try get all
    for (int index = count; remain > 0&& !mtestStop;) {
        memset(buffer, 0, sizeof(buffer));
        memset(&reply, 0, sizeof(reply));
        buffer[0] = index;
        buffer[1] = perGetCount;
        qToLittleEndian(mode, &(buffer[2]));
        SET_PACKAGE(&require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_SIGNAL_TEST_ITEM, 6, buffer);
        ret = sendPackage(&require, &reply, device);
        //TDEBUG("read %d(%d), count: %d, actual: %d", index, reply.data[1], reply.data[0], reply.data[2]);
        if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
            return -2;
        }
        count += reply.data[2];
        remain -= reply.data[2];
        memcpy((items + index), &reply.data[3], reply.data[2]);
        index += reply.data[2];
    }
#endif


#if 1
    TDEBUG("test count:%d", count);
#endif

    return count;
}

int TouchManager::getSignalTestData(touch_device *device, unsigned char testIndex,
                                    unsigned char *data, int count, int *actualCount)
{
    int ret;
    if (device == NULL || data == NULL || count <= 0)
        return -1;
    unsigned short perCount = 50;
    int remain = count, retCount, cpyCount;
    unsigned short index = 0;
    unsigned char *dst = data;
    int tryTime = 5;

    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_SIGNAL_DATA, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    require.data_length = 5;
    require.data[0] = testIndex;
    perCount = device->touch.output_report_length - require.data_length - 9;

    while (remain > 0) {
        wordToPackage(index, &require.data[1]);
        wordToPackage(perCount, &require.data[3]);

        ret = sendPackage(&require, &reply, device);

//        touch_package *package,touch_package *reply = NULL,
//                            touch_device *device = NULL,int async = 0, CommandThread::CommandListener *listener = NULL,
//                                               CommandItem *item = NULL)
        if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
            return -2;
        }
        if (index != toWord(reply.data[1], reply.data[2])) {
            if (tryTime) {
                tryTime--;
                continue;
            }
            TWARNING("%s: index is not match", __func__);
            return -3;
        }
        retCount = toWord(reply.data[3], reply.data[4]);
        cpyCount = retCount > remain ? remain : retCount;
        memcpy(dst, &reply.data[5], cpyCount);
        dst += cpyCount;
        index += cpyCount;
        remain -= cpyCount;
        if (cpyCount < perCount) {
            // all is done
            break;
        }
    }
    if (actualCount) {
        *actualCount = (int)(dst - data);
    }
    return 0;
}

int TouchManager::getOnboardTestItems(touch_device *device, unsigned char *items, int max, uint32_t mode)
{
    if (device == NULL || items == NULL)
    {
            return -1;
    }

    unsigned char *temp = items;
    unsigned char buffer[6];
    int remain, count = 0;
    int perGetCount = 50;
    int ret;
    buffer[0] = 0;
    buffer[1] = perGetCount;
    qToLittleEndian(mode, &(buffer[2]));

    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_ONBOARD_TEST_ITEM, 6, buffer);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    ret = sendPackage(&require, &reply, device);
    //TDEBUG("read %d, count: %d, actual: %d", 0, reply.data[0], reply.data[2]);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(items, &reply.data[3], reply.data[2]);
    remain = max > reply.data[0] ? reply.data[0] : max;
    remain -= reply.data[2];
    count += reply.data[2];
    for (int index = count; remain > 0;) {
            memset(buffer, 0, sizeof(buffer));
            memset(&reply, 0, sizeof(reply));
            buffer[0] = index;
            buffer[1] = perGetCount;
            qToLittleEndian(mode, &(buffer[2]));
            SET_PACKAGE(&require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_ONBOARD_TEST_ITEM, 6, buffer);
            ret = sendPackage(&require, &reply, device);
            if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
                return -2;
            }
            count += reply.data[2];
            remain -= reply.data[2];
            memcpy((items + index), &reply.data[3], reply.data[2]);
            index += reply.data[2];
        }
    TDEBUG("onboard test item count:" + count);
    return count;
}

int TouchManager::getOnboardTestItemStandard(touch_device *device, unsigned char item, onboard_test_standard *itemStandard, uint32_t mode)
{
    if (device == NULL || mtestStop)
            return -1;

    unsigned char buf[5];
    int ret;
    buf[0] = item;
    qToLittleEndian(mode, &(buf[1]));
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_ONBOARD_TEST_ATTRIBUTE, 5, buf);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    memset(reply.data, 0, sizeof(reply.data));
    ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(itemStandard, reply.data, 11);

    return 0;

}

bool TouchManager::touchOnboardTest(touch_device *device, unsigned char item,onboard_test_data_result *onboardTestData, uint32_t mode)
{
    bool result = true;
    onboard_test_standard itemStandard ;
    int ret = getOnboardTestItemStandard(device,item,&itemStandard,mode);
    if(ret != 0)
    {
        TDEBUG("%d item  getOnboardTestItemStandard error",item);
        return false;
    }
    unsigned short testCount = toWord(itemStandard.count_l,itemStandard.count_h);

//    TDEBUG("%d item  = %d",item,testCount );
//    TDEBUG("%d item itemStandard.faultValue = %d",item,itemStandard.faultValue );
//    TDEBUG("%d item itemStandard.warnValue = %d",item,itemStandard.warnValue );
//    TDEBUG("%d item itemStandard.qualifiedValue = %d",item,itemStandard.qualifiedValue );
//    TDEBUG("%d item itemStandard.goodValue = %d",item,itemStandard.goodValue );


    unsigned char buffer[testCount];
    memset(buffer,0,sizeof(buffer));
    int dataCount = getOnboardTestData(device,item,buffer,sizeof(buffer));
    if(dataCount < 0)
    {
        TDEBUG("%d item  getOnboardTestData error",item);
        return false;
    }

    if(item == 0x00 || item == 0x04)
        onboardTestData->downLampState.clear();
    if(item == 0x01 || item == 0x05)
        onboardTestData->leftLampState.clear();
    if(item == 0x02 || item == 0x06)
        onboardTestData->upLampState.clear();
    if(item == 0x03 || item == 0x07)
        onboardTestData->rightLampState.clear();
    if(item == 0x08)
        onboardTestData->downBoardState.clear();
    if(item == 0x09)
        onboardTestData->leftBoardState.clear();
    if(item == 0x0A)
        onboardTestData->upBoardState.clear();
    if(item == 0x0B)
    onboardTestData->rightBoardState.clear();
    for(int i = 0;i < dataCount;i++)
    {
//        TDEBUG("getOnboardTestData:item = %d,buffer[%d] = %d",item,i,buffer[i]);
        if(item == 0x00 || item == 0x04)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->downLampState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->downLampState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->downLampState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->downLampState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->downLampState.append(4);
            }

        }
        else if(item == 0x01 || item == 0x05)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->leftLampState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->leftLampState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->leftLampState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->leftLampState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->leftLampState.append(4);
            }

        }
        else if(item == 0x02 || item == 0x06)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->upLampState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->upLampState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->upLampState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->upLampState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->upLampState.append(4);
            }

        }
        else if(item == 0x03 || item == 0x07)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->rightLampState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->rightLampState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->rightLampState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->rightLampState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->rightLampState.append(4);
            }

        }
        else if(item == 0x08)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->downBoardState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->downBoardState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->downBoardState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->downBoardState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->downBoardState.append(4);
            }

        }
        else if(item == 0x09)
        {
            onboardTestData->leftBoardState.clear();
            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->leftBoardState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->leftBoardState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->leftBoardState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->leftBoardState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->leftBoardState.append(4);
            }

        }
        else if(item == 0x0A)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->upBoardState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->upBoardState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->upBoardState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->upBoardState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->upBoardState.append(4);
            }

        }
        else if(item == 0x0B)
        {

            if(buffer[i] < itemStandard.faultValue )
            {
                onboardTestData->rightBoardState.append(0);
                result = false;

            }
            else if(buffer[i] >= itemStandard.faultValue && buffer[i] < itemStandard.warnValue)
            {
                onboardTestData->rightBoardState.append(1);
            }
            else if(buffer[i] >= itemStandard.warnValue && buffer[i] < itemStandard.qualifiedValue)
            {
                onboardTestData->rightBoardState.append(2);
            }
            else if(buffer[i] >= itemStandard.qualifiedValue && buffer[i] < itemStandard.goodValue)
            {
                onboardTestData->rightBoardState.append(3);
            }
            else if(buffer[i] >= itemStandard.goodValue)
            {
                onboardTestData->rightBoardState.append(4);
            }

        }
    }
    return result;
}

int TouchManager::getOnboardTestData(touch_device *device, unsigned char item, unsigned char *itemData,unsigned short max)
{
    if (device == NULL || mtestStop)
            return -1;
    unsigned char buffer[5];
    unsigned short perCount = 50;;
    unsigned short writeCount = 0;
    unsigned short readCount = 0;
    int retCount = 0;
    unsigned short index = 0;
    int tryTime = 5;
    int ret ;

    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_ONBOARD_TEST_DATA, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    require.data_length = 5;
    require.data[0] = item;
    perCount = device->touch.output_report_length - require.data_length - 9;

    do
    {
        wordToPackage(index, &require.data[1]);
        wordToPackage(perCount, &require.data[3]);

        ret = sendPackage(&require, &reply, device);
        if (!isCommandReplySuccessful(&require, &reply, ret, __func__))
            return -2;
        if (index != toWord(reply.data[1], reply.data[2]))
        {
            if (tryTime) {
                tryTime--;
                continue;
            }
            TWARNING("%s: index is not match", __func__);
            return -3;
        }
        readCount = toWord(reply.data[3], reply.data[4]);
        index += readCount;
        if(index > max)
        {
            writeCount = max - (index - readCount);
        }
        else
        {
            writeCount = readCount;
        }

        memcpy(itemData + retCount,&reply.data[5],writeCount);
        retCount += writeCount;
    }while(readCount > 0 && index < max);


    return retCount;
}

bool TouchManager::checkOnboardTestResult(touch_device *device, unsigned char *buffer)
{
    if (device == NULL && mtestStop) {
        return false;
    }
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_ONBOARD_TEST_RESULT, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return false;
    }
    buffer[0] = reply.data[0];
    buffer[1] = reply.data[1];
    buffer[2] = reply.data[6];
    return true;
}

int TouchManager::sendOnboardTestDataToQML(onboard_test_data_result *onboardTestData)
{
    QVariantMap map;
    map.insert("downLampState",onboardTestData->downLampState);
    map.insert("leftLampState",onboardTestData->leftLampState);
    map.insert("upLampState",onboardTestData->upLampState);
    map.insert("rightLampState",onboardTestData->rightLampState);

    map.insert("downBoardState",onboardTestData->downBoardState);
    map.insert("leftBoardState",onboardTestData->leftBoardState);
    map.insert("upBoardState",onboardTestData->upBoardState);
    map.insert("rightBoardState",onboardTestData->rightBoardState);

    mTestListener->refreshOnboardTestData(map);
}

int TouchManager::getMcuInfo(touch_device *device, mcu_info *info)
{
    if (device == NULL || info == NULL) {
        return -1;
    }
    unsigned char buf = 0;
    int ret;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_MCU_INFO, 0, &buf);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    int len = sizeof(mcu_info);
    memcpy(info, reply.data, len);
    return 0;
}

int TouchManager::getSignalTestStandard(touch_device *device, unsigned char index,
            touch_test_standard *standard, uint32_t mode)
{
    if (device == NULL || standard == NULL) {
        return -1;
    }
    unsigned char buf[5];
    int ret;
    buf[0] = index;
    qToLittleEndian(mode, &(buf[1]));
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, TOUCH_S_CMD_GET_SIGNAL_TEST_STAN, 5, &buf);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    memset(reply.data, 0, sizeof(reply.data));
    ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(standard, reply.data, 18);//sizeof(touch_test_standard));
//    standard->method_enum = (unsigned int)reply.data[17];
//    TDEBUG("mmmm = %d", standard->method_enum);
//    standard->method_enum = 3;
    if (reply.data_length < 18) {
        standard->method_enum = 0;
    } else {
        standard->method_enum = reply.data[17];
//        standard->method_enum = 3;
    }
//        standard->new_command = 1;
//        standard->method_enum = (unsigned int)reply.data[17];
//        TDEBUG("method enum: %d", standard->method_enum);
//    } else {
//        standard->new_command = 0;
//    }
    return 0;
}

int TouchManager::setAging(touch_device *device, bool on)
{
    unsigned char data = on ? 0x01 : 0x00;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_SET_AGING, 1, &data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);

    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::setIndicatorLed(touch_device *device, int mode)
{
    unsigned char data = (unsigned char)mode;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_SET_AGING, 1, &data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}


int TouchManager::startIAP(touch_device *dev, const FirewareHeader *header)
{
    unsigned char data[44];
    if (dev == NULL || header == NULL)
        return -1;
    qToLittleEndian(header->deviceIdRangeStart, (void*)(&data[0]));
    qToLittleEndian(header->deviceIdRangeEnd, (void*)(&data[2]));
    qToLittleEndian(header->packSize, (void*)(&data[4]));
    qToLittleEndian(header->packCount, (void*)(&data[8]));
    //qToLittleEndian(header->handShakeCode, (void*)(&data[12]));
    memcpy((void*)(&data[12]), (const void*)header->handShakeCode, sizeof(header->handShakeCode));

extern int hidReadTimeOut;
    hidReadTimeOut = 30000;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_FIREWARE_UPGRADE, TOUCH_S_CMD_IAP_START, sizeof(data), &data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, dev);
    hidReadTimeOut = 30000;
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::IAPDownload(touch_device *dev, qint32 index, const unsigned char *data, int count)
{
    if (dev == NULL || data == NULL || index < 0 || count < 0)
        return -1;
    unsigned char buf[64];
    qToLittleEndian(index, buf);
    memcpy((void*)(&buf[4]), (const void*)data, count);

    DEFINE_PACKAGE(require, TOUCH_M_CMD_FIREWARE_UPGRADE, TOUCH_S_CMD_IAP_DOWNLOAD, count + 4, buf);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, dev);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::IAPVerify(touch_device *dev, qint32 dataLength, qint8 verifyLength, const unsigned char *verifyData)
{
    if (dev == NULL || verifyData == NULL || dataLength < 0 || verifyLength < 0)
        return -1;
    unsigned char buf[64];
    qToLittleEndian(dataLength, buf);
    qToLittleEndian(verifyLength, (void*)(&buf[4]));

    memcpy((void*)(&buf[5]), (void*)verifyData, verifyLength);

    DEFINE_PACKAGE(require, TOUCH_M_CMD_FIREWARE_UPGRADE, TOUCH_S_CMD_IAP_VERIFY, verifyLength + 5, buf);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, dev);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::IAPSetFinished(touch_device *dev)
{
    if (dev == NULL || !dev->touch.connected)
        return -1;

    DEFINE_PACKAGE(require, TOUCH_M_CMD_FIREWARE_UPGRADE, TOUCH_S_CMD_IAP_FINISHED, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);

    int ret = sendPackage(&require, &reply, dev);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::isAging(touch_device *device)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_GET_AGING, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return reply.data[0] ? 1: 0;
}

int TouchManager::getCoordsEnabled(touch_device *device, qint8 channel, qint8 *mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_GET_COORDS_ENABLED, 1, &channel);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    *mode = reply.data[1];
    TINFO("%s %d=%d", __func__, channel, *mode);
    return 0;
}

int TouchManager::setCoordsEnabled(touch_device *device, qint8 channel, qint8 enable)
{
    QString str1;
    QString str2;
    if(channel == 0x01)
        str1 = "USB channel";
    else if(channel == 0x02)
        str1 = "Serial channel";
    else
        str1 = "channel choose error!";

    if(enable == 0x00)
        str2 = "disenable ";
    else if(enable == 0x01)
        str2 = "enable ";
    TPRINTF("%s %s%s",__FUNCTION__, str2.toStdString().c_str(),str1.toStdString().c_str());
    qint8 data[2] = {channel, enable};
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_SET_COORDS_ENABLED, 2, data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    TINFO("%s %d=%d", __func__, channel, enable);
    if (ret < 0)
    {
        TPRINTF("%s sendPackage command error!!!",__FUNCTION__);
        return ret;
    }
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        TPRINTF("%s reply failed[%d,%d], require[%d,%d]",
                 __func__,
                 reply.master_cmd, reply.sub_cmd,
                 require.master_cmd, require.sub_cmd);
        return -2;
    }
    TPRINTF("set successfully");
    return 0;
}

int TouchManager::getCoordsMode(touch_device *device, qint8 channel, qint8 *mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_GET_COORDS_MODE, 1, &channel);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    *mode = reply.data[1];
    return 0;
}

int TouchManager::setCoordsMode(touch_device *device, qint8 channel, qint8 mode)
{
    qint8 data[2] = {channel, mode};
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_SET_COORDS_MODE, 2, data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::getRotation(touch_device *device, qint8 *current, qint8 *def)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_GET_ROTATION, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    current[0] = reply.data[0];
    current[1] = reply.data[1];
    def[0] = reply.data[2];
    def[1] = reply.data[3];
    return 0;
}

int TouchManager::testSinglePointDraw(touch_device *device, qint8 delay)
{
    DEFINE_PACKAGE(require, 0xFD, 0x01, 1, &delay);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::testMultiPointDraw(touch_device *device, qint8 delay)
{
    DEFINE_PACKAGE(require, 0xFD, 0x02, 1, &delay);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::testCalibrationCapture(touch_device *device, qint32 time)
{
    qint8 toTime[4];
    TDEBUG("%s %d", __func__, time);
    qToLittleEndian(time, (void*)(&toTime[0]));
    DEFINE_PACKAGE(require, 0xFD, 0x05, 4, toTime);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    TDEBUG("%s done", __func__);
    return 0;
}

int TouchManager::setRotation(touch_device *device, qint8 *values)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_SET_ROTATION, 2, values);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::getMirror(touch_device *device, qint8 *cur, qint8 *def)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_GET_REFLECTION, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    cur[0] = reply.data[0];
    cur[1] = reply.data[1];
    def[0] = reply.data[2];
    def[1] = reply.data[3];
    return 0;
}

int TouchManager::setMirror(touch_device *device, qint8 *values)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_SET_REFLECTION, 2, values);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::getMacOSMode(touch_device *device, qint8 *cur, qint8 *def)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_GET_MACOS_MODE, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    cur[0] = reply.data[0];
//    cur[1] = reply.data[1];
    def[0] = reply.data[1];
//    def[1] = reply.data[3];
    return 0;
}

int TouchManager::setMacOSMode(touch_device *device, qint8 mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_COORDS, TOUCH_S_CMD_SET_MACOS_MODE, 1, &mode);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::signalInit(touch_device *device, qint8 mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_SIGNAL_INITIAL, 1, &mode);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        TERROR("signal init failed with mode %d", mode);
        return -2;
    }
    return 0;
}

bool TouchManager::setOnboardTeststatus(touch_device *device,unsigned char *buffer)
{
    if(device == NULL)
        return -1;

    DEFINE_PACKAGE(require, TOUCH_M_CMD_HARDWARE, TOUCH_S_CMD_START_ONBOARD_TEST, 6, buffer);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0)
    {
        TDEBUG("setOnboardTeststatus error");
        return false;
    }
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        TERROR("%s  failed ",__FUNCTION__);
        return false;
    }

    return true;
}

int TouchManager::getOnboardTestboardCount(touch_device *device, unsigned char *items)
{
    int boardCount = 0;
    if(device == NULL)
        return -1;
    unsigned char buffer[2];
    int count = 0;
    int remain;
    int perGetCount = 30;
    buffer[0] = 0;
    buffer[1] = perGetCount;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, ONBOARD_TEST_GET_BOARD_COUNT, 2, buffer);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        TERROR("getOnboardTestboardCount  failed ");
        return -2;
    }
    count = reply.data[0];

    boardCount += reply.data[2];
    memcpy(items,&reply.data[3],reply.data[2]);
    remain = count - boardCount;

    for(;remain > 0 && !mtestStop;)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&reply, 0, sizeof(reply));
        buffer[0] = boardCount;
        buffer[1] = perGetCount;
        DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, ONBOARD_TEST_GET_BOARD_COUNT, 2, buffer);
        DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
        int ret = sendPackage(&require, &reply, device);
        if (ret < 0) return ret;
        if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
            TERROR("getOnboardTestboardCount  failed ");
            return -2;
        }
        memcpy((items+boardCount),&reply.data[3],reply.data[2]);
        boardCount += reply.data[2];
        remain -= reply.data[2];

    }
    TDEBUG("getOnboardTestboardCount board count = %d",boardCount);
    return boardCount;
}

int TouchManager::getOnboardTestBoardAttribute(touch_device *device, unsigned char index, get_board_attribute *boardAttribute)
{
    if(device == NULL || index < 0)
        return -1;
    unsigned char boardIndex = index;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_DEVICE_INFO, ONBOARD_TEST_GET_BOARD_ATTRIBUTE, 1, &boardIndex);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    memset(reply.data, 0, sizeof(reply.data));
    int ret = sendPackage(&require, &reply, device);
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {

        return -2;
    }

    memcpy(boardAttribute,reply.data,7);
    

   return 0;
}

// V_03
int TouchManager::getCalibrationMode(touch_device *device, qint8 *mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_GET_WORK_MODE, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    *mode = reply.data[0];
    return 0;
}

int TouchManager::setCalibrationMode(touch_device *device, qint8 mode)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_SET_WORK_MODE, 1, &mode);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::getCalibrationSettings(touch_device *device, struct CalibrationSettings *data)
{
    if (data == NULL)
        return -1;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_GET_CALI_SETTINGS, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    memcpy(data, reply.data, 4);
    return 0;
}

int TouchManager::setCalibrationSettings(touch_device *device, CalibrationSettings *data)
{
    if (data == NULL)
        return -1;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_SET_CALI_SETTINGS, 2, data);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::startCalibrationCapture(touch_device *device, qint8 index)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_START_CAPTURE, 1, &index);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::saveCalibrationData(touch_device *device)
{
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_SAVE_CALI_DATA, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

int TouchManager::getCalibrationCapture(touch_device *device, CalibrationCapture *data)
{
    if (data == NULL)
        return -1;
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_GET_CAPTURE_DATA, 0, NULL);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    data->index = reply.data[0];
    data->finished = qFromLittleEndian<qint16>(&reply.data[1]);
    data->count = qFromLittleEndian<qint16>(&reply.data[3]);
    return 0;
}

int TouchManager::getCalibrationPointData(touch_device *device,
        qint8 where, qint8 index, CalibrationData *data)
{
    if (data == NULL)
        return -1;
    qint8 temp[2] = {where, index};
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_GET_CALI_POINT_DATA, 2, temp);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    data->targetX = qFromLittleEndian<qint32>(&reply.data[2]);
    data->targetY = qFromLittleEndian<qint32>(&reply.data[6]);
    data->collectX = qFromLittleEndian<qint32>(&reply.data[10]);
    data->collectY = qFromLittleEndian<qint32>(&reply.data[14]);
    data->maxX = qFromLittleEndian<qint32>(&reply.data[18]);
    data->maxY = qFromLittleEndian<qint32>(&reply.data[22]);

    return 0;
}

int TouchManager::setCalibrationPointData(touch_device *device, qint8 index, CalibrationData *data)
{
    if (data == NULL)
        return -1;
    qint8 temp[25];
    temp[0] = index;
    qToLittleEndian(data->targetX, &temp[1]);
    qToLittleEndian(data->targetY, &temp[5]);
    qToLittleEndian(data->collectX, &temp[9]);
    qToLittleEndian(data->collectY, &temp[13]);
    qToLittleEndian(data->maxX, &temp[17]);
    qToLittleEndian(data->maxY, &temp[21]);
    DEFINE_PACKAGE(require, TOUCH_M_CMD_CALIBRATION, TOUCH_S_CMD_SET_CALI_POINT_DATA, 25, temp);
    DEFINE_PACKAGE(reply, 0, 0, 0, NULL);
    int ret = sendPackage(&require, &reply, device);
    if (ret < 0) return ret;
    if (!isCommandReplySuccessful(&require, &reply, ret, __func__)) {
        return -2;
    }
    return 0;
}

//----------------------------

int TouchManager::checkCommandReply(touch_package *require, touch_package *reply)
{
    if ((reply->master_cmd == TOUCH_M_CMD_RESPONSE && reply->sub_cmd == TOUCH_S_CMD_SUCCEED) ||
            (require->master_cmd == reply->master_cmd &&
            require->sub_cmd == reply->sub_cmd)) {
        return 1;
    }
    // 0 for error
    return 0;
}

int TouchManager::isCommandReplySuccessful(touch_package *require, touch_package *reply, int ret, const char *func)
{
    if (ret < 0) {
        TWARNING("%s send error", func);
        return 0;
    }

    if (!checkCommandReply(require, reply)) {
        TWARNING("%s reply failed[%d,%d], require[%d,%d]",
                 func,
                 reply->master_cmd, reply->sub_cmd,
                 require->master_cmd, require->sub_cmd);
        return 0;
    }
    return 1;
}
//深拷贝设备
void TouchManager::deepCloneDevice(touch_device *dst, touch_device *src)
{
    dst->hid = src->hid;
    dst->info = src->info;
    memcpy(&dst->touch, &src->touch, sizeof(dst->touch));
}

bool TouchManager::isSameDeviceInPort(touch_device *a, touch_device *b)
{
#if 0
    TDEBUG("A: %s", a->touch.id_str);
    TDEBUG("B: %s", b->touch.id_str);
#endif
#if 0
    return false;
#else
    if (memcmp(a->touch.mcu.id, b->touch.mcu.id, sizeof(b->touch.mcu.id)))
        return true;
    else
        return false;
#endif
}

bool TouchManager::mShowTestData = false;
bool TouchManager::mIgnoreFailedTestItem = false;
bool TouchManager::mIgnoreFailedOnboardTestItem = false;
bool TouchManager::switchOnboardTest = false;
bool TouchManager::continueOnboardTest = false;
void TouchManager::setIgnoreFailedTestItem(bool ignore)
{
    mIgnoreFailedTestItem = ignore;
}

void TouchManager::setIgnoreFailedOnboardTestItem(bool ignore)
{
    mIgnoreFailedOnboardTestItem = ignore;
}

void TouchManager::setSwitchOnboardTest(bool enable)
{
    switchOnboardTest = enable;
}

void TouchManager::setContinueOnboardTest(bool _continueOnboardTest)
{
    continueOnboardTest = _continueOnboardTest;
}
void TouchManager::setShowTestData(bool show)
{
    mShowTestData = show;
}

