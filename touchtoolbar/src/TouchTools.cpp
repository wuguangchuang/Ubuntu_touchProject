#include "TouchTools.h"
#include "stdio.h"
#include "sdk/hidapi.h"

#include "sdk/tdebug.h"
#include "sdk/tPrintf.h"

#include "sdk/touch.h"
#include "sdk/TouchManager.h"
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QtEndian>
#include <QSemaphore>
//#include <windows.h>

using namespace Touch;
#define UPGRADE_FILE_DIR  "config/"
#define UPGRADE_FILE_NAME "upgrade"
#define AUTO_UPDATE_DIR "FirmwareBin/"

//显示消息框
void TouchTools::showMessageDialog(QString title, QString message, int type)
{
    presenter->showDialog(title, message, type);
}

void TouchTools::doUpgradeFireware()
{

}

void TouchTools::restoreUpgradeFile()
{
    QString path = QString().sprintf("%s%s", UPGRADE_FILE_DIR, UPGRADE_FILE_NAME);
    if (!QDir(UPGRADE_FILE_DIR).exists() && !QDir(".").mkdir(UPGRADE_FILE_DIR)) {
        path = QString(UPGRADE_FILE_NAME);
    }

    TINFO("read upgrade file");
    QFile file(path);

    char upgradeFile[10240];
    qint64 readCount = 0;
    if (!file.open(QIODevice::ReadOnly|QIODevice::Text)) {
        TDebug::debug("can not open upgrade file:" + file.errorString());
    } else {

        readCount = file.read(upgradeFile, sizeof(upgradeFile) - 1);
        if (readCount < 0) {
            TWARNING("read upgrade file failed(%d)", readCount);
            TDebug::error(file.errorString());
        } else {
            TDEBUG("read count %d", readCount);
            if (readCount == 0) {
                TDEBUG("read upgrade file, nothing");
            } else {
                upgradeFile[readCount] = '\0';
                TDEBUG("Upgrade file: %s", upgradeFile);

                char *tmp = strtok(upgradeFile,"\n");
                QFile f(QString(tmp).replace(0, 7, ""));
                if (f.exists()) {
                    upgradePath = tmp;
                    presenter->setFileText(tmp);
                }
                TDEBUG("Upgrade file tmp: %s", tmp);
                while(tmp)
                {
                    tmp = strtok(NULL,"\n");
                    QFile f(QString(tmp).replace(0, 7, ""));
                    if (f.exists()) {
                        TDEBUG("Upgrade file tmp: %s", tmp);
                        upgradePath = tmp;
                        presenter->setFileText(tmp);
                    }
                }

            }
        }
    }
    file.close();
}

void TouchTools::onTouchHotplug(touch_device *dev, const int attached, const void *val)
{
    TDEBUG("hotplug: %s, B:%d, 0x%04x:0x%04x [%d][%p]",
           dev->touch.model, dev->touch.booloader, dev->info->vendor_id,
           dev->info->product_id, dev->touch.connected, dev);


    appendMessageText(QString(dev->touch.booloader ? "Bootloader" : "TouchApp") + " " +
                            QString(dev->touch.model) + " " +
                            (dev->touch.connected ? tr("connected") : tr("disconnected")), 0);
    if((getAppType() == APP_FACTORY || getAppType() == APP_RD) && dev->touch.booloader && dev->touch.connected)
    {
        QString version = "";
        QString checksum = "";
        touch_fireware_info finfo;
        mTouchManager->getFirewareInfo(dev, &finfo);
        version = QString().sprintf(" 0x%04X", toWord(finfo.version_l, finfo.version_h));
        checksum = QString().sprintf(" 0x%04X", toWord(finfo.checksum_l, finfo.checksum_h));
        QString message = tr("Fireware version:") + version +"   "+ tr("Fireware checksum:") + checksum;
        appendMessageText(message,0);
    }
    qint8 mode = 0;
    if(argc > 1 && strcmp(argv[1],"-changeCoordsMode") == 0)
    {
        argcTimer->stop();
        int setCoordsSuccessRet = -1;
        if(dev != NULL && !dev->touch.booloader && dev->touch.connected)
        {
            setCoordsSuccessRet = mTouchManager->getCoordsMode(dev,COORDS_CHANNEL_USB,&mode);
            if(mode == 1)
            {
                setCoordsSuccessRet = mTouchManager->setCoordsMode(dev,COORDS_CHANNEL_USB,0x02);
            }
            else if(mode == 2)
            {
                setCoordsSuccessRet = mTouchManager->setCoordsMode(dev,COORDS_CHANNEL_USB,0x01);
            }
        }
//        if(setCoordsSuccessRet < 0)
//        {
//            if(language == en_US)
//                MessageBox(NULL,TEXT("Set coordinate mode failed"),TEXT("Coordinate"),MB_ICONHAND|MB_OK);
//            else
//                MessageBox(NULL,TEXT("设置坐标模式失败"),TEXT("坐标"),MB_ICONHAND|MB_OK);
//        }
//        else
//        {
//            if(mode == 1)
//            {
//                if(language == en_US)
//                    MessageBox(NULL,TEXT("Set to multi-touch mode"),TEXT("Coordinate"),MB_ICONINFORMATION|MB_OK);
//                else
//                   MessageBox(NULL,TEXT("设置为多点触摸模式"),TEXT("坐标"),MB_ICONINFORMATION|MB_OK);
//            }
//            else if(mode == 2)
//            {
//                if(language == en_US)
//                    MessageBox(NULL,TEXT("Set to simulate mouse mode"),TEXT("Coordinate"),MB_ICONINFORMATION|MB_OK);
//                else
//                   MessageBox(NULL,TEXT("设置为模拟鼠标模式"),TEXT("坐标"),MB_ICONINFORMATION|MB_OK);
//            }

//        }
        mTouchManager->mHotplugThread.stopThread();
        TDEBUG("桌面快捷方式切换坐标模式");
        exit(0);
    }

    //发送信号
    emit presenter->hotplug(QVariant::fromValue((attached == 1)));
    if (!dev->touch.booloader)
        presenter->refreshSettings();
    touchAging.onTouchHotplug(dev, attached, val);
    if(attached == 1 && !dev->touch.booloader)
    {
        showFirewareInfo(0);
        getBoardAttribyteData();


        if(firstTimeUpdate)
        {
            char fileName[200];
            memset(fileName,0,sizeof(fileName));
            sprintf(fileName,"%s.bin",dev->touch.model);
            TDEBUG("需要升级的固件：%s",fileName);
            firstTimeUpdate = false;
            autoUpdatePath.clear();
            bool flag = false;
            QString dirPath = AUTO_UPDATE_DIR;
            if (QDir(AUTO_UPDATE_DIR).exists()) {
                QDir *dir = new QDir(dirPath);
                QStringList filter;
                QList<QFileInfo> *fileInfo = new QList<QFileInfo>(dir->entryInfoList(filter));
                for(int f = 0;f <fileInfo->count();f++)
                {

                    TDEBUG("路径：%s",fileInfo->at(f).fileName().toStdString().c_str());
                    if((QString)fileName == fileInfo->at(f).fileName())
                    {
                        memset(fileName,0,sizeof(fileName));
                        sprintf(fileName,"file:///%s/%s",dir->absolutePath().toStdString().c_str(),
                                fileInfo->at(f).fileName().toStdString().c_str());
                        TDEBUG("绝对路径：%s",fileName);
//                        upgradePath = fileName;

                        presenter->setAutoUpgradeFile((QString)fileName);
                        startUpgrade();
                        flag = true;
                    }
                }

            }
            else{
                TDEBUG("目录不存在");
            }
            if(!flag)
            {
                presenter->showToast(tr("file does no exist"));
            }

        }

    }
    TDEBUG("autoTestSwitch = %d",autoTestSwitch ? 1:0);
    if(autoTestSwitch)
    {
        if(dev->touch.connected && !dev->touch.booloader)
        {
            TDEBUG("自动升级");
            autoTestConnect(dev);
        }
        if(!dev->touch.connected && !dev->touch.booloader)
        {
            clearTestInfo();
        }
    }
}


void TouchTools::doTest()
{

    //showMessage("测试", "测试成功!");
}

void TouchTools::setAutoTestSwitch(bool testSwitch)
{
    autoTestSwitch = testSwitch;
}

void TouchTools::autoTestConnect(touch_device *dev)
{
    presenter->autoTestConnect();
}

void TouchTools::clearTestInfo()
{
    presenter->clearTestInfo();
}

void TouchTools::setUpgradeProgess(int process)
{
    //发送升级进度信号
     emit presenter->setUpgradeProgress(process);
}

//开始测试的槽函数
void TouchTools::startTest()
{
    presenter->setTesting(true);
    mTestLstener.inProgress(0,"");
    testThread.start();
    /*
    if (mTouchManager->firstConnectedDevice() == NULL){
        showMessageDialog(tr("Error"), tr("Cannot find devices!!"), 2);

        presenter->setTestButtonEnable(true);
        presenter->setTestButtonCheck(false);
        presenter->setTesting(false);
        return;
    }
    */

//    presenter->setTestButtonEnable(false);
//    uint32_t mode = STE_ALL_ITEMS;
//    switch (getAppType()) {
//    case APP_CLIENT:
//        mode = STE_END_USER_TEST;
//        break;
//    case APP_FACTORY:
//        mode = STE_FACTORY_TEST;
//        break;
//    case APP_RD:
//        mode = STE_DEV_TEST;
//        break;
//    case APP_PCBA:
//        mode = STE_PCBA_CUSTOMER_TEST;
//        break;
//    }

//    mTouchManager->startTest(mTouchManager->firstConnectedDevice(),
//                             &mTestLstener,
//                             (StandardType)mode);
//    appendMessageText(tr("开始测试"),2);
}

void TouchTools::TestThread::run()
{
    touch_device *dev;
    bool firstTime = true;
    setCancel(false);
    touchTool->presenter->setTextButtonText(TouchTools::tr("Cancel test"));
    do
    {
        dev = touchTool->mTouchManager->firstConnectedDevice();

        if (dev == NULL || !dev->touch.connected || dev->touch.booloader)
        {
            if(firstTime)
            {
                touchTool->showMessage(TouchTools::tr("Error"), TouchTools::tr("No connected devices!"), 7);
                firstTime = false;
            }
            QThread::msleep(100);
            if(isCanceled())
            {
                touchTool->presenter->setTextButtonText(TouchTools::tr("Test"));
                touchTool->presenter->setTestButtonCheck(false);
                touchTool->presenter->setTesting(false);
                return;
            }
        }
    }while(dev == NULL || !dev->touch.connected || dev->touch.booloader);
    touchTool->presenter->destroyDialog();
    touchTool->appendMessageText(TouchTools::tr("Start test"),2);
    if(!firstTime)
        msleep(1000);

    uint32_t mode = STE_ALL_ITEMS;
    switch (touchTool->getAppType()) {
    case APP_CLIENT:
        mode = STE_END_USER_TEST;
        break;
    case APP_FACTORY:
        mode = STE_FACTORY_TEST;
        break;
    case APP_RD:
        mode = STE_DEV_TEST;
        break;
    case APP_PCBA:
        mode = STE_PCBA_CUSTOMER_TEST;
        break;
    }

    touchTool->mTouchManager->startTest(touchTool->mTouchManager->firstConnectedDevice(),
                             &touchTool->mTestLstener,
                             (StandardType)mode);

}

void TouchTools::onStopAll()
{
    mTouchManager->mHotplugThread.stopThread();
    mTouchManager->commandThread->setStopValue();
    TDEBUG("onstopAll function is running,please waiting...");
}

void TouchTools::onSetTestThreadStop(bool stop)
{
    TDEBUG("@@@onSetTestThreadStop %p, %p", (mTouchManager->testThread), mTouchManager);
    mTouchManager->setStop(stop);
    TDEBUG("@@@@@");
}

void TouchTools::setTestThreadCancel(bool t)
{
    testThread.setCancel(t);
}
//开始运行更新
void TouchTools::UpgradeThread::run()
{
    TDEBUG("start upgrade running");
    touch_device *dev;
    waiting = true;
    running = true;
    cancel = false;
    bool firstTime = true;
    touchTool->presenter->setUpgrading(true);
    do {
        dev = touchTool->mTouchManager->firstConnectedDevice();
//        qDebug("@%d @%d @%d", isCanceled(), (dev), (!dev ? 0 : dev->touch.connected));
        if (dev == NULL || !dev->touch.connected)
        {
            touchTool->presenter->setUpgradeButtonText(TouchTools::tr("Cancel upgrade"));
            if(firstTime)
            {
                touchTool->showMessage(TouchTools::tr("Error"), TouchTools::tr("Please plug in device"), 7);
                firstTime = false;
            }
        }
        msleep(100);
        if (isCanceled()) {
            waiting = false;
            running = false;
            touchTool->presenter->setUpgrading(false);
            touchTool->presenter->setUpgradeButtonText(TouchTools::tr("Upgrade"));
            cancel = false;
            return;
        }
    } while (dev == NULL || !dev->touch.connected);
    touchTool->presenter->destroyDialog();
    waiting = false;

    touchTool->showMessage(" ",TouchTools::tr("Upgrading! Do not disconnect the device"),6);
    touchTool->presenter->setUpgradeButtonEnable(false);

//    touchTool->presenter->setUpgradeButtonText(tr("Start"));
    int result = touchTool->mTouchManager->startUpgrade(touchTool->upgradePath, &touchTool->mUpgradeListener);
    if (result != 0) {
        touchTool->showMessage(TouchTools::tr("Upgrade"), TouchTools::tr("Uprade failure"));
        touchTool->presenter->setUpgradeButtonEnable(true);

    }
    running = false;
    TDEBUG("start upgrade end");
}

void TouchTools::startUpgrade()
{
    if (upgradeThread.isWaiting()) {
        upgradeThread.setCancel();
//        presenter->setUpgradeButtonText( tr("during upgrade"));
        return;
    }
    if (upgradeThread.isRunning())
        return;

    presenter->setUpgradeProgress(0);
    upgradeThread.start();
}

void TouchTools::setUpdatePath(QString path)
{
    upgradePath = path;
}

void TouchTools::upgradeFireware(QString path)
{
    setUpgradeFile(path);
    startUpgrade();
}

void TouchTools::setUpgradeFile(QString path)
{

    QString fpath = QString().sprintf("%s%s", UPGRADE_FILE_DIR, UPGRADE_FILE_NAME);
    if (!QDir(UPGRADE_FILE_DIR).exists() && !QDir(".").mkdir(UPGRADE_FILE_DIR)) {
        fpath = QString(UPGRADE_FILE_NAME);
    }
    QFile file(fpath);

//    if (!file.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Truncate)) {
//        TWARNING("can not open upgrade file");
//    }
    if (!file.open(QIODevice::ReadWrite|QIODevice::Text|QIODevice::Append)) {
        TWARNING("can not open upgrade file");
    }
    //TDebug::debug(file.fileName());
    QTextStream out(&file);
    out << path;
    out << "\n";
    file.close();
    upgradePath = path;

}

void TouchTools::clearComboBoxData()
{
    QString fpath = QString().sprintf("%s%s",UPGRADE_FILE_DIR, UPGRADE_FILE_NAME);
    if (!QDir(UPGRADE_FILE_DIR).exists() && !QDir(".").mkdir(UPGRADE_FILE_DIR)) {
        fpath = QString(UPGRADE_FILE_NAME);
    }
    QFile file(fpath);
    if(!file.open(QFile::WriteOnly|QFile::Truncate))
    {
        TDEBUG("clear upgrade file error");
        return ;
    }
    else
    {
        TINFO("clear upgrade file success");
    }
    file.close();
}

TouchTools::InitSdkThread::InitSdkThread(TouchTools *tool)
{
    touchTool = tool;
}

void TouchTools::triggerUsbHotplug()
{

    mTouchManager->triggerHotplugEvent();
}

void TouchTools::InitSdkThread::run(void)
{
    TDebug::info("init touch sdk");
    touchTool->mTouchManager = TouchManager::getInstance();
    touchTool->presenter->setTouchManager(touchTool->mTouchManager);
    touchTool->touchAging.setManager(touchTool->mTouchManager);
    touchTool->mCurDevice = touchTool->mTouchManager->firstConnectedDevice();
    touchTool->mDeviceCount = touchTool->mTouchManager->getDeviceCount();
    touchTool->mTouchManager->registerHotplug(touchTool);
    touchTool->mTouchManager->setTr(touchTool);
    if (touchTool->hotplugInterval > 0)
        touchTool->mTouchManager->setHutplugCheckInterval(touchTool->hotplugInterval);
    TDebug::debug(QString().sprintf("found %d", touchTool->mDeviceCount));

    touchTool->mTouchManager->setHotplugByEvent(false);

    if (touchTool->mDeviceCount > 0) {
        touch_device *dev = touchTool->mTouchManager->firstConnectedDevice();
        if (dev){
            touchTool->appendMessageText(
                        QString().sprintf("%s %s ",
                                    (dev->touch.booloader ? "Bootloader" : "TouchApp"),
                                    dev->touch.model) + tr("connected") + "\n",0);
        }
    }

    touchTool->restoreUpgradeFile();

#if 0
    if (touchTool->mTouchManager->firstConnectedDevice()) {
        TouchTestData *data = touchTool->mTouchManager->getSignalDatas(
                    touchTool->mTouchManager->firstConnectedDevice(), 1);
        if (data != NULL) {
            TDEBUG("%d, %d - %d", data->count, data->min, data->max);
            int size = data->datas.size();
            QString info = "";
            for (int i = 0; i < size; i++) {
                info += " " + data->datas.at(i).toString();
            }
            TDebug::debug(info);
            delete data;
        }
    }
#endif

    TDebug::info("init done");
   touchTool->presenter->initSdkDone = true;
}

QVariant TouchTools::getRelativeInfo()
{
    QString info = "";
    touch_device *dev = mTouchManager->firstConnectedDevice();
#if 0
    if (dev == NULL || !dev->touch.connected) {
//        info = "没有设备连接!";
        info = "<font color='red'>没有设备连接!</font>";
    } else {
        touch_fireware_info finfo;
        mTouchManager->getFirewareInfo(dev, &finfo);
        info += "<b>设备信息</b><br>";
        info += QString().sprintf("设备名称: %s<br>", dev->touch.model);
        info += QString().sprintf("固件版本: 0x%04X<br>", toWord(finfo.version_l, finfo.version_h));
        info += QString().sprintf("固件验证码: 0x%04X<br>", toWord(finfo.checksum_l, finfo.checksum_h));
        info += QString().sprintf("支持的触摸点数: %d<br>", finfo.touch_point);
        info += QString().sprintf("USB VID: 0x%04X<br>", toWord(finfo.usb_vid_l, finfo.usb_vid_h));
        info += QString().sprintf("USB PID: 0x%04X<br>", toWord(finfo.usb_pid_l, finfo.usb_pid_h));
    }

    info += "<br><b>软件信息</b><br>";
    info += "软件名称: TouchAssistant<br>";
    info += QString().sprintf("软件版本: %s<br>", APP_VERSION_NAME);
    info += "操作系统长名称: " + QSysInfo::prettyProductName() + "<br>";
    info += "操作系统版本: " + QSysInfo::kernelVersion() + "<br>";
#else
    if (dev == NULL || !dev->touch.connected) {
        info = tr("No connected devices!") + "\n";
    } else {
        touch_fireware_info finfo;
        mTouchManager->getFirewareInfo(dev, &finfo);
        if(language)
        {
            info += tr("Device infomation");
            info += "\n";
            info += tr("Device name:") + "                    " +QString(dev->touch.model).toStdString().c_str()   + "\n";
            info += tr("Fireware version:") + QString().sprintf("                    0x%04X\n",toWord(finfo.version_l, finfo.version_h));
            info += tr("Fireware checksum:") + QString().sprintf("               0x%04X\n", toWord(finfo.checksum_l, finfo.checksum_h));
            info += tr("Support touch number:") + QString().sprintf("      %d\n", finfo.touch_point);
            info += QString().sprintf("USB VID:                    0x%04X\n", toWord(finfo.usb_vid_l, finfo.usb_vid_h));
            info += QString().sprintf("USB PID:                    0x%04X\n", toWord(finfo.usb_pid_l, finfo.usb_pid_h));
        }
        else
        {
            info += tr("Device infomation");
            info += "\n";
            info += tr("Device name:") + "                        " +QString(dev->touch.model).toStdString().c_str()   + "\n";
            TDEBUG("111111111version_l = %d,version_h = %d",finfo.version_l,finfo.version_h);
            TDEBUG("toWord(finfo.version_l, finfo.version_h) = %d",toWord(finfo.version_l, finfo.version_h));
            info += tr("Fireware version:") + QString().sprintf("                   0x%04X\n", toWord(finfo.version_l, finfo.version_h));
            info += tr("Fireware checksum:") + QString().sprintf("             0x%04X\n", toWord(finfo.checksum_l, finfo.checksum_h));
            info += tr("Support touch number:") + QString().sprintf("          %d\n", finfo.touch_point);
            info += QString().sprintf("USB VID:                                    0x%04X\n", toWord(finfo.usb_vid_l, finfo.usb_vid_h));
            info += QString().sprintf("USB PID:                                    0x%04X\n", toWord(finfo.usb_pid_l, finfo.usb_pid_h));
        }

    }


    char *versionType = "";
    switch (THIS_APP_TYPE) {
    case APP_FACTORY:
        versionType = "F";
        break;
    case APP_CLIENT:
        versionType = "C";
        break;
    case APP_PCBA:
        versionType = "P";
        break;
    case APP_RD:
        versionType = "R";
        break;
    default:
        break;
    }
    if(language)
    {
        info += "\n" + tr("Software information") + "\n";
        info += tr("Software Name") + "                     TouchAssistant\n";
        info += tr("Software version:") + QString().sprintf("                   %s.%s\n",
                    APP_VERSION_NAME, versionType);
        info += tr("OS name:") + "          " + QSysInfo::prettyProductName() + "\n";
        info += tr("OS version:") + "          " + QSysInfo::kernelVersion() + "\n";
    }
    else
    {
        info += "\n" + tr("Software information") + "\n";
        info += tr("Software Name") + "                     TouchAssistant\n";
        info += tr("Software version:") + QString().sprintf("                 %s.%s\n",
                    APP_VERSION_NAME, versionType);
        info += tr("OS name:") + "                                 " + QSysInfo::prettyProductName() + "\n";
        info += tr("OS version:") + "                              " + QSysInfo::kernelVersion() + "\n";
    }

#endif
    return QVariant::fromValue(info);
}
bool TouchTools::whetherDeviceConnect()
{
    touch_device *dev = mTouchManager->firstConnectedDevice();
    if (dev == NULL || !dev->touch.connected)
        return false;
    else
        return true;
}
QVariant TouchTools::getDeviceInfoName()
{
    QString info = "";
    info += tr("Device infomation") + "\n";
    info += tr("Device name:") + "\n";
    info += tr("Fireware version:") + "\n";
    info += tr("Fireware checksum:") + "\n";
    info += tr("Support touch number:") + "\n";
    info += "USB VID:\n";
    info += "USB PID:\n";

    return QVariant::fromValue(info);
}
QVariant TouchTools::getDeviceInfo()
{
    QString info = "";
    touch_device *dev = mTouchManager->firstConnectedDevice();

    if (dev == NULL || !dev->touch.connected) {
        info = tr("No connected devices!");
    } else {
        touch_fireware_info finfo;
        mTouchManager->getFirewareInfo(dev, &finfo);
        info += "\n";
        info += QString(dev->touch.model) + "\n";
        info += QString().sprintf("0x%04X\n", toWord(finfo.version_l, finfo.version_h));
        info += QString().sprintf("0x%04X\n", toWord(finfo.checksum_l, finfo.checksum_h));
        info += QString().sprintf("%d\n", finfo.touch_point);
        info += QString().sprintf("0x%04X\n", toWord(finfo.usb_vid_l, finfo.usb_vid_h));
        info += QString().sprintf("0x%04X\n", toWord(finfo.usb_pid_l, finfo.usb_pid_h));
    }

    return QVariant::fromValue(info);
}
QVariant TouchTools::getSoftwareInfoName()
{
     QString info = "";
     info += tr("Software information") + "\n";
     info += tr("Software Name:") + "\n";
     info += tr("Software version:") + "\n";
     info += tr("OS name:") + "\n";
     info += tr("OS version:") + "\n";
     return QVariant::fromValue(info);
}
QVariant TouchTools::getSoftwareInfo()
{
    QString info = "";
    info += " \n";
    char *versionType = "";
    switch (THIS_APP_TYPE) {
    case APP_FACTORY:
        versionType = "F";
        break;
    case APP_CLIENT:
        versionType = "C";
        break;
    case APP_PCBA:
        versionType = "P";
        break;
    case APP_RD:
        versionType = "R";
        break;
    default:
        break;
    }
    info += "TouchAssistant\n";
    info +=QString().sprintf("%s.%s\n",
                APP_VERSION_NAME, versionType);
    info +=QSysInfo::prettyProductName() + "\n";
    info +=QSysInfo::kernelVersion() + "\n";
    return QVariant::fromValue(info);
}


QVariantMap TouchTools::getBoardAttribyteData()
{
    unsigned char boardIndexBuf[128];
    int boardCount = 0;

    QVariantList items;
    QVariantList attritubeData;
    get_board_attribute attribute;
    QVariantMap att;
    int boardIndex;
    int retryCount = 4;
    int lampCount = 0;

    map.clear();
onboard_test_retry:
    boardCount = mTouchManager->getOnboardTestboardCount(mTouchManager->firstConnectedDevice(),boardIndexBuf);
    if(boardCount <= 0)
    {
        if (retryCount > 0)
        {
            retryCount--;
            presenter->msleep(100);
            goto onboard_test_retry;
        }
        map.insert("result",1);
        goto do_test_end;
    }
    //获取板子属性
    for(boardIndex = 0;boardIndex < boardCount ;boardIndex++)
    {
        items.append(boardIndexBuf[boardIndex]);

        memset(&attribute,0,sizeof(attribute));
        mTouchManager->getOnboardTestBoardAttribute(mTouchManager->firstConnectedDevice(),boardIndexBuf[boardIndex],&attribute);
        att.insert("num",attribute.num);
        att.insert("direction",attribute.direction);
        att.insert("order",attribute.order);

        if(toWord(attribute.launchLampCount_l,attribute.launchLampCount_h) > 0)
            lampCount = toWord(attribute.launchLampCount_l,attribute.launchLampCount_h);
        if(toWord(attribute.recvLampCount_l,attribute.recvLampCount_h) > 0)
            lampCount = toWord(attribute.recvLampCount_l,attribute.recvLampCount_h);
        att.insert("lampCount",lampCount);

        attritubeData.append(QVariant::fromValue(att));
        
//        TDEBUG("getBoardAttribyteData：board num = %d,direction = %d,order = %d,lampCount = %d",
//           attribute.num,attribute.direction,attribute.order,lampCount);
    }

    map.insert("result",0);

do_test_end:
    map.insert("items",items);
    map.insert("attritubeData",attritubeData);
    return map;
}

void TouchTools::showFirewareInfo(int type)
{
    QString info = "";
        touch_device *dev = mTouchManager->firstConnectedDevice();

        if (dev == NULL || !dev->touch.connected) {
            info = tr("No connected devices!");
        } else {
            touch_fireware_info finfo;
            mTouchManager->getFirewareInfo(dev, &finfo);
            info = QString().sprintf("%s 0x%04X   ",tr("Fireware version:").toStdString().c_str(), toWord(finfo.version_l, finfo.version_h));
            info += QString().sprintf("%s 0x%04X",tr("Fireware checksum:").toStdString().c_str(), toWord(finfo.checksum_l, finfo.checksum_h));
            appendMessageText(info,type);
        }
}

QVariantMap TouchTools::getSignalItems()
{
    unsigned char buf[1024];
    QVariantMap map;
    uint32_t mode = STE_ALL_ITEMS;
    switch (getAppType()) {
    case APP_CLIENT:
        mode = STE_END_USER_GRAPH;
        break;
    case APP_FACTORY:
        mode = STE_FACTORY_GRAPH;
        break;
    case APP_RD:
        mode = STE_DEV_GRAPH;
        break;
    case APP_PCBA:
        mode = STE_PCBA_CUSTOMER_GRAPH;
        break;
    }

    int count = mTouchManager->getSignalTestItems(mTouchManager->firstConnectedDevice(),
                                      buf, sizeof(buf), mode);
    TDEBUG("items count: %d", count);
    if (count <= 0) {
        map.insert("result", 1);
        return map;
    }

    QVariantList items;
    QVariantList standards;
    for (int i = 0; i < count; i++) {
        items.append(buf[i]);

        touch_test_standard standard;
        memset(&standard, 0, sizeof(standard));
        QVariantMap st;
        mTouchManager->getSignalTestStandard(
                    mTouchManager->firstConnectedDevice(),
                    buf[i], &standard, mode);
        st.insert("client_max", standard.client_max);
        st.insert("client_min", standard.client_min);
        st.insert("factory_max", standard.factory_max);
        st.insert("factory_min", standard.factory_min);
        st.insert("min", standard.min);
        st.insert("max", standard.max);
        st.insert("count", toWord(standard.count_l, standard.count_h));
        st.insert("index", buf[i]);

        standards.append(QVariant::fromValue(st));
//        qDebug("%d signal count: %d", buf[i], toWord(standard.count_l, standard.count_h));
    }
    map.insert("items", items);
    map.insert("standards", standards);
    map.insert("result", 0);

    return map;
}
//获取信号数据
QVariantMap TouchTools::getSignalData(QVariant index, int count)
{
    QVariantMap map;
    int no = index.toUInt();
    if (no < 0) {
        map.insert("result", 1);
        TWARNING("%s index invalid");
        return map;
    }
    TouchTestData *data = mTouchManager->getSignalDatas(mTouchManager->firstConnectedDevice(), no, count, true);

    if (data == NULL) {
        map.insert("result", 1);
        return map;
    }
//    TINFO("signal data count=%d", data->count);
    map.insert("count", data->count);
    map.insert("index", data->number);
    map.insert("f_min", data->f_min);
    map.insert("f_max", data->f_max);
    map.insert("c_min", data->c_min);
    map.insert("c_max", data->c_max);
    map.insert("datas", data->datas);
    map.insert("result", 0);

    delete data;
    return map;
}
bool TouchTools::autoTestSwitch = false;
#define show_line() TDEBUG("%s [%d]", __func__, __LINE__);
TouchTools::TouchTools(QObject *parent, TouchPresenter *presenter,int argc,char **argv) : QObject(parent),
    mTestLstener(this), mUpgradeListener(this), initSdkThread(this), upgradeThread(this),
    touchAging(presenter, NULL), appType(APP_FACTORY), hotplugInterval(0),testThread(this)
{

    if(argc > 0)
    {
     this->argc = argc;
     this->argv = argv;
    }
    firstTimeUpdate = false;
    if (presenter == NULL) {
        TDebug::error("presenter is NULL");
        return;
    }

    timer = new QTimer(this);
    argcTimer = new QTimer(this);
    this->presenter = presenter;
    presenter->setTouchInterface(this);
    presenter->setAppType((int)appType);

    QObject::connect(this->presenter, SIGNAL(upgradeFireware(QString)),
                     this, SLOT(upgradeFireware(QString)));
    QObject::connect(this->presenter, SIGNAL(setUpgradeFile(QString)),
                     this, SLOT(setUpgradeFile(QString)));
    QObject::connect(this->presenter,SIGNAL(clearComboBoxData()),this,SLOT(clearComboBoxData()));
     QObject::connect(presenter,SIGNAL(setUpdatePath(QString)),this,SLOT(setUpdatePath(QString)));
    QObject::connect(this->presenter, SIGNAL(startUpgrade()),
                     this, SLOT(startUpgrade()));
    QObject::connect(this->presenter,SIGNAL(setCancelTest(bool)),this,SLOT(setTestThreadCancel(bool)));
     QObject::connect(this->presenter,SIGNAL(stopAll()),this,SLOT(onStopAll()));

    QObject::connect(this, SIGNAL(showMessage(QString,QString,int)),
                     this, SLOT(showMessageDialog(QString,QString,int)));

    QObject::connect(presenter,SIGNAL(setTestThreadStop(bool)),this,SLOT(onSetTestThreadStop(bool)));

    QObject::connect(presenter, SIGNAL(startTest()),
                     this, SLOT(startTest()));

//    QObject::connect(timer,SIGNAL(timeout()),this,SLOT(timeoutWorking()));
//    timer->start(25000);

    QObject::connect(argcTimer,SIGNAL(timeout()),this,SLOT(exitProject()));
    if(argc > 1 && strcmp(argv[1],"-changeCoordsMode") == 0)
    {
        argcTimer->start(2000);
    }
    TINFO("start init thread");
    addTouchManagerTr();
    initSdkThread.start();
}
void TouchTools::timeoutWorking()
{
    if(mTouchManager->firstConnectedDevice() == NULL)
    {
        TDEBUG("No touch device connect!!");
        return;
    }
    startUpgrade();
}
int TouchTools::language = zh_CN;
void TouchTools::setLanguage(int lu)
{
    language = lu;
}

void TouchTools::exitProject()
{
    mTouchManager->mHotplugThread.stopThread();
//    if(argc > 1 && QString::compare(argv[1],"-changeCoordsMode") == 0)
//    {
//        if(language == en_US)
//            MessageBox(NULL,TEXT("Touch device disconnected"),TEXT("error"),MB_ICONHAND|MB_OK);
//        else
//            MessageBox(NULL,TEXT("没有连接到触摸框设备"),TEXT("错误"),MB_ICONHAND|MB_OK);
//    }
    exit(0);
}
TouchTools::~TouchTools()
{
#if 1  
    presenter->stopGetSignalDataSync();

    presenter->destroyQml();

    if (mTouchManager != NULL) {
        mTouchManager->setTesting(mTouchManager->firstConnectedDevice(), 0);
        TouchManager::freeInstance();

        mTouchManager = NULL;
    }


    TouchManager::freeAllTouchDeviceInfo();

#endif

    TDEBUG("TouchTools end");
}

void TouchTools::onCommandDone(touch_device *dev, touch_package *require, touch_package *reply)
{

}

QString TouchTools::getTr(QString str)
{
    if(str == NULL)
    {
        return NULL;
    }
    return tr(str.toStdString().c_str());
}

void TouchTools::TestListener::inProgress(int progress, QString message)
{
    manager->setTestProgess(progress);
    if (message != NULL && message != "") {
        manager->appendMessageText(message,2);
    }
}
void TouchTools::TestListener::showOnboardFailItem(QString message)
{
    if (message != NULL && message != "") {
        manager->appendMessageText(message,2);
    }
}

void TouchTools::TestListener::showFirewareInfo(int type)
{
    manager->showFirewareInfo(type);
}



void TouchTools::TestListener::onTestDone(bool result, QString text,bool stop,bool isSupport)
{
    QString message = "";
    QString info;
    QString info2;
//    if (manager->appType == APP_FACTORY) {
        message = text;
//    }

//    TDEBUG("manager->mTouchManager->mtestStop:%d",manager->mTouchManager->mtestStop);
    TDEBUG("manager->mTouchManager : %p",manager->mTouchManager);
    TDEBUG("manager->mTouchManager->testThread : %p",manager->mTouchManager->testThread);

    if(!stop)
    {

//        info = (result ? tr("Test pass") : tr("Test failed") + "! ") + message + "\n";
//        info2 = (result ? tr("Test pass") : tr("Test failed") + "!\n") + message;
        info = (result ? tr("Test pass") : tr("Test failed") + "! ")  + "\n";
        info2 = (result ? tr("Test pass") : tr("Test failed") + "!\n") ;
        TDebug::info(info);
        manager->showMessage(tr("Test"), info2, result ? 1 : 3);

    }
    else
    {
        info = tr("Cancel test")+"\n";
        info2 = tr("You have cancelled the test");
        TDebug::info(info);
        manager->showMessage(tr("Test"), info2,8);
        if(autoTestSwitch)
        {
            destroyDialog();
        }
    }
    manager->presenter->setTextButtonText(tr("Test"));
    manager->appendMessageText(info,2);
//    manager->presenter->setTestButtonEnable(true);
    manager->presenter->setTestButtonCheck(false);
    manager->presenter->setTesting(false);

}

void TouchTools::TestListener::setNewWindowVisable()
{
    manager->presenter->setVisibleValue();
}

void TouchTools::TestListener::changeOnboardtestString(QString info)
{
    manager->presenter->changeOnboardtestString(info);
}

void TouchTools::TestListener::showTestMessageDialog(QString title, QString message, int type)
{
    manager->showMessage(title,message,type);
}

void TouchTools::TestListener::destroyDialog()
{
    manager->presenter->destroyDialog();
}


void TouchTools::TestListener::refreshOnboardTestData(QVariantMap map)
{
    manager->presenter->refreshOnboardTestData(map);
}


void TouchTools::UpgradeListener::inProgress(int progress)
{
//    TDEBUG("upgrade %d", progress);
    switch (progress) {
    case 1:
        manager->appendMessageText(tr("Load fireware done"),1);
        break;
    case 2:
        manager->appendMessageText(tr("Reboot device done"),1);
        break;
    case 3:
        manager->appendMessageText(tr("Enter download mode"),1);
        break;
    case -1:
        manager->appendMessageText(tr("Start download fireware"),1);
        break;
    }

    manager->setUpgradeProgess(progress);
}

void TouchTools::UpgradeListener::onUpgradeDone(bool result, QString message)
{

    manager->presenter->destroyDialog();
    TINFO("upgrade result %d, (%s)", result, message.toStdString().c_str());
    if (result) {
        manager->showMessage(tr("Upgrade"), tr("Upgrade success") + "!", 1);
        manager->appendMessageText(tr("Upgrade success") + "!\n",1);
    } else {
        manager->showMessage(tr("Upgrade"), tr("Upgrade failed") + "!\n" + message, 3);
        manager->appendMessageText(tr("Upgrade failed") + "! " + message + "\n",1);
    }
    manager->presenter->setUpgradeButtonEnable(true);

    manager->presenter->setUpgrading(false);
}

void TouchTools::UpgradeListener::showUpdateMessageDialog(QString title, QString message, int type)
{
    TDEBUG("showUpdateMessageDialog=============================================");
    manager->showMessage(title,message,type);
}

void TouchTools::UpgradeListener::destroyDialog()
{
    manager->presenter->destroyDialog();
}
void TouchTools::addTouchManagerTr(){
    tr("Being detected! Do not touch!");
    tr("test failed");
    tr("Check the onboard test result failed");
    tr("Failed to get test item");
    tr("Failed to switch to touch mode");
    tr("Please draw a picture around the touch frame");
    tr("The onboard test function is not activated");
    tr("Onboard test failed");
    tr("Onboard test passed");
    tr("The firmware package size is larger than the report package");
    tr("Failed to switch to upgrade mode");
    tr("Failed to verify firmware");
    tr("Failed to download firmware");
    tr("IAP failed");
    tr("Firmware error");

}

