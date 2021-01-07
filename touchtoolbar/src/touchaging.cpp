#include "touchaging.h"
#include "sdk/tdebug.h"
#include "sdk/touch.h"
#include "sdk/tPrintf.h"

TouchAging::TouchAging(TouchPresenter *presenter, TouchManager *manager, QObject *parent):
    mManager(manager), mTestDeviceCount(40), running(false),
    presenter(presenter), mAgingItems(NULL),
    QObject(parent), mAgingTime(AGING_TIME)
{
    QObject::connect(presenter, SIGNAL(agingFinished(int)), this,
                     SLOT(onAgingFinished(int)));
    QObject::connect(presenter->getComponent(), SIGNAL(startAgingTest()),
                     this, SLOT(onStartAgingTest()));
    QObject::connect(presenter->getComponent(), SIGNAL(stopAgingTest()),
                     this, SLOT(onStopAgingTest()));
    presenter->setAgingTime(mAgingTime);
}

TouchAging::~TouchAging()
{
    if (mAgingItems)
        free(mAgingItems);
}

void TouchAging::setAgingTime(int time)
{
    mAgingTime = time;
    presenter->setAgingTime(mAgingTime);
    TDEBUG("aging time = %d", mAgingTime);
}

void TouchAging::stopAgingTest()
{
    if (mAgingItems) {
        for (int i = 0; i < mTestDeviceCount; i++) {
            AgingItem *item = &mAgingItems[i];
            if (item->device) {
                stopAging(item);
            }
        }
        free(mAgingItems);
    }

    presenter->stopAgingTest();
    running = false;
}

void TouchAging::startAgingTest()
{
    //mTestDeviceCount = presenter->getDeviceCount();
//    TDEBUG("count=%d",  mTestDeviceCount);
    mAgingItems = (struct AgingItem*)malloc(mTestDeviceCount * sizeof(struct AgingItem));
    memset(mAgingItems, 0, mTestDeviceCount * sizeof(struct AgingItem));
    touch_device *dev = mManager->firstConnectedDevice();
    for (int i = 0; i < mTestDeviceCount; i++) {
        mAgingItems[i].device = NULL;
    }
    int index = 0;
    while (dev) {
        mAgingItems[index].device = dev;
        mAgingItems[index].index = index;
        startAging(&mAgingItems[index]);
        index++;
        dev = dev->next;
    }
    presenter->startAgingTest();
    running = true;

    //mManager.registerHotplug(this);
}

int TouchAging::setDeviceAging(touch_device *device, bool on)
{
    int retVal = 0;
    int tryTime = 5;

    while (tryTime--) {
        retVal = mManager->setAging(device, true);
        if (retVal == 0)
            break;
    }
    return retVal;
}

int TouchAging::startAging(AgingItem *item)
{

    int retVal;
    if (mManager == NULL)
        return -1;
    retVal = mManager->getCoordsEnabled(item->device, COORDS_CHANNEL_USB, &item->usb_status);
    if (retVal != 0) {
        TERROR("%s get usb coords status failed(%d)", __func__, retVal);
        return retVal;
    }

    retVal = mManager->getCoordsEnabled(item->device, COORDS_CHANNEL_SERIAL, &item->serial_status);
    if (retVal != 0) {
        TERROR("%s get serial coords status failed(%d)", __func__, retVal);
        return retVal;
    }
    retVal = setDeviceAging(item->device, true);
    if (retVal != 0) {
        item->status = AGING_ERROR;
        presenter->setDeviceStatus(item->index, AGING_ERROR);
        return retVal;
    }
    if (item->status != AGING_CONNECTED && item->status != AGING_FINISHED) {
        item->status = AGING_CONNECTED;
        presenter->setDeviceStatus(item->index, AGING_CONNECTED);
    }
    TPRINTF("开始加速老化 itemIndex = %d",item->index);
    TDEBUG("%s disable coords, save usb=%d, serival=%d", __func__, item->usb_status, item->serial_status);
    mManager->setCoordsEnabled(item->device, COORDS_CHANNEL_SERIAL, COORDS_CHANNEL_DISABLE);
    mManager->setCoordsEnabled(item->device, COORDS_CHANNEL_USB, COORDS_CHANNEL_DISABLE);
    return 0;
}

int TouchAging::resumeAging(AgingItem *item)
{
    return startAging(item);
//    int retVal = setDeviceAging(item->device, true);
//    if (retVal != 0) {
//        item->status = AGING_ERROR;
//        presenter->setDeviceStatus(item->index, AGING_ERROR);
//        return;
//    }
//    if (item->status != AGING_CONNECTED && item->status != AGING_FINISHED) {
//        item->status = AGING_CONNECTED;
//        presenter->setDeviceStatus(item->index, 1);
//    }
}

int TouchAging::pauseAging(AgingItem *item)
{
    if (item->status == AGING_CONNECTED) {
        item->status = AGING_DISCONNECTED;
        presenter->setDeviceStatus(item->index, 2);
    }
    return 0;
}

int TouchAging::stopAging(AgingItem *item)
{

    mManager->setAging(item->device, 0);
    TDEBUG("%s resume usb=%d, serival=%d", __func__, item->usb_status, item->serial_status);
    TPRINTF("停止加速老化 itemIndex = %d",item->index);
    mManager->setCoordsEnabled(item->device, COORDS_CHANNEL_SERIAL, item->serial_status);
    mManager->setCoordsEnabled(item->device, COORDS_CHANNEL_USB, item->usb_status);
    return 0;
}

void TouchAging::onStopAgingTest()
{
    stopAgingTest();
}

void TouchAging::onStartAgingTest()
{
    qDebug("start aging");
    startAgingTest();
}

void TouchAging::onTouchHotplug(touch_device *dev, const int attached, const void *val)
{
    if (!running || dev->touch.booloader) return;

    AgingItem *item;
    for (int i = 0; i < mTestDeviceCount; i++) {
        item = &mAgingItems[i];
        if (dev->touch.connected && item->device == NULL) {
            item->device = dev;
            item->index = i;

            TDEBUG("start %d: %s", i, item->device->info->path);
            startAging(item);
            break;
        } else if (item->device && TouchManager::isSameDeviceInPort(item->device, dev)) {
            if (dev->touch.connected) {
                TDEBUG("resume %d: %s", i, item->device->info->path);
                resumeAging(item);
            } else {
                TDEBUG("pause %d: %s", i, item->device->info->path);
                pauseAging(item);
            }
            break;
        }
    }
}

void TouchAging::onAgingFinished(int index)
{
    TDEBUG("%s: %d", __func__, index);
    if (mAgingItems && index < mTestDeviceCount) {
        mAgingItems[index].status = AGING_FINISHED;
        stopAging(&mAgingItems[index]);
    }
}
