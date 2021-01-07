#ifndef TOUCHAGING_H
#define TOUCHAGING_H

#include "sdk/TouchManager.h"
#include "presenter/touchpresenter.h"

/**
  * deviceStatus:
  * 0: default, no device
  * 1: connected
  * 2: disconnected
  * 3: error
  * 4: finished
  */
enum {
    AGING_NC = 0,
    AGING_CONNECTED,
    AGING_DISCONNECTED,
    AGING_ERROR,
    AGING_FINISHED
};
struct AgingItem {
    touch_device *device;
    long runTime;
    int index;
    int status;
    qint8 usb_status;
    qint8 serial_status;
};
#define AGING_TIME 3 * 60
class TouchAging: public QObject, public TouchManager::HotplugListener
{
    Q_OBJECT
public:
    TouchAging(TouchPresenter *presenter, TouchManager *manager, QObject *parent = NULL);
    virtual ~TouchAging();

    void startAgingTest();
    void stopAgingTest();
    void setAgingTime(int time);

    void setManager(TouchManager *m) {mManager = m;}

    void onTouchHotplug(touch_device *dev, const int attached, const void *val);

public slots:
    void onAgingFinished(int index);
    void onStopAgingTest();
    void onStartAgingTest();
private:
    int startAging(AgingItem *item);
    int resumeAging(struct AgingItem *item);
    int pauseAging(AgingItem *item);
    int stopAging(struct AgingItem *item);

    int setDeviceAging(touch_device *device, bool on);

private:
    TouchManager *mManager;
    TouchPresenter *presenter;
    struct AgingItem *mAgingItems;
    bool running;
    int mAgingTime;
    int mTestDeviceCount;
};

#endif // TOUCHAGING_H
