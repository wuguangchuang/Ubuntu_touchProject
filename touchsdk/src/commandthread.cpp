#include "CommandThread.h"
#include "utils/tdebug.h"

#include "TouchManager.h"
#include <QTime>
#include "hidapi.h"


CommandThread::CommandThread() : sem(0)
{
}

void CommandThread::run()
{
#if 1
    stop = 0;
    int ret;
    int tryCount = 3;
    int i = 0;
    int milliseconds = 30000;
    TDEBUG("command thread running");
    while (!stop) {
//        sem.acquire();
        if(!sem.tryAcquire(1,10))
            continue;

        mutex.lock();
        if (mCommandItem.isEmpty()) {
            mutex.unlock();
            continue;
        }
        //出队
        CommandItem *item = mCommandItem.dequeue();
        mutex.unlock();
        // TODO: deal with command
        item->require->report_id = item->dev->touch.report_id;
        touch_package tp;
        if (item->reply == NULL)
            item->reply = &tp;
//#define _SHOW_TIME
#ifdef _SHOW_TIME
        QTime time;
        time.start();
#endif
        item->dev->mutex.lock();
        tryCount = 3;
        do {
                ret = TouchManager::sendPackageToDevice(item->require, item->reply, item->dev);

                if(ret > 0 && item->dev->touch.connected)
                    break;

                for(i = 0;i < milliseconds / 50 && !stop && item->dev->touch.connected;i++)
                {
                    ret = TouchManager::wait_time_out(item->dev->hid, (unsigned char *)(item->reply),HID_REPORT_DATA_LENGTH,50);

                    if(ret > 0)
                        break;
                }
                if(stop)
                    break;
                tryCount--;


        } while (ret <= 0 && tryCount > 0 && !stop);

        item->dev->mutex.unlock();
#ifdef _SHOW_TIME
        qDebug("command consume: %u[%d, %d], %d", time.elapsed(),
               item->require->master_cmd, item->require->sub_cmd,
               QTime::currentTime().msecsSinceStartOfDay());
#endif
//        hid_send_data(item->dev->hid, (hid_report_data*)item->require, (hid_report_data*)reply);
        if (item->async) {
            TDEBUG("异步");
            if (item->listener) {
                item->listener->onCommandDone(item->dev, item->require, item->reply);
            }
            delete item->sem;
            free(item);
        } else {
            item->sem->release(1);
        }
    }
#endif

    finshed = true;
    TDEBUG("command thread end");
    exit(0);
}

int CommandThread::addCommandToQueue(touch_device *dev, touch_package *require,
                                     touch_package *reply,int async, CommandListener *listener)
{
    if (dev == NULL && !dev->touch.connected) {
        TWARNING("%s: device is not ready", __func__);
        return -1;
    }
    if (require == NULL) {
        TWARNING("%s: require is NULL", __func__);
        return -2;
    }
    CommandItem *item = (CommandItem*)malloc(sizeof(struct CommandItem));
    memset(item, 0, sizeof(CommandItem));

    item->dev = dev;
    item->require = require;
    item->reply = reply;
    item->async = async;

    item->sem = new QSemaphore(0);
    mutex.lock();
    mCommandItem.enqueue(item);
    mutex.unlock();
    sem.release();

    if (async == 1) {        
        if (listener != NULL) {
            item->listener = listener;
        }
    } else {

        item->sem->acquire();
        delete item->sem;
        free(item);
    }
    return 0;
}
