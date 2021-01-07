//#ifndef TUSBEVENT_H
//#define TUSBEVENT_H

////#include <windows.h>
//#include <QWidget>
//#include <QMainWindow>
////#include <dbt.h>
//#include "sdk/tdebug.h"
////#include<devguid.h>
////#include<SetupAPI.h>
////#include<InitGuid.h>

//class TUsbEvent : public QMainWindow
//{
//Q_OBJECT
//public:
//    TUsbEvent();
//    ~TUsbEvent(){}
//    signals:
//    void usbDeviceRemove();
//    void usbDeviceAdd();
//protected:
//    bool nativeEvent(const QByteArray &eventType, void *message, long *result) {
//         Q_UNUSED(eventType);
//        MSG* msg = reinterpret_cast<MSG*>(message);
//        int msgType = msg->message;
//        if (WM_DEVICECHANGE == msgType) {
//            TINFO("nativeEvent: %x->%x(%x,%x, %x)", msgType, msg->wParam,
//                  DBT_DEVICEREMOVECOMPLETE, DBT_DEVICEARRIVAL, DBT_DEVNODES_CHANGED);
//            if (msg->wParam == DBT_DEVNODES_CHANGED) {
//                TINFO("DEVICE change");
//                emit usbDeviceAdd();
//            }
//            /*
//            if (msg->wParam == DBT_DEVICEARRIVAL) {
//                TINFO("DEVICE arrival");
//                emit usbDeviceAdd();
//            } else if (msg->wParam == DBT_DEVICEREMOVECOMPLETE){
//                TINFO("DEVICE remove");
//                emit usbDeviceRemove();
//            }
//            */
//        }
//        return false;
//    }
//};

//#endif // TUSBEVENT_H
