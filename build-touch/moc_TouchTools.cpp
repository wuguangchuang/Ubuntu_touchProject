/****************************************************************************
** Meta object code from reading C++ file 'TouchTools.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.7.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../touchtoolbar/include/TouchTools.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'TouchTools.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.7.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_Touch__TouchTools_t {
    QByteArrayData data[22];
    char stringdata0[261];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Touch__TouchTools_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Touch__TouchTools_t qt_meta_stringdata_Touch__TouchTools = {
    {
QT_MOC_LITERAL(0, 0, 17), // "Touch::TouchTools"
QT_MOC_LITERAL(1, 18, 11), // "showMessage"
QT_MOC_LITERAL(2, 30, 0), // ""
QT_MOC_LITERAL(3, 31, 5), // "title"
QT_MOC_LITERAL(4, 37, 7), // "message"
QT_MOC_LITERAL(5, 45, 4), // "type"
QT_MOC_LITERAL(6, 50, 15), // "upgradeFireware"
QT_MOC_LITERAL(7, 66, 4), // "path"
QT_MOC_LITERAL(8, 71, 12), // "startUpgrade"
QT_MOC_LITERAL(9, 84, 13), // "setUpdatePath"
QT_MOC_LITERAL(10, 98, 14), // "setUpgradeFile"
QT_MOC_LITERAL(11, 113, 17), // "clearComboBoxData"
QT_MOC_LITERAL(12, 131, 17), // "showMessageDialog"
QT_MOC_LITERAL(13, 149, 17), // "triggerUsbHotplug"
QT_MOC_LITERAL(14, 167, 9), // "startTest"
QT_MOC_LITERAL(15, 177, 9), // "onStopAll"
QT_MOC_LITERAL(16, 187, 19), // "onSetTestThreadStop"
QT_MOC_LITERAL(17, 207, 4), // "stop"
QT_MOC_LITERAL(18, 212, 19), // "setTestThreadCancel"
QT_MOC_LITERAL(19, 232, 1), // "t"
QT_MOC_LITERAL(20, 234, 14), // "timeoutWorking"
QT_MOC_LITERAL(21, 249, 11) // "exitProject"

    },
    "Touch::TouchTools\0showMessage\0\0title\0"
    "message\0type\0upgradeFireware\0path\0"
    "startUpgrade\0setUpdatePath\0setUpgradeFile\0"
    "clearComboBoxData\0showMessageDialog\0"
    "triggerUsbHotplug\0startTest\0onStopAll\0"
    "onSetTestThreadStop\0stop\0setTestThreadCancel\0"
    "t\0timeoutWorking\0exitProject"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Touch__TouchTools[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    3,   94,    2, 0x06 /* Public */,
       1,    2,  101,    2, 0x26 /* Public | MethodCloned */,

 // slots: name, argc, parameters, tag, flags
       6,    1,  106,    2, 0x0a /* Public */,
       8,    0,  109,    2, 0x0a /* Public */,
       9,    1,  110,    2, 0x0a /* Public */,
      10,    1,  113,    2, 0x0a /* Public */,
      11,    0,  116,    2, 0x0a /* Public */,
      12,    3,  117,    2, 0x0a /* Public */,
      12,    2,  124,    2, 0x2a /* Public | MethodCloned */,
      13,    0,  129,    2, 0x0a /* Public */,
      14,    0,  130,    2, 0x0a /* Public */,
      15,    0,  131,    2, 0x0a /* Public */,
      16,    1,  132,    2, 0x0a /* Public */,
      18,    1,  135,    2, 0x0a /* Public */,
      20,    0,  138,    2, 0x0a /* Public */,
      21,    0,  139,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int,    3,    4,    5,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    3,    4,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int,    3,    4,    5,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    3,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   17,
    QMetaType::Void, QMetaType::Bool,   19,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Touch::TouchTools::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TouchTools *_t = static_cast<TouchTools *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->showMessage((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3]))); break;
        case 1: _t->showMessage((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 2: _t->upgradeFireware((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->startUpgrade(); break;
        case 4: _t->setUpdatePath((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 5: _t->setUpgradeFile((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 6: _t->clearComboBoxData(); break;
        case 7: _t->showMessageDialog((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3]))); break;
        case 8: _t->showMessageDialog((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 9: _t->triggerUsbHotplug(); break;
        case 10: _t->startTest(); break;
        case 11: _t->onStopAll(); break;
        case 12: _t->onSetTestThreadStop((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 13: _t->setTestThreadCancel((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 14: _t->timeoutWorking(); break;
        case 15: _t->exitProject(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        void **func = reinterpret_cast<void **>(_a[1]);
        {
            typedef void (TouchTools::*_t)(QString , QString , int );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&TouchTools::showMessage)) {
                *result = 0;
                return;
            }
        }
    }
}

const QMetaObject Touch::TouchTools::staticMetaObject = {
    { &QObject::staticMetaObject, qt_meta_stringdata_Touch__TouchTools.data,
      qt_meta_data_Touch__TouchTools,  qt_static_metacall, Q_NULLPTR, Q_NULLPTR}
};


const QMetaObject *Touch::TouchTools::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Touch::TouchTools::qt_metacast(const char *_clname)
{
    if (!_clname) return Q_NULLPTR;
    if (!strcmp(_clname, qt_meta_stringdata_Touch__TouchTools.stringdata0))
        return static_cast<void*>(const_cast< TouchTools*>(this));
    if (!strcmp(_clname, "CommandThread::CommandListener"))
        return static_cast< CommandThread::CommandListener*>(const_cast< TouchTools*>(this));
    if (!strcmp(_clname, "TouchManager::HotplugListener"))
        return static_cast< TouchManager::HotplugListener*>(const_cast< TouchTools*>(this));
    if (!strcmp(_clname, "TouchInterface"))
        return static_cast< TouchInterface*>(const_cast< TouchTools*>(this));
    if (!strcmp(_clname, "TouchManager::Trans"))
        return static_cast< TouchManager::Trans*>(const_cast< TouchTools*>(this));
    return QObject::qt_metacast(_clname);
}

int Touch::TouchTools::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 16)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 16;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 16)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 16;
    }
    return _id;
}

// SIGNAL 0
void Touch::TouchTools::showMessage(QString _t1, QString _t2, int _t3)
{
    void *_a[] = { Q_NULLPTR, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_END_MOC_NAMESPACE
