#ifndef FIREWARE_H
#define FIREWARE_H

#include <QFile>
#include <QtEndian>

#include <QList>

// 10MB
#define MAX_FIREWARE_SIZE (10 * 1024 * 1024)
#pragma pack(push)
#pragma pack(1)
struct FirewareFileHeader {
    qint16 version;
    qint32 size;
    qint32 firewareCount;
    qint32 crc32;
};

struct FirewareHeader {
    qint16 deviceIdRangeStart; //	此固件中的FirmwareData所对应的MCU的ID段的起始ID	2
    qint16 deviceIdRangeEnd; //	此固件中的FirmwareData所对应的MCU的ID段的结束ID	2
    qint32 packSize;    //	此固件中的FirmwareData每一个数据包的数据量	4
    qint32 packCount;   //	此固件中的FirmwareData数据包数量	4
    qint8 handShakeCode[32];    //	握手校验码	32
    qint8 fWVerifyCodeSize;     //	固件校验码长度	1
    qint8 fWVerifyCode[32];     //	固件校验码，用于设备端校验。	FWVerifyCodeSize
    qint32 firmwareDataCRC32;    //	FirmwareData的CRC32校验的结果，用于文件校验。	4
};

struct FirewarePackage {
    struct FirewareHeader header;
    qint8 *data;
    FirewarePackage *next;
};

struct FirewarePackageList {
    struct FirewarePackage *next;
};


#pragma pack(pop)
class Fireware
{
public:
    Fireware(QString path);
    ~Fireware();

    const FirewareFileHeader* getFileHeader();
    const FirewarePackage* getFirewarePackage(int index);
    bool isReady();
private:
    QFile *file;
    bool ready;
    FirewareFileHeader mFileHeader;
    struct FirewarePackageList mFirewares;
};

#endif // FIREWARE_H
