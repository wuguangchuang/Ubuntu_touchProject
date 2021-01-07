#include "Fireware.h"
#include "utils/tdebug.h"
#include "include/utils/CRC_32.h"

#include <QtEndian>
#include <QFileInfo>

#define DBG TDEBUG

static int addFirewarePackageToList(struct FirewarePackageList *list, struct FirewarePackage *package)
{
    struct FirewarePackage *fp, *temp;
    if (list == NULL || package == NULL)
        return -1;
    if (list->next == NULL) {
        list->next = package;
        return 0;
    }
    fp = list->next;
    while (fp->next) {
        temp = fp;
        temp->next = package;
        fp = fp->next;
    }
    return 0;
}

Fireware::Fireware(QString path) : ready(false)
{
    int ret;
    mFirewares.next = NULL;
    file = new QFile(path);
    qint8 *fileData;
    TDEBUG("path = %s",path.toStdString().c_str());
    if (!file->open(QIODevice::ReadOnly)) {
        TDebug::debug("can not open fireware file:" + file->errorString());
        return;
    } else {
        ret = file->read((char*)&mFileHeader, sizeof(struct FirewareFileHeader));
        if (ret < 0) {
            return;
        }
        mFileHeader.version = qFromLittleEndian(mFileHeader.version);
        mFileHeader.crc32 = qFromLittleEndian(mFileHeader.crc32);
        mFileHeader.fileSize = qFromLittleEndian(mFileHeader.fileSize);
        mFileHeader.headerSize = qFromLittleEndian(mFileHeader.headerSize);
        mFileHeader.firewareCount = qFromLittleEndian(mFileHeader.firewareCount);
        DBG("Fireware %s", path.toStdString().c_str());
        DBG("version: 0x%04x, header size: %d, file size: %d, fireware count: %d",
            mFileHeader.version, mFileHeader.headerSize, mFileHeader.fileSize, mFileHeader.firewareCount);
        TDEBUG("file info crc: 0x%x", mFileHeader.crc32);

        qint32 binSize = mFileHeader.fileSize;
        fileData = (qint8*)malloc(binSize);
        file->seek(sizeof(FirewareFileHeader));
        ret = file->read((char*)fileData, binSize);
        if (ret < 0) {
            TWARNING("read bin data failed");
            free(fileData);
            return;
        }

        CCRC_32 crc;
        crc.Reset();
        crc.Calculate((const unsigned char*)fileData, binSize);
//        char *testData = "123456789";
//        crc.Calculate((const unsigned char*)testData, strlen(testData));
        TDEBUG("#################calculate crc: 0x%x", crc.GetCrcResult());
        free(fileData);
        if (crc.GetCrcResult() != mFileHeader.crc32) {
            TWARNING("file crc error");
            TWARNING("1calculate crc: 0x%x", crc.GetCrcResult());
            TWARNING("1file info crc: 0x%x", mFileHeader.crc32);
            return;
        }
        struct FirewarePackage *fireware;
        struct FirewareHeader *header;
        file->seek(sizeof(FirewareFileHeader));
        for (int i = 0; i < mFileHeader.firewareCount; i++) {
            fireware = (struct FirewarePackage*)malloc(sizeof(struct FirewarePackage));
            memset(fireware, 0, sizeof(struct FirewarePackage));
            int readSize = sizeof(fireware->header.version) + sizeof(fireware->header.headerSize) +
                    sizeof(fireware->header.deviceIdRangeStart) + sizeof(fireware->header.deviceIdRangeEnd) +
                    sizeof(fireware->header.packSize) + sizeof(fireware->header.packCount) +
                    sizeof(fireware->header.handShakeCode) + sizeof(fireware->header.verifyCodeSize);
//            ret = file->read((char *)&fireware->header, (int)&(fireware->header.verifyCode) - (int)&fireware->header);
            ret = file->read((char *)&fireware->header,readSize);
            TDEBUG("readSize = %d",readSize);
            if (ret < 0) {
                TWARNING("read fireware header failed");
                free(fireware);
                return;
            }
            header = &fireware->header;
            header->version = qFromLittleEndian(header->version);
            header->headerSize = qFromLittleEndian(header->headerSize);
            header->deviceIdRangeStart = qFromLittleEndian(header->deviceIdRangeStart);
            header->deviceIdRangeEnd = qFromLittleEndian(header->deviceIdRangeEnd);
            header->packSize = qFromLittleEndian(header->packSize);
            header->packCount = qFromLittleEndian(header->packCount);

            //header->handShakeCode = qFromLittleEndian(header->handShakeCode);
            header->verifyCodeSize = qFromLittleEndian(header->verifyCodeSize);
            //header->verifyCode = qFromLittleEndian(header->verifyCode);
            //header->firmwareDataCRC32 = qFromLittleEndian(header->firmwareDataCRC32);
            DBG("Fireware %d", i);
            DBG("version: 0x%04x, header size: %d, device range [0x%04x - 0x%04x]",
                header->version, header->headerSize,
                header->deviceIdRangeStart, header->deviceIdRangeEnd);
            DBG("package size: %d, package count: %d, verify code size: %x",
                header->packSize, header->packCount, header->verifyCodeSize);

            ret = file->read((char*)fireware->header.verifyCode, fireware->header.verifyCodeSize);
            TDEBUG("fireware->header.verifyCodeSize = %d",fireware->header.verifyCodeSize);
            if (ret < 0) {
                TWARNING("read fireware header.fWVerifyCode failed");
                free(fireware);
                return;
            }

            ret = file->read((char*)&fireware->header.firmwareDataCRC32, sizeof(fireware->header.firmwareDataCRC32));
            if (ret < 0) {
                TWARNING("read fireware firmwareDataCRC32 failed");
                free(fireware);
                return;
            }
            TDEBUG("sizeof(fireware->header.firmwareDataCRC32) = %d",sizeof(fireware->header.firmwareDataCRC32));
            TDEBUG("fireware->header.firmwareDataCRC32 = %0x0x",fireware->header.firmwareDataCRC32);
            header->firmwareDataCRC32 = qFromLittleEndian(header->firmwareDataCRC32);
            TDEBUG("header->firmwareDataCRC32 = %0x0x",header->firmwareDataCRC32);

            fireware->data = (qint8*)malloc(header->packCount * header->packSize);
            ret = file->read((char*)fireware->data, header->packCount * header->packSize);
            if (ret < 0) {
                TWARNING("read fireware data failed");
                free(fireware);
                return;
            }
            crc.Reset();
            TWARNING("2222fireware  crc: 0x%x", fireware->header.firmwareDataCRC32);
            if (crc.Calculate((const unsigned char *)fireware->data, fireware->header.packCount * fireware->header.packSize)
                    != fireware->header.firmwareDataCRC32) {
                TWARNING("2calculate crc: 0x%x", crc.GetCrcResult());
                TWARNING("2fireware  crc: 0x%x", fireware->header.firmwareDataCRC32);
                free(fireware);
                return;
            }
            addFirewarePackageToList(&mFirewares, fireware);
        }

    }
    ready = true;
}


Fireware::~Fireware()
{
    struct FirewarePackage *fp = mFirewares.next, *temp;
    while (fp) {
        temp = fp->next;
        if (fp->data)
            free(fp->data);
        free(fp);
        fp = temp;
    }
    if (file)
        delete file;
}

bool Fireware::isReady()
{
    return ready;
}

const FirewareFileHeader* Fireware::getFileHeader()
{
    return (const FirewareFileHeader*) &mFileHeader;
}

const FirewarePackage* Fireware::getFirewarePackage(int index)
{
    if (!isReady())
        return NULL;
    FirewarePackage *fp = mFirewares.next;
    if (index < 0) return NULL;
    while (!!index && fp) {
        index--;
        fp = fp->next;
    }
    return (const FirewarePackage*)fp;
}


int Fireware::firewareCount() {
    if (!isReady())
        return -1;
    return mFileHeader.firewareCount;
}








