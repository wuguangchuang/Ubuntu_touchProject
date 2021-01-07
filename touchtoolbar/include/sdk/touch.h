#ifndef TOUCH_H
#define TOUCH_H
#include "hidapi.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>


#pragma pack(push)
#pragma pack(1)

#define MCU_ID_LENGTH (16)
typedef struct {
    unsigned char type_l;
    unsigned char type_h;
    char id[MCU_ID_LENGTH];
}mcu_info;


typedef struct _touch_package {
    unsigned char report_id;
    unsigned char version;
    unsigned char magic;
    unsigned char flow;
    unsigned char reserved1;
    unsigned char master_cmd;
    unsigned char sub_cmd;
    unsigned char reserved2;
    unsigned char data_length;
    unsigned char data[55];
}touch_package;

typedef struct _touch_fireware_info {
    unsigned char type_l;
    unsigned char type_h;
    unsigned char version_l;
    unsigned char version_h;
    unsigned char command_protocol_version;
    unsigned char serial_protocol_version;
    unsigned char checksum_l;
    unsigned char checksum_h;
    unsigned char touch_point;
    unsigned char usb_vid_l;
    unsigned char usb_vid_h;
    unsigned char usb_pid_l;
    unsigned char usb_pid_h;
}touch_fireware_info;

typedef struct _touch_test_standard {
    unsigned char no;
    unsigned char count_l;
    unsigned char count_h;
    unsigned char factory_min;
    unsigned char factory_max;
    unsigned char client_min;
    unsigned char client_max;

    uint32_t mode;
    uint8_t min;
    uint8_t max;
    unsigned char method_switch_0;
    unsigned char method_switch_1;
    unsigned char method_switch_2;
    unsigned char method_switch_3;
    unsigned char method_enum;
}touch_test_standard;
typedef struct _get_board_attribute
{
    unsigned char num;
    unsigned char direction;
    unsigned char order;
    unsigned char launchLampCount_l;
    unsigned char launchLampCount_h;
    unsigned char recvLampCount_l;
    unsigned char recvLampCount_h;
}get_board_attribute;
typedef struct _onboard_test_standard {
    unsigned char num;
    unsigned char count_l;
    unsigned char count_h;
    uint32_t mode;
    unsigned char faultValue;
    unsigned char warnValue;
    unsigned char qualifiedValue;
    unsigned char goodValue;
}onboard_test_standard;


#pragma pack(pop)

typedef struct {
    unsigned int report_id;
    unsigned int connected;
    mcu_info mcu;
    char id_str[2 * MCU_ID_LENGTH + 1];
    unsigned char booloader;
    char model[64];
    unsigned int output_report_length;
}touch_info;

typedef struct _touch_device{
    struct hid_device_ *hid;
    struct hid_device_info *info;
    touch_info touch;
    struct _touch_device *next;
}touch_device;


touch_package *getPackage(unsigned char masterCmd, unsigned char subCmd,
                          unsigned char dataLength, unsigned char *data);
void putPackage(touch_package *package);
#define DEFINE_PACKAGE(pname, mcmd, scmd, length, src_data) \
    touch_package pname; \
    memset(&pname, 0, sizeof(touch_package)); \
    pname.master_cmd = mcmd; \
    pname.sub_cmd = scmd; \
    pname.data_length = length; \
    memcpy(pname.data, src_data, length); \

struct touch_vendor_info {
    unsigned short vid; // vendor id
    unsigned short pid; // product id
    char path[128];     // path
    unsigned int rid;   // report id
    unsigned char bootloader; // is bootloader
};


// support devices
static struct touch_vendor_info vendor_touchs[] = {
{0xAED7, 0x0013, "col01", 0xCD},
{NULL},
};

// master command
#define TOUCH_M_CMD_DEVICE_INFO             0x01
#define TOUCH_M_CMD_FIREWARE_UPGRADE        0x02
#define TOUCH_M_CMD_HARDWARE                0X05

#define TOUCH_M_CMD_RESPONSE                0xFE


// sub command
#define TOUCH_S_CMD_GET_FIRMWARE_INFO       0x01
#define TOUCH_S_CMD_GET_MCU_INFO            0x03
#define TOUCH_S_CMD_GET_STRING_INFO         0x04
#define TOUCH_S_CMD_GET_SIGNAL_TEST_ITEM    0x05
#define TOUCH_S_CMD_GET_SIGNAL_TEST_STAN    0x06

#define TOUCH_S_CMD_RESET_DEVICE            0x01

#define TOUCH_S_CMD_SET_TLED                0x05

#define TOUCH_S_CMD_RESPONSE_UNKNONW        0x01
#define TOUCH_S_CMD_RESPONSE_FAILED         0x02
#define TOUCH_S_CMD_RESPONSE_SUCCEED        0x03

#define COORDS_CHANNEL_USB      0x01
#define COORDS_CHANNEL_SERIAL   0x02

#define COORDS_CHANNEL_ENABLE   0x01
#define COORDS_CHANNEL_DISABLE  0x00

#define COORDS_USB_MODE_MOUSE   0x01
#define COORDS_USB_MODE_TOUCH   0x02

#define COORDS_SERIAL_MODE_TOUCH              0x01
#define COORDS_SERIAL_MODE_TOUCH_WITH_SIZE    0x02

#define COORDS_ROTAION_0    0
#define COORDS_ROTAION_90   1
#define COORDS_ROTAION_180  2
#define COORDS_ROTAION_270  3

#define COORDS_MIRROR_ENABLE    0x01
#define COORDS_MIRROR_DISABLE   0x00

#define COORDS_MAC_OS_MODE_10.9     0x01
#define COORDS_MAC_OS_MODE_10.10    0x02

#define CALIBRATION_MODE_CLOSE              0x00
#define CALIBRATION_MODE_COLLECT            0x01
#define CALIBRATION_MODE_CALIBRATION        0x02


#define	STE_DEV_GRAPH	0x00000001
#define	STE_DEV_TEST	0x00000002
#define	STE_FACTORY_GRAPH	0x00000004
#define	STE_FACTORY_TEST	0x00000008
#define	STE_PCBA_CUSTOMER_GRAPH	0x00000010
#define	STE_PCBA_CUSTOMER_TEST	0x00000020
#define	STE_END_USER_GRAPH	0x00000040
#define	STE_END_USER_TEST	0x00000080
#define STE_ALL_ITEMS   0xFFFFFFF

//onboard
#define TOUCH_S_CMD_START_ONBOARD_TEST          0x02
#define TOUCH_S_CMD_GET_ONBOARD_TEST_ITEM       0x08
#define TOUCH_S_CMD_GET_ONBOARD_TEST_ATTRIBUTE  0x09
#define TOUCH_S_CMD_GET_ONBOARD_TEST_DATA       0x0A
#define TOUCH_S_CMD_GET_ONBOARD_TEST_RESULT     0x0B


#define ONBOARD_TEST_SWITCH_START           0x01
#define ONBOARD_TEST_SWITCH_STOP            0x00

#define ONBOARD_TEST_MODE_CLOSE             0x00
#define ONBOARD_TEST_MODE_NOTOUCH           0x01
#define ONBOARD_TEST_MODE_TOUCH             0x02

#define ONBOARD_TEST_GET_BOARD_COUNT        0x0C
#define ONBOARD_TEST_GET_BOARD_ATTRIBUTE    0x0D

// string type
typedef enum _touch_string_type{
    TOUCH_STRING_TYPE_VENDOR = 0x01,
    TOUCH_STRING_TYPE_MODEL,
    TOUCH_STRING_TYPE_CUSTOM,
}touch_string_type;

// reset dst
#define RESET_DST_UNKNOWN   0
#define RESET_DST_BOOLOADER 1
#define RESET_DST_APP       2
touch_device *hid_find_touchdevice(touch_device *existDevice,int *count);
#define touch_reponse_ok(packge) \
    ((package->master_cmd == TOUCH_M_CMD_RESPONSE) && (package->sub_cmd == TOUCH_S_CMD_RESPONSE_SUCCEED))

static __inline unsigned int toWord(unsigned char low, unsigned char high) {
    return (high << 8) | low;
}

static __inline void wordToPackage(unsigned short value, unsigned char *target) {
    target[0] = (unsigned char)(value & 0xff);
    target[1] = (unsigned char)((value >> 8) & 0xff);
}
#ifdef __cplusplus
} // extern "C"
#endif
#endif // TOUCH_H
