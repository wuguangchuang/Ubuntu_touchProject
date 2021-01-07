#ifndef TOUCH_H

#define TOUCH_H
#include "hidapi.h"
/*
#ifdef __cplusplus
extern "C" {
#endif
*/
#include <stdint.h>
#include <QMutex>
#include <QVariantList>

static __inline unsigned int toDWord(unsigned char a0, unsigned char a1, unsigned char a2, unsigned a3) {
    return (a0 + (a1 << 8) + (a2 << 16) + (a3 << 24));
}

static __inline unsigned int toWord(unsigned char low, unsigned char high) {
    return (high << 8) | low;
}

static __inline void wordToPackage(unsigned short value, unsigned char *target) {
    target[0] = (unsigned char)(value & 0xff);
    target[1] = (unsigned char)((value >> 8) & 0xff);
}

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
    unsigned char data[HID_REPORT_DATA_LENGTH];
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


#define STM_TLED_ON 0x00000001
#define STM_REPEAT 	0x00000002

#define STM_RAW_RANGE		0x01
#define STM_MAX_MIN_DIFF	0x02
#define STM_MEAN			0x03
static int isTestTledOn(touch_test_standard tts) {
    return (toDWord(tts.method_switch_0, tts.method_switch_1, tts.method_switch_2, tts.method_switch_3)
            & STM_TLED_ON) == 0 ? 0 : 1;
}
static int isTestRepeat(touch_test_standard tts) {
    return (toDWord(tts.method_switch_0, tts.method_switch_1, tts.method_switch_2, tts.method_switch_3)
            & STM_REPEAT) == 0 ? 0 : 1;
}
static unsigned int getTestSwitch(touch_test_standard tts) {
    return toDWord(tts.method_switch_0, tts.method_switch_1, tts.method_switch_2, tts.method_switch_3);
}
static unsigned int getTestMethod(touch_test_standard tts) {
    return tts.method_enum;
}

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
    QMutex mutex;
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
    if (src_data != NULL && length > 0) \
    memcpy(pname.data, src_data, length); \

#define SET_PACKAGE(pname, mcmd, scmd, length, src_data) \
    memset(pname, 0, sizeof(touch_package)); \
    (pname)->master_cmd = mcmd; \
    (pname)->sub_cmd = scmd; \
    (pname)->data_length = length; \
    memcpy((pname)->data, src_data, length); \

struct touch_vendor_info {
    unsigned short vid; // vendor id
    unsigned short pid; // product id
    char path[128];     // path
    unsigned int rid;   // report id
    unsigned char bootloader; // is bootloader
};

#define TLED_ON (0x11)
#define TLED_OFF (0x10)

#define TESTING_ON (0x01)
#define TESTING_OFF (0x00)

// master command
#define TOUCH_M_CMD_DEVICE_INFO             0x01
#define TOUCH_M_CMD_FIREWARE_UPGRADE        0x02
#define TOUCH_M_CMD_COORDS                  0x03
#define TOUCH_M_CMD_HARDWARE                0x04
#define TOUCH_M_CMD_CALIBRATION             0x05

#define TOUCH_M_CMD_RESPONSE                0xFE


// sub command
#define TOUCH_S_CMD_GET_FIRMWARE_INFO           0x01
#define TOUCH_S_CMD_GET_MCU_INFO                0x03
#define TOUCH_S_CMD_GET_STRING_INFO             0x04
#define TOUCH_S_CMD_GET_SIGNAL_TEST_ITEM        0x05
#define TOUCH_S_CMD_GET_SIGNAL_TEST_STAN        0x06
#define TOUCH_S_CMD_GET_SIGNAL_DATA             0x07

//状态应答
#define TOUCH_S_CMD_UNKNOWN     0x01
#define TOUCH_S_CMD_FAILED      0x02
#define TOUCH_S_CMD_SUCCEED     0x03


#define INDICATOR_LED_OFF                   0x00
#define INDICATOR_LED_ON                    0x01
#define INDICATOR_LED_AUTO                  0x02
#define INDICATOR_LED_DEFAULT_AUTO          0x03

#define TOUCH_S_CMD_RESET_DEVICE            0x01
#define TOUCH_S_CMD_IAP_START               0x02
#define TOUCH_S_CMD_IAP_DOWNLOAD            0x03
#define TOUCH_S_CMD_IAP_VERIFY              0x04
#define TOUCH_S_CMD_IAP_FINISHED            0x05

#define TOUCH_S_CMD_SIGNAL_INITIAL          0x01
#define TOUCH_S_CMD_SET_TLED                0x05
#define TOUCH_S_CMD_GET_TLED                0x06
#define TOUCH_S_CMD_SET_AGING               0x08
#define TOUCH_S_CMD_SET_INDICATOR_LED_ON    0x07
#define TOUCH_S_CMD_GET_AGING               0x09

#define TOUCH_S_CMD_SET_TESTING				0x0A
#define TOUCH_S_CMD_GET_TESTING				0x0B

#define TOUCH_S_CMD_SET_LOCK_AGC			0x0C
#define TOUCH_S_CMD_GET_LOCK_AGC			0x0D

#define LOCK_AGC_DISABLE					0x00
#define LOCK_AGC_ENABLE						0x01

#define TOUCH_S_CMD_RESPONSE_UNKNONW        0x01
#define TOUCH_S_CMD_RESPONSE_FAILED         0x02
#define TOUCH_S_CMD_RESPONSE_SUCCEED        0x03

// coords
#define TOUCH_S_CMD_GET_COORDS_ENABLED      0x01
#define TOUCH_S_CMD_SET_COORDS_ENABLED      0x02
#define TOUCH_S_CMD_GET_COORDS_MODE         0x03
#define TOUCH_S_CMD_SET_COORDS_MODE         0x04
#define TOUCH_S_CMD_GET_ROTATION            0x05
#define TOUCH_S_CMD_SET_ROTATION            0x06
#define TOUCH_S_CMD_GET_REFLECTION          0x07
#define TOUCH_S_CMD_SET_REFLECTION          0x08
#define TOUCH_S_CMD_GET_MACOS_MODE          0x09
#define TOUCH_S_CMD_SET_MACOS_MODE          0x0A

// calibration
#define TOUCH_S_CMD_GET_WORK_MODE           0x01
#define TOUCH_S_CMD_SET_WORK_MODE           0x02
#define TOUCH_S_CMD_GET_CALI_SETTINGS       0x03
#define TOUCH_S_CMD_SET_CALI_SETTINGS       0x04
#define TOUCH_S_CMD_GET_CALI_POINT_DATA     0x05
#define TOUCH_S_CMD_SET_CALI_POINT_DATA     0x06
#define TOUCH_S_CMD_START_CAPTURE           0x07
#define TOUCH_S_CMD_GET_CAPTURE_DATA        0x08
#define TOUCH_S_CMD_SAVE_CALI_DATA          0x09


#define CALIBRATION_MODE_CLOSE              0x00
#define CALIBRATION_MODE_COLLECT            0x01
#define CALIBRATION_MODE_CALIBRATION        0x02


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

#define COORDS_MAC_OS_MODE_10_9     0x01
#define COORDS_MAC_OS_MODE_10_10    0x02

#define SIGNAL_INIT_COMPLETE    0x01
#define SIGNAL_INIT_QUICK       0x02
//onboard
#define TOUCH_S_CMD_START_ONBOARD_TEST          0x02
#define TOUCH_S_CMD_GET_ONBOARD_TEST_ITEM       0x08
#define TOUCH_S_CMD_GET_ONBOARD_TEST_ATTRIBUTE  0x09
#define TOUCH_S_CMD_GET_ONBOARD_TEST_DATA       0x0A
#define TOUCH_S_CMD_GET_ONBOARD_TEST_RESULT     0x0B
#define ONBOARD_TEST_GET_BOARD_COUNT        0x0C
#define ONBOARD_TEST_GET_BOARD_ATTRIBUTE    0x0D


#define ONBOARD_TEST_SWITCH_START           0x01
#define ONBOARD_TEST_SWITCH_STOP            0x00

#define ONBOARD_TEST_MODE_CLOSE             0x00
#define ONBOARD_TEST_MODE_NOTOUCH           0x01
#define ONBOARD_TEST_MODE_TOUCH             0x02



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

#if 0
#define	STI_ADC_X_TB		0
#define	STI_ADC_Y_TB		1
#define	STI_ADC_X_TM		2
#define	STI_ADC_Y_TM		3
#define	STI_ADC_X_TF		4
#define	STI_ADC_Y_TF		5
#define	STI_ORG_X_TB		6
#define	STI_ORG_Y_TB		7
#define	STI_ORG_X_TM		8
#define	STI_ORG_Y_TM		9
#define	STI_ORG_X_TF		10
#define	STI_ORG_Y_TF		11
#define	STI_RAT_X_TB		12
#define	STI_RAT_Y_TB		13
#define	STI_RAT_X_TM		14
#define	STI_RAT_Y_TM		15
#define	STI_RAT_X_TF		16
#define	STI_RAT_Y_TF		17
#define	STI_AGC_X_TB		18
#define	STI_AGC_Y_TB		19
#define	STI_AGC_X_TM		20
#define	STI_AGC_Y_TM		21
#define	STI_AGC_X_TF		22
#define	STI_AGC_Y_TF		23
#define	STI_UNT_X_TB		24
#define	STI_UNT_Y_TB		25
#define	STI_UNT_X_TM		26
#define	STI_UNT_Y_TM		27
#define	STI_UNT_X_TF		28
#define	STI_UNT_Y_TF		29
#define	STI_RVR_X_TB		30
#define	STI_RVR_Y_TB		31
#define	STI_RVR_X_TM		32
#define	STI_RVR_Y_TM		33
#define	STI_RVR_X_TF		34
#define	STI_RVR_Y_TF		35
#endif

#define STI_ADC_X_TB    0
#define STI_ADC_Y_TB    1
#define STI_ADC_X_TM    2
#define STI_ADC_Y_TM    3
#define STI_ADC_X_TF    4
#define STI_ADC_Y_TF    5
#define STI_ORG_X_TB    6
#define STI_ORG_Y_TB    7
#define STI_ORG_X_TM    8
#define STI_ORG_Y_TM    9
#define STI_ORG_X_TF    10
#define STI_ORG_Y_TF    11
#define STI_RAT_X_TB    12
#define STI_RAT_Y_TB    13
#define STI_RAT_X_TM    14
#define STI_RAT_Y_TM    15
#define STI_RAT_X_TF    16
#define STI_RAT_Y_TF    17
#define STI_AGC_X_TB    18
#define STI_AGC_Y_TB    19
#define STI_AGC_X_TM    20
#define STI_AGC_Y_TM    21
#define STI_AGC_X_TF    22
#define STI_AGC_Y_TF    23
#define STI_UNT_X_TB    24
#define STI_UNT_Y_TB    25
#define STI_UNT_X_TM    26
#define STI_UNT_Y_TM    27
#define STI_UNT_X_TF    28
#define STI_UNT_Y_TF    29
#define STI_RVR_X_TB    30
#define STI_RVR_Y_TB    31
#define STI_RVR_X_TM    32
#define STI_RVR_Y_TM    33
#define STI_RVR_X_TF    34
#define STI_RVR_Y_TF    35
#define STI_ADC_X_TB_ALL    36
#define STI_ADC_Y_TB_ALL    37
#define STI_ADC_X_TM_ALL    38
#define STI_ADC_Y_TM_ALL    39
#define STI_ADC_X_TF_ALL    40
#define STI_ADC_Y_TF_ALL    41
#define STI_ORG_X_TB_ALL    42
#define STI_ORG_Y_TB_ALL    43
#define STI_ORG_X_TM_ALL    44
#define STI_ORG_Y_TM_ALL    45
#define STI_ORG_X_TF_ALL    46
#define STI_ORG_Y_TF_ALL    47
#define STI_RAT_X_TB_ALL    48
#define STI_RAT_Y_TB_ALL    49
#define STI_RAT_X_TM_ALL    50
#define STI_RAT_Y_TM_ALL    51
#define STI_RAT_X_TF_ALL    52
#define STI_RAT_Y_TF_ALL    53
#define STI_AGC_X_TB_ALL    54
#define STI_AGC_Y_TB_ALL    55
#define STI_AGC_X_TM_ALL    56
#define STI_AGC_Y_TM_ALL    57
#define STI_AGC_X_TF_ALL    58
#define STI_AGC_Y_TF_ALL    59


#define	STE_DEV_GRAPH	0x00000001
#define	STE_DEV_TEST	0x00000002
#define	STE_FACTORY_GRAPH	0x00000004
#define	STE_FACTORY_TEST	0x00000008
#define	STE_PCBA_CUSTOMER_GRAPH	0x00000010
#define	STE_PCBA_CUSTOMER_TEST	0x00000020
#define	STE_END_USER_GRAPH	0x00000040
#define	STE_END_USER_TEST	0x00000080
#define STE_ALL_ITEMS   0xFFFFFFF




static int isUNT(int testNo)
{
    if (testNo >= STI_UNT_X_TB && testNo <= STI_UNT_Y_TF)
        return 1;
    else
        return 0;
}

static int isRVR(int testNo)
{
    if (testNo >= STI_RVR_X_TB && testNo <= STI_RVR_Y_TF)
        return 1;
    else
        return 0;
}
static int isSingleSignalTest(int testNo)
{
    if (isUNT(testNo) || isRVR(testNo))
        return 0;
//    if (testNo >= STI_ADC_X_TB && testNo <= STI_AGC_Y_TF)
//        return 1;
//    else if (testNo >= STI_ADC_X_TB_ALL && testNo <= STI_AGC_Y_TF_ALL)
//        return 1;
    return 1;
}


int touch_vendor_add(struct touch_vendor_info *info);
int touch_vendor_remove(struct touch_vendor_info *info);
void touch_vendor_remove_all(void);
touch_device *hid_find_touchdevice(touch_device *existDevice,int *count);
int hid_check(touch_device *dev);
void *free_touchdevice(touch_device *devices);
#define touch_reponse_ok(package) \
    (((package)->master_cmd == TOUCH_M_CMD_RESPONSE) && ((package)->sub_cmd == TOUCH_S_CMD_RESPONSE_SUCCEED))



/*
#ifdef __cplusplus
} // extern "C"
#endif
*/
#endif // TOUCH_H
