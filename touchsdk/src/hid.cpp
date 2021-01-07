/* C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>

/* Unix */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <poll.h>

/* Linux */
#include <linux/hidraw.h>
#include <linux/version.h>
#include <linux/input.h>
#include <libudev.h>

#include "hidapi.h"
#include "CommandThread.h"
#include "touch.h"
#include "utils/tdebug.h"
#include "TouchManager.h"
#include <QProcess>

static int parse_uevent_info(const char *uevent, int *bus_type,
    unsigned short *vendor_id, unsigned short *product_id,
    char **serial_number_utf8, char **product_name_utf8);


/* Definitions from linux/hidraw.h. Since these are new, some distros
   may not have header files which contain them. */
#ifndef HIDIOCSFEATURE
#define HIDIOCSFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
#endif
#ifndef HIDIOCGFEATURE
#define HIDIOCGFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
#endif

#define DEFAULT_REPORT_LENGTH (64)

/* USB HID device property names */
const char *device_string_names[] = {
    "manufacturer",
    "product",
    "serial",
};

/* Symbolic names for the properties above */
enum device_string_id {
    DEVICE_STRING_MANUFACTURER,
    DEVICE_STRING_PRODUCT,
    DEVICE_STRING_SERIAL,

    DEVICE_STRING_COUNT,
};

struct hid_device_ {
    int device_handle;
    int blocking;
    int uses_numbered_reports;
    size_t input_report_length;
    char *read_buf;
    struct hid_device_info *info;
    size_t output_report_length;
};
// support devices
static struct touch_vendor_info default_vendor_touchs[] = {
{0xAED7, 0x0013, "col01", 0xCD, 0},
{0xAED7, 0xFEDC, "col01", 0xCD, 1},
{NULL},
};

typedef struct _touch_vendor_list {
        struct touch_vendor_info *info;
            struct _touch_vendor_list *next;
}touch_vendor_list;

static touch_vendor_list *vendor_list = NULL;

int touch_vendor_add(struct touch_vendor_info *info)
{
    touch_vendor_list *vendor = (touch_vendor_list*)malloc(sizeof(touch_vendor_list));
    touch_vendor_list *next = NULL;
    if (info == NULL)
        return -1;

    vendor->info = (struct touch_vendor_info*)malloc(sizeof(struct touch_vendor_info));
    memcpy(vendor->info, info, sizeof(struct touch_vendor_info));
    if (vendor_list) {
        next = vendor_list->next;
        vendor_list->next = vendor;
    } else {
        vendor_list = vendor;
    }

//    TDEBUG("add touch vendor info: vid=0x%04x,pid=0x%04x,path=%s", vendor->info->vid, vendor->info->pid, vendor->info->path);
    vendor->next = next;
    return 0;
}
int touch_vendor_remove(struct touch_vendor_info *info)
{
    touch_vendor_list *vendor = vendor_list;
    touch_vendor_list *next = NULL;
    touch_vendor_list *prev = NULL;
    if (info == NULL)
        return -1;

    while (vendor) {
        next = vendor->next;
        if (info == vendor->info) {
            // first
            if (vendor == vendor_list) {
                vendor_list = vendor->next;
                free(vendor);
                return 0;
            } else {
                if (prev) {
                    prev->next = vendor->next;
                    free(vendor);
                    return 0;
                }
            }
        }
        prev = vendor;
        vendor = next;
    }
    return -2;
}
void touch_vendor_remove_all(void)
{
    touch_vendor_list *vendor = vendor_list;
    touch_vendor_list *temp = NULL;
    while (vendor) {
        temp = vendor->next;
        free(vendor);
        vendor = temp;
    }
}
//寻找触摸屏设备
touch_device *HID_API_EXPORT HID_API_CALL hid_find_touchdevice(touch_device *existDevice,int *count)
{
    bool res;
    struct hid_device_info *root = NULL; // return object
    struct hid_device_info *cur_dev = NULL;
    int vendor_touch_count = sizeof(default_vendor_touchs) / sizeof(struct touch_vendor_info);
    struct touch_vendor_info *temp_vendor;
    touch_device *device, *root_device = NULL, *tmp_device = NULL;
    int found = 0;
    int touchCount = 0;


    #define WSTR_LEN 512
    struct hid_device_info *tmp;
    size_t len;

    touch_vendor_list *vendor = NULL;

    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices, *dev_list_entry;
    struct hid_device_info *prev_dev = NULL; /* previous device */

    if (hid_init() < 0)
        return NULL;
    /* Create the udev object */
    udev = udev_new();
    if (!udev) {
        TDEBUG("Can't create udev\n");
        return NULL;
    }
    /* Create a list of the devices in the 'hidraw' subsystem. */
    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "hidraw");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item, see if it matches the vid/pid, and if so
           create a udev_device record for it */
    udev_list_entry_foreach(dev_list_entry, devices) {
        const char *sysfs_path;
        const char *dev_path;
        const char *str;
        struct udev_device *raw_dev; /* The device's hidraw udev node. */
        struct udev_device *hid_dev; /* The device's HID udev node. */
        struct udev_device *usb_dev; /* The device's USB udev node. */
        struct udev_device *intf_dev; /* The device's interface (in the USB sense). */
        unsigned short dev_vid;
        unsigned short dev_pid;
        char *serial_number_utf8 = NULL;
        char *product_name_utf8 = NULL;
        int bus_type;
        int result;
        bool existDev = false;

        /* Get the filename of the /sys entry for the device
                   and create a udev_device object (dev) representing it */
        sysfs_path = udev_list_entry_get_name(dev_list_entry);
        raw_dev = udev_device_new_from_syspath(udev, sysfs_path);
        dev_path = udev_device_get_devnode(raw_dev);


        touch_device *tmpExistDev = existDevice;
        while (tmpExistDev) {
            existDev = false;
            if(tmpExistDev->touch.connected == 1 && strcmp(tmpExistDev->info->path,dev_path) == 0)
            {
                existDev = true;
                break;
            }
            tmpExistDev = tmpExistDev->next;
        }
        if(existDev)
        {
            goto next;
        }

        hid_dev = udev_device_get_parent_with_subsystem_devtype(
            raw_dev,
            "hid",
            NULL);

        if (!hid_dev) {
            /* Unable to find parent hid device. */
            goto next;
        }
        result = parse_uevent_info(
            udev_device_get_sysattr_value(hid_dev, "uevent"),
            &bus_type,
            &dev_vid,
            &dev_pid,
            &serial_number_utf8,
            &product_name_utf8);

        if (!result) {
            /* parse_uevent_info() failed for at least one field. */
            goto next;
        }

        if (bus_type != BUS_USB) {
            /* We only know how to handle USB and BT devices. */
            goto next;
        }

        /* Check the VID/PID against the arguments */
        found = 0;
        //        printf("HID: 0x%x 0x%x, %s\n", attrib.VendorID, attrib.ProductID, device_interface_detail_data->DevicePath);
        if (dev_vid != 0 && dev_pid != 0) {
            for (int i = 0; i < vendor_touch_count; i++) {
                temp_vendor = &default_vendor_touchs[i];
                if (temp_vendor == NULL) break;

//                if (temp_vendor->vid == dev_vid && temp_vendor->pid == dev_pid
//                        && strstr(device_interface_detail_data->DevicePath, temp_vendor->path) != NULL) {
//                    found = 1;
//                    break;
//                }
                if (temp_vendor->vid == dev_vid && temp_vendor->pid == dev_pid) {
                    found = 1;
                    break;
                }
            }

            vendor = vendor_list;
            while (vendor) {

                temp_vendor = vendor->info;

//                if (temp_vendor->vid == dev_vid && temp_vendor->pid == dev_pid
//                        && strstr(device_interface_detail_data->DevicePath, temp_vendor->path) != NULL) {
//                    found = 1;
//    //                qDebug("vid:=%x, pid=%x, bootloader=%d, repord_id=0x%x, path=%s\n",
//    //                       temp_vendor->vid, temp_vendor->pid,
//    //                       temp_vendor->bootloader, temp_vendor->rid, temp_vendor->path);
//                    break;
//                }
                if (temp_vendor->vid == dev_vid && temp_vendor->pid == dev_pid) {
                    found = 1;
    //                qDebug("vid:=%x, pid=%x, bootloader=%d, repord_id=0x%x, path=%s\n",
    //                       temp_vendor->vid, temp_vendor->pid,
    //                       temp_vendor->bootloader, temp_vendor->rid, temp_vendor->path);
                    break;
                }
                vendor = vendor->next;
            }
        }

        if (found && temp_vendor != NULL) {
//            TVERBOSE("## %d,  vid:=%x, pid=%x, bootloader=%d, repord_id=0x%x, path=%s\n",
//                     found,
//                     temp_vendor->vid, temp_vendor->pid,
//                     temp_vendor->bootloader, temp_vendor->rid, temp_vendor->path);
            TDEBUG("##########vid:=%x, pid=%x",temp_vendor->vid, temp_vendor->pid);
        }

        if (found) {
//            TDEBUG("sysfs_path = %s\n raw_dev = %s\ndev_path = %s",sysfs_path,raw_dev,dev_path);
            device = (touch_device*)malloc(sizeof(touch_device));
            memset(device, 0, sizeof(touch_device));
            /* VID/PID match. Create the record. */
            tmp = (struct hid_device_info*) calloc(1, sizeof(struct hid_device_info));
            if (cur_dev) {
                cur_dev->next = tmp;
            }
            else {
                root = tmp;
            }
            cur_dev = tmp;

            /* Fill out the record */
            cur_dev->next = NULL;

            str = dev_path? strdup(dev_path): NULL;
//            str = sysfs_path;
            TDEBUG("str = %s",str);
           if (str) {
               len = strlen(str);
               cur_dev->path = (char*) calloc(len+1, sizeof(char));
               strncpy(cur_dev->path, str, len+1);
               cur_dev->path[len] = '\0';
           }
           else
               cur_dev->path = NULL;



            /* VID/PID */
            cur_dev->vendor_id = dev_vid;
            cur_dev->product_id = dev_pid;

            /* Serial Number */
            cur_dev->serial_number = utf8_to_wchar_t(serial_number_utf8);


            device->next = tmp_device;
            device->info = cur_dev;

            device->hid = hid_open_path(device->info->path);
            if(device->hid == NULL)
            {
                free(device);
                goto next;
            }
            if (device->hid != NULL)
                device->touch.output_report_length = device->hid->output_report_length;
            else
                device->touch.output_report_length = DEFAULT_REPORT_LENGTH;

            if (temp_vendor != NULL) {
                device->touch.report_id = temp_vendor->rid;
                device->touch.booloader = temp_vendor->bootloader;
            }
            device->touch.connected = 1;

            tmp_device = device;

            touchCount++;
        }

        next:
        free(serial_number_utf8);
        free(product_name_utf8);
        udev_device_unref(raw_dev);
        /* hid_dev, usb_dev and intf_dev don't need to be (and can't be)
           unref()d.  It will cause a double-free() error.  I'm not
           sure why.  */

    }

    root_device = tmp_device;
    tmp_device = root_device;
//    while (tmp_device) {
//        TDEBUG("try %s", tmp_device->info->path);
//        tmp_device->hid = hid_open_path(tmp_device->info->path);
//        if (tmp_device->hid != NULL)
//            tmp_device->touch.output_report_length = tmp_device->hid->output_report_length;
//        else
//            tmp_device->touch.output_report_length = DEFAULT_REPORT_LENGTH;
//        tmp_device = tmp_device->next;
//    }

    if (count != NULL)
        *count = touchCount;
    return root_device;

}
int HID_API_EXPORT HID_API_CALL hid_check(touch_device *dev)
{
    size_t maxlen = 256;
    wchar_t *string = (wchar_t *)malloc(maxlen * sizeof(wchar_t *));
    int ret = hid_get_serial_number_string(dev->hid,string,maxlen);

    if(strncmp((const char *)string,(const char *)dev->info->serial_number,strlen((const char *)dev->info->serial_number) != 0))
    {
//        TDEBUG("hid_check ret = %d,strncmp == 0",ret);
        free(string);
        return 0;
    }
    else
    {
//        TDEBUG("hid_check == %d,strncmp != 0",ret);
        free(string);
        return 1;
    }
}

void HID_API_EXPORT * HID_API_CALL free_touchdevice(touch_device *devices)
{
    touch_device *tmp = NULL;
    while (devices) {
        if (devices->hid) {
            devices->hid = NULL;
            hid_close(devices->hid);
        }
        if (devices->info) {
            devices->info->next = NULL;
            hid_free_enumeration(devices->info);
        }
        tmp = devices->next;
        free(devices);
        devices = tmp;
    }
    return NULL;
}
touch_package *getPackage(unsigned char masterCmd, unsigned char subCmd,
                                        unsigned char dataLength, unsigned char *data)
{
    touch_package *package = (touch_package*)malloc(sizeof(touch_package));
    memset(package, 0, sizeof(touch_package));
    package->master_cmd = masterCmd;
    package->sub_cmd = subCmd;
    package->data_length = dataLength;
    if (data != NULL) {
        memcpy(package->data, data, dataLength);
    }
    return package;
}
void putPackage(touch_package *package) { if (package) free(package);}

int hidReadTimeOut = 3000;
int hid_send_data(hid_device *dev, struct hid_report_data *data, struct hid_report_data *back)
{
    if (data == NULL)
        return -1;
    if (dev != NULL && dev->info != NULL) {
        data->report_id = dev->info->report_id;
    }

    // Clear data buffer
    int r = 1;
//    int count = 10;
    r = 1;

    while (r > 0) {
        r = hid_read_timeout(dev, (unsigned char*)back, HID_REPORT_DATA_LENGTH, 0);
    }
    int ret = hid_write(dev, (unsigned char*)data, sizeof(struct hid_report_data));
    if (back == NULL)
        return ret;
    if (ret < 0)
        return ret;
    hid_set_nonblocking(dev, 0);
    // FIXME: for this touch device, report id is in back data;
    //back->report_id = data->report_id;

   ret = hid_read_timeout(dev, (unsigned char*)back, HID_REPORT_DATA_LENGTH, 0);

    return ret;
}

static __u32 kernel_version = 0;

static __u32 detect_kernel_version(void)
{
    struct utsname name;
    int major, minor, release;
    int ret;

    uname(&name);
    ret = sscanf(name.release, "%d.%d.%d", &major, &minor, &release);
    if (ret == 3) {
        return KERNEL_VERSION(major, minor, release);
    }

    ret = sscanf(name.release, "%d.%d", &major, &minor);
    if (ret == 2) {
        return KERNEL_VERSION(major, minor, 0);
    }

    printf("Couldn't determine kernel version from version string \"%s\"\n", name.release);
    return 0;
}

static hid_device *new_hid_device(void)
{
    hid_device *dev = (hid_device *)calloc(1, sizeof(hid_device));
    dev->device_handle = -1;
    dev->blocking = 1;
    dev->uses_numbered_reports = 0;

    return dev;
}


/* The caller must free the returned string with free(). */
static wchar_t *utf8_to_wchar_t(const char *utf8)
{
    wchar_t *ret = NULL;

    if (utf8) {
        size_t wlen = mbstowcs(NULL, utf8, 0);
        if ((size_t) -1 == wlen) {
            return wcsdup(L"");
        }
        ret = (wchar_t *)calloc(wlen+1, sizeof(wchar_t));
        mbstowcs(ret, utf8, wlen+1);
        ret[wlen] = 0x0000;
    }

    return ret;
}

/* Get an attribute value from a udev_device and return it as a whar_t
   string. The returned string must be freed with free() when done.*/
static wchar_t *copy_udev_string(struct udev_device *dev, const char *udev_name)
{
    return utf8_to_wchar_t(udev_device_get_sysattr_value(dev, udev_name));
}

/* uses_numbered_reports() returns 1 if report_descriptor describes a device
   which contains numbered reports. */
static int uses_numbered_reports(__u8 *report_descriptor, __u32 size) {
    unsigned int i = 0;
    int size_code;
    int data_len, key_size;

    while (i < size) {
        int key = report_descriptor[i];

        /* Check for the Report ID key */
        if (key == 0x85/*Report ID*/) {
            /* This device has a Report ID, which means it uses
               numbered reports. */
            return 1;
        }

        //printf("key: %02hhx\n", key);

        if ((key & 0xf0) == 0xf0) {
            /* This is a Long Item. The next byte contains the
               length of the data section (value) for this key.
               See the HID specification, version 1.11, section
               6.2.2.3, titled "Long Items." */
            if (i+1 < size)
                data_len = report_descriptor[i+1];
            else
                data_len = 0; /* malformed report */
            key_size = 3;
        }
        else {
            /* This is a Short Item. The bottom two bits of the
               key contain the size code for the data section
               (value) for this key.  Refer to the HID
               specification, version 1.11, section 6.2.2.2,
               titled "Short Items." */
            size_code = key & 0x3;
            switch (size_code) {
            case 0:
            case 1:
            case 2:
                data_len = size_code;
                break;
            case 3:
                data_len = 4;
                break;
            default:
                /* Can't ever happen since size_code is & 0x3 */
                data_len = 0;
                break;
            };
            key_size = 1;
        }

        /* Skip over this key and it's associated data */
        i += data_len + key_size;
    }

    /* Didn't find a Report ID key. Device doesn't use numbered reports. */
    return 0;
}

/*
 * The caller is responsible for free()ing the (newly-allocated) character
 * strings pointed to by serial_number_utf8 and product_name_utf8 after use.
 */
static int parse_uevent_info(const char *uevent, int *bus_type,
    unsigned short *vendor_id, unsigned short *product_id,
    char **serial_number_utf8, char **product_name_utf8)
{
    char *tmp = strdup(uevent);
    char *saveptr = NULL;
    char *line;
    char *key;
    char *value;

    int found_id = 0;
    int found_serial = 0;
    int found_name = 0;

    line = strtok_r(tmp, "\n", &saveptr);
    while (line != NULL) {
        /* line: "KEY=value" */
        key = line;
        value = strchr(line, '=');
        if (!value) {
            goto next_line;
        }
        *value = '\0';
        value++;

        if (strcmp(key, "HID_ID") == 0) {
            /**
             *        type vendor   product
             * HID_ID=0003:000005AC:00008242
             **/
            int ret = sscanf(value, "%x:%hx:%hx", bus_type, vendor_id, product_id);
            if (ret == 3) {
                found_id = 1;
            }
        } else if (strcmp(key, "HID_NAME") == 0) {
            /* The caller has to free the product name */
            *product_name_utf8 = strdup(value);
            found_name = 1;
        } else if (strcmp(key, "HID_UNIQ") == 0) {
            /* The caller has to free the serial number */
            *serial_number_utf8 = strdup(value);
            found_serial = 1;
        }

next_line:
        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(tmp);
    return (found_id && found_name && found_serial);
}


static int get_device_string(hid_device *dev, enum device_string_id key, wchar_t *string, size_t maxlen)
{
    struct udev *udev;
    struct udev_device *udev_dev, *parent, *hid_dev;
    struct stat s;
    int ret = -1;
        char *serial_number_utf8 = NULL;
        char *product_name_utf8 = NULL;

    /* Create the udev object */
    udev = udev_new();
    if (!udev) {
        TDEBUG("Can't create udev\n");
        return -1;
    }

    /* Get the dev_t (major/minor numbers) from the file handle. */
    ret = fstat(dev->device_handle, &s);
    if (-1 == ret)
        return ret;
    /* Open a udev device from the dev_t. 'c' means character device. */
    udev_dev = udev_device_new_from_devnum(udev, 'c', s.st_rdev);
    if (udev_dev) {
        hid_dev = udev_device_get_parent_with_subsystem_devtype(
            udev_dev,
            "hid",
            NULL);
        if (hid_dev) {
            unsigned short dev_vid;
            unsigned short dev_pid;
            int bus_type;
            size_t retm;

            ret = parse_uevent_info(
                       udev_device_get_sysattr_value(hid_dev, "uevent"),
                       &bus_type,
                       &dev_vid,
                       &dev_pid,
                       &serial_number_utf8,
                       &product_name_utf8);

            if (bus_type == BUS_BLUETOOTH) {
                switch (key) {
                    case DEVICE_STRING_MANUFACTURER:
                        wcsncpy(string, L"", maxlen);
                        ret = 0;
                        break;
                    case DEVICE_STRING_PRODUCT:
                        retm = mbstowcs(string, product_name_utf8, maxlen);
                        ret = (retm == (size_t)-1)? -1: 0;
                        break;
                    case DEVICE_STRING_SERIAL:
                        retm = mbstowcs(string, serial_number_utf8, maxlen);
                        ret = (retm == (size_t)-1)? -1: 0;
                        break;
                    case DEVICE_STRING_COUNT:
                    default:
                        ret = -1;
                        break;
                }
            }
            else {
                /* This is a USB device. Find its parent USB Device node. */
                parent = udev_device_get_parent_with_subsystem_devtype(
                       udev_dev,
                       "usb",
                       "usb_device");
                if (parent) {
                    const char *str;
                    const char *key_str = NULL;

                    if (key >= 0 && key < DEVICE_STRING_COUNT) {
                        key_str = device_string_names[key];
                    } else {
                        ret = -1;
                        goto end;
                    }

                    str = udev_device_get_sysattr_value(parent, key_str);
                    if (str) {
                        /* Convert the string from UTF-8 to wchar_t */
                        retm = mbstowcs(string, str, maxlen);
                        ret = (retm == (size_t)-1)? -1: 0;
                        goto end;
                    }
                }
            }
        }
    }

end:
        free(serial_number_utf8);
        free(product_name_utf8);

    udev_device_unref(udev_dev);
    /* parent and hid_dev don't need to be (and can't be) unref'd.
       I'm not sure why, but they'll throw double-free() errors. */
//    udev_unref(udev);

    return ret;
}

int HID_API_EXPORT hid_init(void)
{
    const char *locale;

    /* Set the locale if it's not set. */
    locale = setlocale(LC_CTYPE, NULL);
    if (!locale)
        setlocale(LC_CTYPE, "");

    kernel_version = detect_kernel_version();

    return 0;
}

int HID_API_EXPORT hid_exit(void)
{
    /* Nothing to do for this in the Linux/hidraw implementation. */
    return 0;
}


struct hid_device_info  HID_API_EXPORT *hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices, *dev_list_entry;

    struct hid_device_info *root = NULL; /* return object */
    struct hid_device_info *cur_dev = NULL;
    struct hid_device_info *prev_dev = NULL; /* previous device */

    hid_init();

    /* Create the udev object */
    udev = udev_new();
    if (!udev) {
        printf("Can't create udev\n");
        return NULL;
    }

    /* Create a list of the devices in the 'hidraw' subsystem. */
    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "hidraw");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);
    /* For each item, see if it matches the vid/pid, and if so
       create a udev_device record for it */
    udev_list_entry_foreach(dev_list_entry, devices) {
        const char *sysfs_path;
        const char *dev_path;
        const char *str;
        struct udev_device *raw_dev; /* The device's hidraw udev node. */
        struct udev_device *hid_dev; /* The device's HID udev node. */
        struct udev_device *usb_dev; /* The device's USB udev node. */
        struct udev_device *intf_dev; /* The device's interface (in the USB sense). */
        unsigned short dev_vid;
        unsigned short dev_pid;
        char *serial_number_utf8 = NULL;
        char *product_name_utf8 = NULL;
        int bus_type;
        int result;

        /* Get the filename of the /sys entry for the device
           and create a udev_device object (dev) representing it */
        sysfs_path = udev_list_entry_get_name(dev_list_entry);
        raw_dev = udev_device_new_from_syspath(udev, sysfs_path);
        dev_path = udev_device_get_devnode(raw_dev);

        hid_dev = udev_device_get_parent_with_subsystem_devtype(
            raw_dev,
            "hid",
            NULL);

        if (!hid_dev) {
            /* Unable to find parent hid device. */
            goto next;
        }

        result = parse_uevent_info(
            udev_device_get_sysattr_value(hid_dev, "uevent"),
            &bus_type,
            &dev_vid,
            &dev_pid,
            &serial_number_utf8,
            &product_name_utf8);

        if (!result) {
            /* parse_uevent_info() failed for at least one field. */
            goto next;
        }

        if (bus_type != BUS_USB && bus_type != BUS_BLUETOOTH) {
            /* We only know how to handle USB and BT devices. */
            goto next;
        }

        /* Check the VID/PID against the arguments */
        if ((vendor_id == 0x0 || vendor_id == dev_vid) &&
            (product_id == 0x0 || product_id == dev_pid)) {
            struct hid_device_info *tmp;

            /* VID/PID match. Create the record. */
            tmp = (hid_device_info *)malloc(sizeof(struct hid_device_info));
            if (cur_dev) {
                cur_dev->next = tmp;
            }
            else {
                root = tmp;
            }
            prev_dev = cur_dev;
            cur_dev = tmp;

            /* Fill out the record */
            cur_dev->next = NULL;
            cur_dev->path = dev_path? strdup(dev_path): NULL;

            /* VID/PID */
            cur_dev->vendor_id = dev_vid;
            cur_dev->product_id = dev_pid;

            /* Serial Number */
            cur_dev->serial_number = utf8_to_wchar_t(serial_number_utf8);

            /* Release Number */
            cur_dev->release_number = 0x0;

            /* Interface Number */
            cur_dev->interface_number = -1;

            switch (bus_type) {
                case BUS_USB:
                    /* The device pointed to by raw_dev contains information about
                       the hidraw device. In order to get information about the
                       USB device, get the parent device with the
                       subsystem/devtype pair of "usb"/"usb_device". This will
                       be several levels up the tree, but the function will find
                       it. */
                    usb_dev = udev_device_get_parent_with_subsystem_devtype(
                            raw_dev,
                            "usb",
                            "usb_device");

                    if (!usb_dev) {
                        /* Free this device */
                        free(cur_dev->serial_number);
                        free(cur_dev->path);
                        free(cur_dev);

                        /* Take it off the device list. */
                        if (prev_dev) {
                            prev_dev->next = NULL;
                            cur_dev = prev_dev;
                        }
                        else {
                            cur_dev = root = NULL;
                        }

                        goto next;
                    }

                    /* Manufacturer and Product strings */
                    cur_dev->manufacturer_string = copy_udev_string(usb_dev, device_string_names[DEVICE_STRING_MANUFACTURER]);
                    cur_dev->product_string = copy_udev_string(usb_dev, device_string_names[DEVICE_STRING_PRODUCT]);

                    /* Release Number */
                    str = udev_device_get_sysattr_value(usb_dev, "bcdDevice");
                    cur_dev->release_number = (str)? strtol(str, NULL, 16): 0x0;

                    /* Get a handle to the interface's udev node. */
                    intf_dev = udev_device_get_parent_with_subsystem_devtype(
                            raw_dev,
                            "usb",
                            "usb_interface");
                    if (intf_dev) {
                        str = udev_device_get_sysattr_value(intf_dev, "bInterfaceNumber");
                        cur_dev->interface_number = (str)? strtol(str, NULL, 16): -1;
                    }

                    break;

                case BUS_BLUETOOTH:
                    /* Manufacturer and Product strings */
                    cur_dev->manufacturer_string = wcsdup(L"");
                    cur_dev->product_string = utf8_to_wchar_t(product_name_utf8);

                    break;

                default:
                    /* Unknown device type - this should never happen, as we
                     * check for USB and Bluetooth devices above */
                    break;
            }
        }

    next:
        free(serial_number_utf8);
        free(product_name_utf8);
        udev_device_unref(raw_dev);
        /* hid_dev, usb_dev and intf_dev don't need to be (and can't be)
           unref()d.  It will cause a double-free() error.  I'm not
           sure why.  */
    }
    /* Free the enumerator and udev objects. */
    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return root;
}

void  HID_API_EXPORT hid_free_enumeration(struct hid_device_info *devs)
{
    struct hid_device_info *d = devs;
    while (d) {
        struct hid_device_info *next = d->next;
        free(d->path);
        free(d->serial_number);
        free(d->manufacturer_string);
        free(d->product_string);
        free(d);
        d = next;
    }
}

hid_device * hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number)
{
    struct hid_device_info *devs, *cur_dev;
    const char *path_to_open = NULL;
    hid_device *handle = NULL;

    devs = hid_enumerate(vendor_id, product_id);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->vendor_id == vendor_id &&
            cur_dev->product_id == product_id) {
            if (serial_number) {
                if (wcscmp(serial_number, cur_dev->serial_number) == 0) {
                    path_to_open = cur_dev->path;
                    break;
                }
            }
            else {
                path_to_open = cur_dev->path;
                break;
            }
        }
        cur_dev = cur_dev->next;
    }

    if (path_to_open) {
        /* Open the device */
        handle = hid_open_path(path_to_open);
    }

    hid_free_enumeration(devs);

    return handle;
}

hid_device * HID_API_EXPORT hid_open_path(const char *path)
{
    hid_device *dev = NULL;

    if(hid_init() < 0)
    {
        TDEBUG("hid_init() == NULL ");
        return NULL;
    }

    dev = new_hid_device();

    /* OPEN HERE */
    dev->device_handle = open(path, O_RDWR); 
    if(dev->device_handle < 0)
    {
        char cmd[256] = "sudo chmod 666 ";
        sprintf(cmd + strlen(cmd),path);
        QProcess *proc = new QProcess;
        proc->start(cmd);
        system(cmd);
        dev->device_handle = open(path, O_RDWR);

//        if(dev->device_handle < 0)
//        {
//            memset(cmd,0,sizeof(cmd));
//            sprintf(cmd,"pkexec sudo chmod 666 ");
//            sprintf(cmd,"sudo -S ");
//            sprintf(cmd + strlen(cmd),path);
//            sprintf(cmd  + strlen(cmd)," << EOF \n123456\nEOF");

//            TDEBUG("cmd = %s",cmd);
//            TDEBUG("system(cmd) = %d", + system("echo 123456 | sudo -S chmod 777 /dev/hidraw11"));
//            sprintf(cmd,"echo %s | sudo -S chmod 777 %s",TouchManager::rootPasswd,path);

//            TDEBUG("cmd = %s",cmd);

//            if(execl("/usr/share/TouchAssistant/changePermissoin.sh","changePermissoin.sh",TouchManager::rootPasswd,path,NULL) < 0)
//            if(execl("/home/xjf/Desktop/touchProject/touch/build-touch/changePermissoin.sh","changePermissoin.sh",TouchManager::rootPasswd,path,NULL) < 0)
//            {
//                perror("execl error");
//            }
//            pid_t pid;
//            pid = fork();
//            if(pid == 0)
//            {
//                if(execl("/home/xjf/Desktop/touchProject/touch/build-touch/changePermissoin.sh","changePermissoin.sh","123456","/dev/hidraw11",NULL) < 0)
//                if(execl("/home/xjf/testC/change.sh","change.sh","123456","777",NULL) < 0)
//                {
//                    perror("execl error");
//                }
//                if(execl("/bin/ls", "/bin/ls",  "-l" , "/etc", NULL) < 0)
//                {
//                    perror("execl error");
//                }
//                else
//                {
//                    TDEBUG("execl successfully");
//                }
//            }
//            int status;
//            wait(&status);

//            dev->device_handle = open(path, O_RDWR);

//        }
    }

    TDEBUG("dev->device_handle = %d",dev->device_handle);
    /* If we have a good handle, return it. */
    if (dev->device_handle > 0) {

        /* Get the report descriptor */
        int res, desc_size = 0;
        struct hidraw_report_descriptor rpt_desc;

        memset(&rpt_desc, 0x0, sizeof(rpt_desc));

        /* Get Report Descriptor Size */
        res = ioctl(dev->device_handle, HIDIOCGRDESCSIZE, &desc_size);
        if (res < 0)
        {
           TDEBUG("HIDIOCGRDESCSIZE");
           goto err;
        }

        /* Get Report Descriptor */
        rpt_desc.size = desc_size;
//        TDEBUG("@@@@@@@ desc_size = %d",desc_size);
        res = ioctl(dev->device_handle, HIDIOCGRDESC, &rpt_desc);
        if (res < 0) {
            TDEBUG("HIDIOCGRDESC");
            goto err;
        } else {
            /* Determine if this device uses numbered reports. */
            dev->uses_numbered_reports =
                uses_numbered_reports(rpt_desc.value,
                                      rpt_desc.size);
//            TDEBUG("@@@@@@@ rpt_desc = %d",rpt_desc.size);
        }
        dev->output_report_length = DEFAULT_REPORT_LENGTH;
        dev->read_buf = (char*) malloc(dev->output_report_length);
        return dev;
    }
    else {
        TDEBUG("device open error.");
    }

err:
        /* Unable to open any devices. */

        hid_close(dev);
//        free(dev);
        return NULL;

}


int HID_API_EXPORT hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
    int bytes_written;

    bytes_written = write(dev->device_handle, data, length);

    return bytes_written;
}


int HID_API_EXPORT hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
    int bytes_read;

    if (milliseconds >= 0) {
        /* Milliseconds is either 0 (non-blocking) or > 0 (contains
           a valid timeout). In both cases we want to call poll()
           and wait for data to arrive.  Don't rely on non-blocking
           operation (O_NONBLOCK) since some kernels don't seem to
           properly report device disconnection through read() when
           in non-blocking mode.  */
        int ret;
        struct pollfd fds;

        fds.fd = dev->device_handle;
        fds.events = POLLIN;
        fds.revents = 0;
        ret = poll(&fds, 1, milliseconds);
        if (ret == -1 || ret == 0) {
            /* Error or timeout */
            return ret;
        }
        else {
            /* Check for errors on the file descriptor. This will
               indicate a device disconnection. */
            if (fds.revents & (POLLERR | POLLHUP | POLLNVAL))
                return -1;
        }
    }

    bytes_read = read(dev->device_handle, data, length);
    if (bytes_read < 0 && (errno == EAGAIN || errno == EINPROGRESS))
        bytes_read = 0;

    if (bytes_read >= 0 &&
        kernel_version != 0 &&
        kernel_version < KERNEL_VERSION(2,6,34) &&
        dev->uses_numbered_reports) {
        /* Work around a kernel bug. Chop off the first byte. */
        memmove(data, data+1, bytes_read);
        bytes_read--;
    }

    return bytes_read;
}

int HID_API_EXPORT hid_read(hid_device *dev, unsigned char *data, size_t length)
{
    return hid_read_timeout(dev, data, length, (dev->blocking)? -1: 0);
}

int HID_API_EXPORT hid_set_nonblocking(hid_device *dev, int nonblock)
{
    /* Do all non-blocking in userspace using poll(), since it looks
       like there's a bug in the kernel in some versions where
       read() will not return -1 on disconnection of the USB device */

    dev->blocking = !nonblock;
    return 0; /* Success */
}


int HID_API_EXPORT hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length)
{
    int res;

    res = ioctl(dev->device_handle, HIDIOCSFEATURE(length), data);
    if (res < 0)
        perror("ioctl (SFEATURE)");

    return res;
}

int HID_API_EXPORT hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length)
{
    int res;

    res = ioctl(dev->device_handle, HIDIOCGFEATURE(length), data);
    if (res < 0)
        perror("ioctl (GFEATURE)");


    return res;
}


void HID_API_EXPORT hid_close(hid_device *dev)
{
    if (!dev)
        return;
    close(dev->device_handle);
    free(dev);
}


int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_device_string(dev, DEVICE_STRING_MANUFACTURER, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_device_string(dev, DEVICE_STRING_PRODUCT, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_device_string(dev, DEVICE_STRING_SERIAL, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
    return -1;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
    return NULL;
}
