import QtQuick 2.7

import QtQuick.Controls 1.4 as Cont1
import QtQuick.Controls 2.0
import QtQuick.Controls.Styles 1.4
import QtQuick.Layouts 1.3
Item {
    property int defaultSpacing: 10
    property int labelSize: 25
    property var mSettings: []
    property var refreshing: true
    property var caliDataModel: null
    property var caliDataDelegate: calibrationDataDelegate

    property bool updateSettings: false
    signal clickCalibration();
    id: root

    Keys.enabled: true
    Keys.onPressed: {

        switch (event.key) {
        case Qt.Key_1:
            if (usbModeEnabledBox.checked) {
                if (usbModeMouse.checked) {
                    usbModeMouse.checked = false;
                    usbModeTouch.checked = true;
                } else {
                    usbModeMouse.checked = true;
                    usbModeTouch.checked = false;
                    usbModeEnabledBox.checked = false;
                }
            } else {
                usbModeEnabledBox.checked = true;
            }

            break;

        case Qt.Key_2:
//            if (serialModeEnabledBox.checked) {
////                if (serialModeGroup.buttons[1].checked) {
////                    serialModeGroup.buttons[1].checked = false;
////                    serialModeGroup.buttons[0].checked = true;
////                } else {
////                    serialModeGroup.buttons[0].checked = false;
////                    serialModeGroup.buttons[1].checked = true;
////                    serialModeEnabledBox.checked = false;
////                }
//            } else {
//                serialModeEnabledBox.checked = true;
//            }
            serialModeEnabledBox.checked = !serialModeEnabledBox.checked;

            break;

        case Qt.Key_3:
            if (!xMirrorCheckBox.checked && !yMirrorCheckBox.checked) {
                xMirrorCheckBox.checked = true;
            } else if (xMirrorCheckBox.checked && !yMirrorCheckBox.checked) {
                yMirrorCheckBox.checked = true;
            } else if (xMirrorCheckBox.checked && yMirrorCheckBox.checked) {
                xMirrorCheckBox.checked = false;
            } else {
                xMirrorCheckBox.checked = yMirrorCheckBox.checked = false;
            }

            break;
        case Qt.Key_4: {

            var count = touchRotationGroup.buttons.length;
            var button = touchRotationGroup.checkedButton;
//            console.log("count=" + count + " mode=" + button.mode);
            button.checked = false;
            var nextMode = button.mode + 1;
            if (button.mode === (count - 1)) {
                nextMode = 0;
            }
            for (var index = 0; index < count; index++) {
                if (nextMode === touchRotationGroup.buttons[index].mode) {
                    touchRotationGroup.buttons[index].checked = true;
                    break;
                }
            }

            break;
        }

        case Qt.Key_5: {
            count = screenRotationGroup.buttons.length;
            button = screenRotationGroup.checkedButton;
//            console.log("count=" + count + " mode=" + button.mode);
            button.checked = false;
            nextMode = button.mode + 1;
            if (button.mode === (count - 1)) {
                nextMode = 0;
            }
            for (var index = 0; index < count; index++) {
                if (nextMode === screenRotationGroup.buttons[index].mode) {
                    screenRotationGroup.buttons[index].checked = true;
                    break;
                }
            }

            break;
        }
        case Qt.Key_6: {
            count = macOsGroup.buttons.length;
            button = macOsGroup.checkedButton;
//            console.log("count=" + count + " mode=" + button.mode);
            button.checked = false;
            nextMode = button.mode + 1;
            if (button.mode === (count - 1)) {
                nextMode = 0;
            }
            for (var index = 0; index < count; index++) {
                if (nextMode === macOsGroup.buttons[index].mode) {
                    macOsGroup.buttons[index].checked = true;
                    break;
                }
            }

            break;
        }
        }
    }

    function refreshSettings() {
        console.log("refresh settings")
        refreshing = true;
        var settings = touch.getSettingsInfos();
        var enables = true;
        var buttons;
        var btn;
        if (settings.usbMode !== undefined && settings.usbMode !== -1) {
            for (var i = 0; i < usbModeGroup.buttons.length; i++) {
                btn = usbModeGroup.buttons[i];
                if (btn.mode === settings.usbMode) {
                    btn.checked = true;
                    break;
                }
            }
            enables = true;
        } else {
            enables = false;
        }

        buttons = usbModeGroup.buttons;
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].enabled = enables;
            if (enables === false) {
                buttons[i].checked = false;
            }
        }

        enables = true;
        if (settings.serialMode !== undefined && settings.serialMode !== -1) {
            for (var i = 0; i < serialModeGroup.buttons.length; i++) {
                btn = serialModeGroup.buttons[i];
                if (btn.mode === settings.serialMode) {
                    btn.checked = true;
                    break;
                }
            }
            enables = true;
        } else {
            enables = false;
        }

        buttons = serialModeGroup.buttons;
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].enabled = enables;
            if (enables === false) {
                buttons[i].checked = enables;
            }
        }

        enables = false;
        if (settings.touchRotation !== undefined && settings.touchRotation !== -1) {
            for (var i = 0; i < touchRotationGroup.buttons.length; i++) {
                btn = touchRotationGroup.buttons[i];
                if (btn.mode === settings.touchRotation) {
                    btn.checked = true;
                    break;
                }
            }
            enables = true;
        } else {
            enables = false;
        }
        buttons = touchRotationGroup.buttons;
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].enabled = enables;
            if (enables === false) {
                buttons[i].checked = enables;
            }
        }

        if (settings.screenRotation !== undefined && settings.screenRotation !== -1) {
            for (var i = 0; i < screenRotationGroup.buttons.length; i++) {
                btn = screenRotationGroup.buttons[i];
                if (btn.mode === settings.screenRotation) {
                    btn.checked = true;
                    break;
                }
            }
            enables = true;
        } else {
            enables = false;
        }
        buttons = screenRotationGroup.buttons;
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].enabled = enables;
            if (enables === false) {
                buttons[i].checked = enables;
            }
        }

        if (settings.xMirror !== undefined && settings.xMirror !== -1) {
            xMirrorCheckBox.checked = settings.xMirror === 1;
            xMirrorCheckBox.enabled = true;
        } else {
            xMirrorCheckBox.enabled = false;
        }

        if (settings.yMirror !== undefined && settings.yMirror !== -1) {
            yMirrorCheckBox.checked = settings.yMirror === 1;
            yMirrorCheckBox.enabled = true;
        } else {
            yMirrorCheckBox.enabled = false;
        }

        enables = true;
        if (settings.mac !== undefined && settings.mac !== -1) {
            var mac

            for (var i = 0; i < macOsGroup.buttons.length; i++) {
                mac = macOsGroup.buttons[i];
                if (mac.mode === settings.mac) {
                    mac.checked = true;
                    break;
                }
            }
        } else {
            enables = false;
        }
        buttons = macOsGroup.buttons;
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].enabled = enables;
            if (enables === false) {
                buttons[i].checked = enables;
            }
        }

        mSettings = settings;
        refreshing = false;
        var connected = touch.isDeviceConnected();
        calibrationButtonRow.enabled = connected;
        calibrationList.enabled = connected;
        if (connected) {
            refreshCalibrationData();

            usbModeEnabledBox.enabled = true;
            serialModeEnabledBox.enabled = true;
//            console.log('usb === ' + settings.usbEnabled);
//            console.log('serial === ' + settings.serialEnabled);
            usbModeEnabledBox.checked = serialModeEnabledBox.checked = true;
            usbModeEnabledBox.checked = settings.usbEnabled === 1;
            serialModeEnabledBox.checked = settings.serialEnabled === 1;
        } else {
            usbModeEnabledBox.enabled = false;
            serialModeEnabledBox.enabled = false;
        }

        var lockAGC = settings.lockAGC;
        updateSettings = true;
        lockAGCcb.checked = lockAGC === 1;
        clearUpdate.restart()
    }
    Timer{
        id: clearUpdate
        interval: 200
        running: false
        triggeredOnStart: false
        onTriggered: {
            updateSettings = false;
        }
    }


    Cont1.ScrollView {
        anchors.fill: parent
        Column {
            topPadding: defaultSpacing
            Column {
                Layout.fillWidth: true
                ButtonGroup {
                    id: usbModeGroup
                    onCheckedButtonChanged: {
                        console.log("usb mode:"+checkedButton.mode)
                        if (refreshing) return;
                        touch.setSettings("usbMode", checkedButton.mode);
                    }
                }
                spacing: defaultSpacing
                Row {
                    spacing: defaultSpacing
                    id: usbMode;
                    Label {
                        id: labelView
                        text: qsTr("usb coordinate mode") + "(1)"
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                        width: font.pointSize * labelSize
                    }

                    CheckBox {
                        id: usbModeEnabledBox
                        onClicked: {
//                            touch.setCoordsEnabled(1, checked ? 1: 0);
                        }

                        onCheckedChanged: {
                            usbModeMouse.enabled = checked;
                            usbModeTouch.enabled = ((winVersion === undefined || winVersion !== winXPVersion) ? checked : false)
                            var str = checked?"设置 checked = true":"设置 checked = false";
                            touch.tPrintf(str);
                            touch.setCoordsEnabled(1, checked ? 1: 0);
                        }
                    }

                    RadioButton {
                        id: usbModeMouse
                        text: qsTr("simulate mouse")
                        ButtonGroup.group: usbModeGroup
                        property int mode: 1
                    }
                    RadioButton {
                        id: usbModeTouch
                        property int mode: 2
                        text: qsTr("multitouch")
                        ButtonGroup.group: usbModeGroup
                        //enabled: ((winVersion === undefined || winVersion !== winXPVersion) ? true : false);
                    }
                }
                ButtonGroup {
                    id: serialModeGroup
                    onCheckedButtonChanged: {
                        console.log("serial mode:" + checkedButton.mode)
                        if (refreshing) return;
                        touch.setSettings("serialMode", checkedButton.mode);
                    }
                }
                Row {
                    spacing: defaultSpacing
                    id: serialModeGG
                    Label {
                        text: qsTr("uart coordinate mode") + "(2)"
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }

                    CheckBox {
                        id: serialModeEnabledBox
                        onClicked: {

                        }

                        onCheckedChanged: {
                            var str = checked?"设置 checked = true":"设置 checked = false";
                            touch.setCoordsEnabled(2, checked ? 1: 0);
                            for (var i = 0; i < serialModeGroup.buttons.length; i++) {
                                serialModeGroup.buttons[i].enabled = checked;
                            }
                        }
                    }

                    RadioButton {
                        visible: false
                        text: qsTr("exclude touch size")
                        ButtonGroup.group: serialModeGroup
                        property int mode: 1
                    }
                    RadioButton {
                        visible: false
                        property int mode: 2
                        text: qsTr("include touch size")
                        checked: true
                        ButtonGroup.group: serialModeGroup
                    }
                }

                Rectangle {
                    width: root.width
                    height: 2
                    color: "#9E9E9E"
//                    anchors.top: serialModeGG.bottom
//                    anchors.topMargin: 5
                }

                Row {
                    spacing: defaultSpacing
                    Label {
                        text: qsTr("turn over") + "(3)"
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }

                    CheckBox {
                        text: qsTr("turn over X")
                        id: xMirrorCheckBox
                        onCheckedChanged: {
                            if (refreshing) return;
                            touch.setSettings("xMirror", checked ? 1 : 0);
                        }
                    }
                    CheckBox {
                        id: yMirrorCheckBox
                        text: qsTr("turn over Y")
                        onCheckedChanged: {
                            if (refreshing) return;
                            touch.setSettings("yMirror", checked ? 1 : 0);
                        }
                    }

                    Button {
                        text: qsTr("factory reset")
                        onClicked: {
                            var def = touch.resetXYOrientation();
                            if (def & 0xff) {
                                xMirrorCheckBox.checked = true;
                            } else {
                                xMirrorCheckBox.checked = false;
                            }
                            if (def & 0xff00) {
                                yMirrorCheckBox.checked = true;
                            } else {
                                yMirrorCheckBox.checked = false;
                            }
                        }
                    }
                }
                ButtonGroup {
                    id: touchRotationGroup
                    onCheckedButtonChanged: {
                        if (refreshing) return;
                        touch.setSettings("touchRotation", checkedButton.mode);
                    }
                }
                Row {
                    spacing: defaultSpacing
                    Label {
                        text: qsTr("touch clockwise rotation") + "(4)"
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }

                    RadioButton {
                        property int mode: 0
                        text: "0°"
                        checked: true
                        ButtonGroup.group: touchRotationGroup
                    }
                    RadioButton {
                        property int mode: 1
                        text: "90°"
                        ButtonGroup.group: touchRotationGroup
                    }
                    RadioButton {
                        property int mode: 2
                        text: "180°"
                        ButtonGroup.group: touchRotationGroup
                    }
                    RadioButton {
                        property int mode: 3
                        text: "270°"
                        ButtonGroup.group: touchRotationGroup
                    }

                    Button {
                        text: qsTr("factory reset")
                        onClicked: {
                            var def = touch.resetTouchRotation();
                            var btn;
                            for (var i = 0; i < touchRotationGroup.buttons.length; i++) {
                                btn = touchRotationGroup.buttons[i];
                                if (btn.mode === def) {
                                    btn.checked = true;
                                } else {
                                    btn.checked = false;
                                }
                            }

                        }
                    }
                }

                ButtonGroup {
                    id: screenRotationGroup
                    onCheckedButtonChanged: {
                        if (refreshing) return;
                        touch.setSettings("screenRotation", checkedButton.mode);
                    }
                }
                Row {
                    spacing: defaultSpacing
                    Label {
                        text: qsTr("screen clockwise rotation") + "(5)"
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }

                    RadioButton {
                        property int mode: 0
                        text: "0°"
                        checked: true
                        ButtonGroup.group: screenRotationGroup
                    }
                    RadioButton {
                        property int mode: 1
                        text: "90°"
                        ButtonGroup.group: screenRotationGroup
                    }
                    RadioButton {
                        property int mode: 2
                        text: "180°"
                        ButtonGroup.group: screenRotationGroup
                    }
                    RadioButton {
                        property int mode: 3
                        text: "270°"
                        ButtonGroup.group: screenRotationGroup
                    }
                    Button {
                        text: qsTr("factory reset")
                        onClicked: {
                            var def = touch.resetScreenRotation();
                            var btn;
                            for (var i = 0; i < screenRotationGroup.buttons.length; i++) {
                                btn = screenRotationGroup.buttons[i];
                                if (btn.mode === def) {
                                    btn.checked = true;
                                } else {
                                    btn.checked = false;
                                }
                            }

                        }
                    }
                }

                ButtonGroup {
                    id: macOsGroup
                    onCheckedButtonChanged: {
                        if (refreshing) return;
                        touch.setSettings("mac", checkedButton.mode);
                    }
                }
                Row {
                    spacing: defaultSpacing
                    Label {
                        text: qsTr("MAC OS") + "(6)"
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }

                    RadioButton {
                        property int mode: 0
                        text: qsTr("mac os 10.9 or before")
                        checked: true
                        ButtonGroup.group: macOsGroup
                    }
                    RadioButton {
                        property int mode: 1
                        text: qsTr("mac os 10.10 or later")
                        ButtonGroup.group: macOsGroup
                    }
                    Button {
                        text: qsTr("factory reset")
                        onClicked: {
                            var def = touch.resetMacOs();
                            var btn;
                            for (var i = 0; i < macOsGroup.buttons.length; i++) {
                                btn = macOsGroup.buttons[i];
                                if (btn.mode === def) {
                                    btn.checked = true;
                                } else {
                                    btn.checked = false;
                                }
                            }

                        }
                    }
                }
                CheckBox {
                    id: lockAGCcb
                    text: qsTr("Lock environmental parameters")
                    visible: false
                    onClicked: {
                        console.log("cccc:" + checked)
                        touch.setSettings("lockAGC", checked);
                    }

                    onCheckedChanged: {
                        console.log("on lock agc checked");
//                        if (updateSettings === false)
//                            touch.setSettings("lockAGC", checked);
                    }

                }


                Rectangle {
                    width: root.width
                    height: 2
                    color: "#9E9E9E"
//                    anchors.bottom: calibrationButtonRow.top
//                    anchors.bottomMargin: 10
                }


                Row {
                    id: calibrationButtonRow
                    spacing: 10
                    Label {
                        text: qsTr("calibrate")
                        width: font.pointSize * labelSize
                        height: parent.implicitHeight
                        verticalAlignment: Text.AlignVCenter
                    }
                    Button {
                        id: calibrationStartBtn
                        text: qsTr("recalibration")
                        onClicked: {
                            touch.tPrintf("校准模式");
                            clickCalibration();
//                            calibrationUi.visible = true;
//                            lastVisibility = mainPage.visibility;
//                            showFullScreen();
//                            calibrationView.visible = false;
                        }
                    }
                    Button {
                        text: qsTr("refresh")
                        onClicked: {
                            refreshCalibrationData();
                        }
                    }
                    Button {
                        text: qsTr("set")
                        onClicked: {
                            showProgessing();
                            touch.setCalibrationDatas(createCalibrationData());
                            hideProgessing();var result = touch.saveCalibration();
                            if (result === false) {
                                showToast(qsTr("save data failure"));
                            } else {
                                showToast(qsTr("set success"));
                            }
                        }
                    }
                    Button {
                        text: qsTr("save")
                        onClicked: {
                            calibrationfileDialog.mode = 1;
                            focus = true;
                            calibrationfileDialog.open();
                        }
                    }
                    Button {
                        text: qsTr("read")
                        onClicked: {
                            calibrationfileDialog.mode = 0;
                            focus = true;
                            calibrationfileDialog.open();
                        }
                    }

                    Button {
                        text: calibrationList.visible === true ? qsTr("hide datas") : qsTr("show datas")
                        onClicked: {
                            calibrationList.visible = !calibrationList.visible;
                            resetCalibrationData();
                        }
                    }

                    Button {
                        text: qsTr("factory reset")
                        onClicked: {
                            showProgessing();
                            resetCalibrationData();
                            touch.saveCalibration();
                            hideProgessing();
                        }
                    }
                }

                ListView {
                    id: calibrationList
//                    anchors.top: calibrationButtonRow.bottom
//                    anchors.topMargin: 10
                    anchors.left: parent.left
                    anchors.leftMargin: labelView.width + 10
                    width: parent.width
                    height: 260
                    spacing: 15
                    visible: true

                    header: Row {
                        width: parent.width
                        height: 50
                        spacing: 15
                        Label {
                            topPadding: 10
                            text: qsTr("Number")
                            horizontalAlignment: Text.left
                            width: calibrationTextWidth
                        }
                        Label {
                            topPadding: 10
                            text: qsTr("target point %1").arg("X")
                            horizontalAlignment: Text.Center
                            width: calibrationTextWidth
                        }
                        Label {
                            topPadding: 10
                            text: qsTr("target point %1").arg("Y")
                            horizontalAlignment: Text.Center
                            width: calibrationTextWidth
                        }
                        Label {
                            topPadding: 10
                            text: qsTr("collect point %1").arg("X")
                            horizontalAlignment: Text.Center
                            width: calibrationTextWidth
                        }
                        Label {
                            topPadding: 10
                            text: qsTr("collect point %1").arg("Y")
                            horizontalAlignment: Text.Center
                            width: calibrationTextWidth
                        }
                    }

                    delegate: caliDataDelegate
                    model: caliDataModel
                }

                Rectangle {
                    width: root.width
                    height: 2
                    color: "#9E9E9E"
//                    anchors.top: calibrationList.bottom
//                    anchors.topMargin: 5
                }

            }

        }
    }
    property real calibrationLabelWidth: 50
    property real calibrationTextWidth: 110
    Component {
        id: calibrationDataDelegate
        Row {
            spacing: 15
            Label {
                text: "" + index
                height: parent.implicitHeight
                width: calibrationTextWidth
                font.pixelSize: height
                horizontalAlignment: Text.left
                verticalAlignment: Text.Center
            }

            CaliTextEdit {
                width: calibrationTextWidth
                maxValue: maxX
                onTextChanged: targetX = text;
                value: targetX
            }
            CaliTextEdit {
                width: calibrationTextWidth
                maxValue: maxY
                onTextChanged: targetY = text;
                value: targetY
            }
            CaliTextEdit {
                width: calibrationTextWidth
                maxValue: maxX
                onTextChanged: collectX = text;
                value: collectX

            }
            CaliTextEdit {
                width: calibrationTextWidth
                maxValue: maxY
                onTextChanged: {
                    collectY = text;
                }
                value: collectY

            }



        }
    }
}
