import QtQuick 2.7

import QtQuick.Controls 1.4
import QtQuick.Controls 2.0 as Cont2
import QtQuick.Controls.Styles 1.4
import QtQuick.Layouts 1.3

Item {
    property var point1Record: []
    property int pindex: 0
    property int prindex: 0

    property var pointCircles: []

    property color bgColor: "#ffffff"
    property bool repaintAll: false

    property real flagSize: 18

    property int defaultCurrentPointDiameter: 30
    property real defaultCurrentPointOpacity: 50
    property int defaultLineWidth: 1
    property bool defaultPaintFlag: false
    property bool defaultShowCurrentPoint: true
    property bool defaultShowPath: true

    property var defaultPointColors: [
        "F44336",
        "9C27B0",
        "2196F3",
        "00BCD4",
        "009688",
        "4CAF50",
        "827717",
        "FF9800",
        "795548",
        "607D8B"
    ]

    property int currentPointDiameter: touch.getSettingsValue("currentPointDiameter") === undefined ?
                                           defaultCurrentPointDiameter : touch.getSettingsValue("currentPointDiameter")
    property real currentPointOpacity: touch.getSettingsValue("currentPointOpacity") === undefined ?
                                           defaultCurrentPointOpacity : touch.getSettingsValue("currentPointOpacity")
    property int lineWidth: touch.getSettingsValue("lineWidth") === undefined ?
                                defaultLineWidth : touch.getSettingsValue("lineWidth")
    property bool paintFlag: touch.getSettingsBool("paintFlag") === undefined ?
                                 defaultPaintFlag : touch.getSettingsBool("paintFlag")
    property bool showCurrentPoint: touch.getSettingsBool("showCurrentPoint") === undefined ?
                                 defaultShowCurrentPoint : touch.getSettingsBool("showCurrentPoint")
    property bool showPath: touch.getSettingsBool("showPath") === undefined ?
                                defaultShowPath : touch.getSettingsBool("showPath")

    property var pointColors: touch.getSettingsValue("pointColors") === undefined ?
                                  defaultPointColors : touch.getSettingsValue("pointColors")

    property var fingers: []
    property var fingerPoints: []

    id: root;
    Rectangle {
        Component.onCompleted: {
        }

        id: panelRoot
        anchors.fill: parent
        color: bgColor
        MultiPointTouchArea {
            id: touchArea
            anchors.fill: parent
            onUpdated: {
                for (var index = 0; index < touchPoints.length; index++) {
                    var point = touchPoints[index];
                    var pointId = point.pointId
                    if (point === undefined || point === null) {
                        continue;
                    }
                    //                console.log("update:" + point.x + "  " + point.y + "   " + point.pressed);
                    var finger = fingers[pointId];
                    var lastPoint = finger.points[finger.points.length - 1];
                    var curIndex = 0;
                    if (lastPoint !== undefined && lastPoint !== null) {
                        curIndex = lastPoint.index + 1;
                    }
                    var newPoint = {"x": point.x, "y": point.y,
                        "pressed": point.pressed,
                        "index": curIndex};
                    finger.points.push(newPoint)
                    drawCanvas.requestPaint();
                }
            }

            onPressed: {
                for (var index = 0; index < touchPoints.length; index++) {
                    var point = touchPoints[index]
                    var pointId = point.pointId
                    if (showCurrentPoint) {
                        var cir = Qt.createComponent("qrc:qml/ui/Circle.qml");
                        var co = pointColors[pointId % pointColors.length]
                        cir = cir.createObject(panelRoot, {
                                                   "width": currentPointDiameter,
                                                   "height": currentPointDiameter,
                                                   "x": point.x - currentPointDiameter / 2,
                                                   "y": point.y - currentPointDiameter / 2,
                                                   "color": "#" + co,
                                                   "opacity": currentPointOpacity / 100
                                               });
                        pointCircles[pointId] = cir;
                    } else {
                        pointCircles[pointId] = null;
                    }
                    for (var i = 0; i <= pointId; i++) {
                        var finger = fingers[i];
                        if (finger === undefined || finger === null) {
                            fingers[i] = {
                                "points": [],
                                "rindex": 0,
                                "id": i
                            }
                        }
                    }
                }
            }

            onReleased: {
                for (var index = 0; index < touchPoints.length; index++) {
                    var point = touchPoints[index];
                    var pointId = point.pointId
                    if (point === undefined)
                        continue;
                    var finger = fingers[pointId];
                    var lastPoint = finger.points[finger.points.length - 1];

                    var cir = pointCircles[pointId];
                    if (cir !== undefined && cir !== null)
                        cir.destroy();
                    var newPoint = {"x": point.x, "y": point.y, "pressed": point.pressed,
                        "index": -1};
                    finger.points.push(newPoint)
                    drawCanvas.requestPaint();
                }
            }

            Canvas {
                id: drawCanvas
                anchors.fill: parent
                onPaint: {
                    var ctx = drawCanvas.getContext("2d");

                    var finger;
                    var index;
                    if (repaintAll) {
                        ctx.reset();
                        for (index = 0; index < fingers.length; index++) {
                            finger = fingers[index];
                            if (finger !== undefined && finger !== null) {
                                finger.rindex = 0;
                            }
                        }
                    }

                    for (index = 0; index < fingers.length; index++) {
                        finger = fingers[index];
                        if (finger === undefined || finger === null)
                            continue;
                        var pointId = finger.id;
                        ctx.fillStyle = "#" + pointColors[pointId % pointColors.length];
                        ctx.strokeStyle = "#" + pointColors[pointId % pointColors.length];
                        ctx.lineWidth = lineWidth;
                        var fontSize = flagSize + (lineWidth * 3)
                        ctx.font = "normal " + fontSize + "px 'Arial'";


                        for (;finger.rindex < finger.points.length; finger.rindex++) {
                            var prindex = finger.rindex;
                            var curPoint = finger.points[prindex];
                            var lastPoint = finger.points[prindex - 1];

                            var cir1 = pointCircles[pointId];
                            if (cir1 !== undefined && cir1 !== null) {
                                cir1.x = curPoint.x - (cir1.width / 2);
                                cir1.y = curPoint.y - (cir1.height / 2);
                            }
                            if (showPath) {
                                ctx.beginPath();

                                if (lastPoint !== undefined && lastPoint.pressed === true) {
                                    ctx.moveTo(lastPoint.x, lastPoint.y);
                                }


                                ctx.lineTo(curPoint.x, curPoint.y);
                                ctx.stroke();
                                ctx.closePath();
                            }
                            if (paintFlag) {
                                var flag = "□";
                                if (lastPoint !== undefined && lastPoint.pressed === true) {
                                    if (curPoint.index % 2 === 1)
                                        flag = "+";
                                    else
                                        flag = "x";
                                }
                                if (lastPoint !== undefined && lastPoint.pressed === false) {
                                    flag = "□";
                                }
                                if (curPoint.pressed === false) {
                                    flag = "△";
                                }
                                var twidth = ctx.measureText(flag).width
                                ctx.fillText(flag, curPoint.x - (twidth / 2), curPoint.y + (fontSize / 4));
                            }

                            //ctx.arc(curPoint.x, curPoint.y, 3, 0, Math.PI*2, true);
                            //ctx.fill();
                        }
                    }


                    if (repaintAll) {
                        repaintAll = false;
                        //focus = true;
                    }
                    //                    ctx.closePath();
                }
            }
        }

    }



    focus: visible

    function repaintPath() {
        repaintAll = true;
        drawCanvas.requestPaint();
    }

    function setPaintFlag(flag) {
        paintFlag = flag;
        repaintPath();
    }

    Cont2.Popup {
        id: popup
        padding: 0
        Column {
            spacing: 0
            Cont2.Button {
                text: "清除(C)"
                onClicked: {
                    popup.close();
                    clearPanel();
                }
            }
            Cont2.Button {
                text: "退出(Esc)"
                onClicked: {
                    popup.close();
                    exitPanel();
                }
            }
            Cont2.Button {
                text: "设置(S)"
                onClicked: {
                    settingsInAnimation.start();
                    popup.close();
                }
            }
        }
    }
    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.RightButton
        onClicked: {
            popup.x = mouse.x
            popup.y = mouse.y
            popup.open();
        }
    }

    signal exit();
    function exitPanel() {
        exit();
//        visible = false;
    }

    Keys.onReleased: {
        if (visible) {
            switch (event.key) {
            case Qt.Key_Escape:
                exitPanel();
                break;
            case Qt.Key_O:
                popup.open();
                break;
            case Qt.Key_F:
                setPaintFlag(!paintFlag);
                break;
            case Qt.Key_P:
                showCurrentPoint = !showCurrentPoint;
                break;
            case Qt.Key_S:
                if (settingsView.visible === false) {
                    settingsInAnimation.start();
                } else {
                    closeSettings();
                }

                break;
            case Qt.Key_C:
                clearPanel();
                break;
            }
        }
    }
    function clearPanel() {
        for (var index = 0; index < fingers.length; index++) {
            var finger = fingers[index];
            pointCircles[finger.id] = null;
            if (finger !== undefined && finger !== null) {
                finger.rindex = 0;
                finger.points = [];
            }
        }
        repaintAll = true;
        drawCanvas.requestPaint();
    }

    property real defaultSpacing: 15
    NumberAnimation {
        id: settingsInAnimation
        target: settingsRectangle
        properties: "x"
        from: -panelRoot.width
        to: 0
        easing {type: Easing.OutExpo; overshoot: 500}
        onStarted: {
            settingsView.visible = true;
        }
    }
    NumberAnimation {
        id: settingsOutAnimation
        target: settingsRectangle
        properties: "x"
        to: -panelRoot.width
        from: 0
        easing {type: Easing.InExpo; overshoot: 500}
        onStopped: {
            settingsView.visible = false;
        }
    }
    ScrollView {
        id: settingsView
        //        height: parent.height
        //        width: parent.width / 2
        anchors.fill: parent

        Rectangle {
            id: settingsRectangle
            height: panelRoot.height
            width: panelRoot.width / 2
            color: "#ffffff"
            Column {
                id: settingsColumn
                padding: 20
                anchors.top: parent.top
                anchors.topMargin: defaultSpacing * 2
                spacing: defaultSpacing
                width: panelRoot.width / 2
                Row {
                    spacing: defaultSpacing
                    CheckBox {
                        id: showPathCheckBox
                        checked: showPath
                        onCheckedChanged: {
                            var v = checked;
                            showPath = v;
                            repaintPath();
                        }
                    }
                    Cont2.Label {
                        text: qsTr("show path")
                        font.bold: true
                    }

                }
                Row {
                    spacing: defaultSpacing
                    Cont2.Label {
                        text: qsTr("path width")
                        anchors.bottom: lineWidthTextField.bottom
                    }
                    TextField {
                        id: lineWidthTextField
                        text: lineWidth
                        width: 50
                        validator: RegExpValidator {
                            regExp: /[0-9]+/
                        }
                        maximumLength: 2
                        onTextChanged: {
                            if (text === "")
                                return;
                            var v = parseInt(text)
                            if (v <= 0)
                                v = 1;
                            text = v;
                            lineWidth = v;
                            repaintPath();
                        }
                        anchors.bottom: parent.bottom
                    }
                    Rectangle {
                        anchors.top: parent.top
                        anchors.topMargin: 2
                        height: lineWidth
                        width: 50;
                        color: "#000000"
                    }

                    visible: showPathCheckBox.checked
                }

                Rectangle {
                    width: settingsColumn.width
                    height: 2
                    color: "#9E9E9E"
                }

                Row {
                    spacing: defaultSpacing
                    CheckBox {
                        id: showPointCircleCheckBox
                        checked: showCurrentPoint
                        onCheckedChanged: {
                            showCurrentPoint = checked;
                        }
                    }
                    Cont2.Label {
                        text: qsTr("show local point")
                        font.bold: true
                    }
                }
                Row {
                    topPadding: 10
                    spacing: defaultSpacing
                    Cont2.Label {
                        text: qsTr("point width")
                    }
                    TextField {
                        text: currentPointDiameter
                        width: 50
                        validator: RegExpValidator {
                            regExp: /[0-9]+/
                        }
                        maximumLength: 2
                        onTextChanged: {
                            if (text === "")
                                return;
                            var v = parseInt(text)
                            if (v <= 0)
                                v = 1;
                            text = v;
                            currentPointDiameter = v;
                        }
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 10
                    }


                    Cont2.Label {
                        text: qsTr("alpha of point")
                    }

                    TextField {
                        text: currentPointOpacity
                        width: 50
                        validator: RegExpValidator {
                            regExp: /[0-9]+/
                        }
                        maximumLength: 2
                        onTextChanged: {
                            if (text === "")
                                return;
                            var v = parseInt(text)
                            if (v <= 0)
                                v = 1;
                            text = v;
                            currentPointOpacity = v;
                        }
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 10
                    }

                    visible: showCurrentPoint
                }
                Row {

                    Circle {
                        width: currentPointDiameter
                        height: currentPointDiameter
                        color: "red"
                        opacity: currentPointOpacity / 100
                    }
                    spacing: defaultSpacing
                    visible: showCurrentPoint
                }

                Rectangle {
                    width: settingsColumn.width
                    height: 2
                    color: "#9E9E9E"
                }

                Row {
                    spacing: defaultSpacing
                    CheckBox {
                        checked: paintFlag
                        onCheckedChanged: {
                            setPaintFlag(checked);
                        }
                    }
                    Cont2.Label {
                        text: qsTr("show flag")
                        font.bold: true
                    }

                }

                Rectangle {
                    width: settingsColumn.width
                    height: 2
                    color: "#9E9E9E"
                }
//                Row {
//                    width: settingsColumn.width
//                    Column {
//                        padding: 1
//                        spacing: 10
//                        id: colorPickers
//                        ColorPickerItem {
//                            color: "#ff0000"
//                        }

//                        ColorPickerItem {
//                            color: "#ffff00"
//                        }
//                    }
//                }
                Rectangle {
                    width: settingsColumn.width
                    height: 500 + pointAddButton.height + pointAddButton.bottomPadding

                    Row {
                        id: pointAddRow
                        Cont2.Label {
                            text: qsTr("add point color")
                            verticalAlignment: Text.AlignVCenter

                            height: pointAddButton.height
                        }

                        Cont2.Button {
                            id: pointAddButton
                            text: "+"
                            width: 50
                            height: width
                            onClicked: {
                                colorPickerModel.append({"mColor": "ff0000", "mIndex": colorPickerModel.count + 1})
                                colorPickerListView.positionViewAtEnd();
                            }
                        }
                        bottomPadding: 10
                    }
                    ListView {
                        width: parent.width
                        anchors.top: pointAddRow.bottom
                        anchors.topMargin: 0
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 0
                        clip: true

                        height: parent.height - anchors.topMargin - anchors.bottomMargin
                        spacing: 10
                        id: colorPickerListView
                        model: ListModel {
                            id: colorPickerModel
                            Component.onCompleted: {
                                for (var i = 0; i < pointColors.length; i++) {
                                    append({"mColor": pointColors[i], "mIndex": i + 1});
                                }
                            }
                        }
                        delegate: Component {
                            ColorPickerItem {
                                color: "#" + mColor
                                index: mIndex
                                onRemoved: {
                                    colorPickerModel.remove(mIndex - 1);
                                    for (var i = 0; i < colorPickerModel.count; i++) {
                                        colorPickerModel.get(i).mIndex = i + 1;
                                    }
                                }
                                onItemClick: {
                                    var index = mIndex - 1;
                                    colorPickerListView.currentIndex = index
                                    console.log("show")
                                }

                                onColorChanged: {
                                    var v = "" + color;
                                    color = v;
                                    if (colorPickerModel.get(index - 1) === undefined)
                                        return;
                                    colorPickerModel.get(index - 1).mColor = v.slice(1, v.length);
                                }
                            }
                        }
                    }
                }

                Row {
                    id: buttonLayout
                    topPadding: defaultSpacing
                    spacing: defaultSpacing
                    Cont2.Button {
                        id: cancelButton;
                        text: qsTr("close")
                        onClicked: {
                            closeSettings();
                        }
                        Layout.fillWidth: true
                    }
                    Cont2.Button {
                        text: qsTr("reset all settings")
                        onClicked: {
                            resetSettings();
                            saveSettings();
                            colorPickerModel.clear();
                            for (var i = 0; i < pointColors.length; i++) {
                                colorPickerModel.append({"mColor": pointColors[i], "mIndex": i + 1});
                            }
                            repaintPath();
                        }
                        Layout.fillWidth: true
                    }
                }
            }
        }
        anchors.centerIn: parent
        visible: false
    }

    function closeSettings() {
        settingsOutAnimation.start();
        pointColors = [];
        for (var i = 0; i < colorPickerModel.count; i++) {
            var info = colorPickerModel.get(i).mColor;
            pointColors[i] = info;
        }
        saveSettings();
        repaintPath();
    }

    function resetSettings() {
        currentPointDiameter = defaultCurrentPointDiameter;
        currentPointOpacity = defaultCurrentPointOpacity;
        lineWidth = defaultLineWidth;
        paintFlag = defaultPaintFlag;
        showCurrentPoint = defaultShowCurrentPoint;
        showPath = defaultShowPath;
        pointColors = defaultPointColors;

    }

    function saveSettings() {
        touch.setSettingsValue("currentPointDiameter", currentPointDiameter);
        touch.setSettingsValue("currentPointOpacity", currentPointOpacity);
        touch.setSettingsValue("lineWidth",lineWidth);
        touch.setSettingsValue("paintFlag", paintFlag);
        touch.setSettingsValue("showCurrentPoint", showCurrentPoint);
        touch.setSettingsValue("showPath", showPath);
        touch.setSettingsValue("pointColors", pointColors);

    }
}
