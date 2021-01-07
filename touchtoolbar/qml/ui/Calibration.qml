import QtQuick 2.7

import QtQuick.Window 2.2
import QtQuick.Controls 1.4
import QtQuick.Controls 2.0 as Cont2
import QtQuick.Controls.Styles 1.4
import QtQuick.Layouts 1.3

Item {
    id: root
//    anchors.fill: parent
    property real calDefRectWidth: root.width / 2
    property real calDefRectHeight: root.height / 2
    property real moveStep: 4

    property bool finished: false
    property var pointList: [point0, point1, point2, point3];
    property int activePoint: 0

    property color defaultRectColor: "#00000000"
    property color pressedRectColor: "#80000000"
    property color hoverRectColor: "#32000000"

    function setCalibrationData(index) {
        touch.debug("set calibration data: " + index)
        var point = pointList[index];
        var result = false;
        var data = {
            targetX: point.x + (point.width / 2),
            targetY: point.y + (point.height / 2),
            collectX: 0xffff,
            collectY: 0xffff,
            maxX: Screen.width,
            maxY: Screen.height
        }
        result = touch.setCalibrationPointData(index, data);
        point.dirty = false;
        return result;
    }

    function setPointActive(index) {
        autoExitTimer.restart();
        activePoint = index;
        for (var i = 0; i < pointList.length; i++) {
            pointList[i].active = false;
        }
        var point = pointList[activePoint];

        point.active = true;
        var result = setCalibrationData(activePoint);
        if (result === false) {
            showToast(qsTr("set calibration failure"));
            return false;
        }

        result = touch.captureCalibrationIndex(activePoint);
        if (result === false) {
            showToast(qsTr("Failed to start collection"));
            return false;
        }

        var data = touch.getCalibrationCapture();
        touch.debug(JSON.stringify(data));
        point.maximumValue = data.count;
        point.currentValue = data.finished;
        if (data.count > 0 && data.finished === data.count) {
            return true;
        }
        return true;
    }

    Menu {
        id: contentMenu

        MenuItem {
            text: qsTr("recalibration")
            onTriggered: {
                stopCaptureTimer();
                resizeWindow();
                root.forceActiveFocus();
                var point;
                for (var i = 0; i < 4; i++) {
                    var result = touch.captureCalibrationIndex(i);
                    point = pointList[i];
                    point.reset();
                    if (result === false) {
                        showToast(qsTr("recovery failed"));
                        return;
                    }
                }
                touch.captureCalibrationIndex(activePoint);
                setPointActive(0);
                startCaptureTimer();
            }
        }

        MenuItem {
            text: qsTr("exit")
            onTriggered: root.exit();
        }
    }

    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.AllButtons
        onClicked: {
            switch (mouse.button) {
            case Qt.LeftButton:
                var point = pointList[activePoint];
                if ((mouse.x > point.x && mouse.x < (point.x + point.width))
                    &&
                    (mouse.y > point.y && mouse.y < (point.y + point.height))) {
                    if (point.currentValue >= point.maximumValue) {
                        nextPointActive();
                    }

                    var data = touch.getCalibrationCapture();
                    touch.debug(JSON.stringify(data));

                }
                mouse.accepted = true;
                break;
            case Qt.RightButton:
                contentMenu.popup();
                mouse.accepted = true;
                break;
            }
//            console.log(""+mouse.x+","+mouse.y + "  " + point.x + "," + point.y
//                        + "[" + point.width + "," + point.height + "]");
        }
    }

    Timer{
        id: getCurrentCapture
        interval: 200
        repeat: true
        running: false
        triggeredOnStart: false
        onTriggered: {
            var data = touch.getCalibrationCapture();
//            touch.debug(JSON.stringify(data));
            var point = pointList[activePoint];
            point.active = true;
            point.maximumValue = data.count;
            point.currentValue = data.finished;
            if (root.finished === true) {
                return;
            }

            if (data.count > 0 && data.finished === data.count) {
                nextPointActive();
            }
        }
    }

    function nextPointActive() {
        activePoint++;
        if (activePoint >= pointList.length)
            activePoint = 0;
        var allFinished = true;
        var point;
        for (var i = 0; i < pointList.length; i++) {
            point = pointList[i];
            if (point.finished !== true) {
                allFinished = false;
                break;
            }
        }
        if (allFinished) {
            root.finished = true;
            return;
        }
        point = pointList[activePoint];
        if (point.finished) {
            nextPointActive();
            return;
        }

        setPointActive(activePoint);
    }

    function resizeWindow() {
        calRect.width = calDefRectWidth;
        calRect.height = calDefRectHeight;
        calRect.x = (root.width - calRect.width) / 2;
        calRect.y = (root.height - calRect.height) / 2;
    }

    property bool ready: false
    Component.onCompleted: {
        ready = true;
    }

    onVisibleChanged: {
        if (!ready) return;
        touch.debug((visible ? "enter" : "eixt") + " calibration");
        if (visible) {
            resizeWindow();
            autoExitTimer.restart();
            focus = true;
            // clear status
            finished = false;
            for (var i = 0; i < pointList.length; i++) {
                var point = pointList[i];
                point.reset();
            }
            var ret = touch.enterCalibrationMode();
            if (ret === false) {
                showToast(qsTr("Failed to enter calibration mode"));
                exitPanel();
                return;
            }
            setPointActive(0);
            getCurrentCapture.start();
            showToast(qsTr("Long press the blue circle to complete the calibration, Automatically exit after ") + (calAutoCancelTime/1000) + qsTr("seconds of inactivity"))
        } else {
            autoExitTimer.stop();
            touch.exitCalibrationMode();
            getCurrentCapture.stop();
        }
    }

    onFinishedChanged: {
        if (finished) {
            showToast(qsTr("Calibration is complete, press Esc to exit"));
            finishTimer.reset();
//            exitPanel();
            showProgessing();
            var result = touch.saveCalibration();
            if (result === false) {
                showToast(qsTr("Error saving data"));
            }

            var point;
            for (var i = 0; i < pointList.length; i++) {
                point = pointList[i];
                point.active = false;
            }
            point = pointList[activePoint];
            point.active = true;
            refreshCalibrationData();
            hideProgessing();
        }
    }

    Timer{
        id: finishTimer
//        interval: (calFinishExitTime ? calFinishExitTime : 3 * 1000)
        interval: 1 * 1000
        repeat: false
        running: false
        property int count: calFinishExitTime ? calFinishExitTime / 1000 : 3
        triggeredOnStart: false
        function reset() {
            count = calFinishExitTime ?  calFinishExitTime / 1000 : 3;
            restart()
            showToast( qsTr("Automatically exit after")+ count + qsTr("seconds"))
        }

        onTriggered: {
            count--
            if (count > 0) {
                showToast(qsTr("Automatically exit after")+ count + qsTr("seconds"))
                restart()
            } else {
                console.log("calibrate finish exit");
                exitPanel();
            }
        }
    }
    Timer{
        id: autoExitTimer
        interval: (calAutoCancelTime ? calAutoCancelTime : 60 * 1000)
        repeat: false
        running: false
        triggeredOnStart: false

        onTriggered: {
            exitPanel();
        }
    }

    function checkDirtyPoint() {
        var point = pointList[activePoint];
        if (point.dirty === true) {
            var result = touch.captureCalibrationIndex(activePoint);
            // Fixed ME: check in first XY change
//            if (result === false) {
//                showToast("开始采集失败");
//                return false;
//            }
        }
    }

    property real calPointRadius: 50
    Rectangle {
        id: fullRect
        anchors.fill: parent


        Rectangle {
            id: calRectLine
            width: calRect.width
            height: calRect.height
            border.width: 1
            border.color: "#a5a5a5"
            anchors.top: calRect.top
            anchors.left: calRect.left
        }
        CalibrationPoint {
            id: point0
            onDirtyChanged: {
                if (active && dirty) {
                    setCalibrationData(index);
                }
            }

            index: 0
            width: Math.max(root.width, root.height) / 12
            height: Math.max(root.width, root.height) / 12
            x: calRect.x - width / 2
            y: calRect.y - height / 2
        }
        CalibrationPoint {
            id: point1
            index: 1
            onDirtyChanged: {
                if (active && dirty) {
                    setCalibrationData(index);
                }
            }
            width: Math.max(root.width, root.height) / 12
            height: Math.max(root.width, root.height) / 12
            x: calRect.x + calRect.width - width / 2
            y: calRect.y - height / 2
        }

        CalibrationPoint {
            id: point2
            index: 2
            onDirtyChanged: {
                if (active && dirty) {
                    setCalibrationData(index);
                }
            }
            width: Math.max(root.width, root.height) / 12
            height: Math.max(root.width, root.height) / 12
            x: calRect.x - width / 2
            y: calRect.y + calRect.height - height / 2
        }

        CalibrationPoint {
            id: point3
            index: 3
            onDirtyChanged: {
                if (active && dirty) {
                    setCalibrationData(index);
                }
            }
            width: Math.max(root.width, root.height) / 12
            height: Math.max(root.width, root.height) / 12
            x: calRect.x + calRect.width - width / 2
            y: calRect.y + calRect.height - height / 2
        }

        Rectangle {
            id: calRect
            width: calDefRectWidth
            height: calDefRectHeight
            border.width: 1
            border.color: "#00a5a5a5"
            Component.onCompleted: {
                resizeWindow();
            }

//            onXChanged: checkDirtyPoint()
//            onYChanged: checkDirtyPoint()

            property bool hover: false

            color: (calMouseArea.pressed ? pressedRectColor : (calRect.hover ? hoverRectColor : defaultRectColor))
            MouseArea {
                id: calMouseArea
                drag.target: calRect
                drag.axis: Drag.XAndYAxis
                drag.minimumX: 0
                drag.maximumX: root.width - calRect.width
                drag.minimumY: 0
                drag.maximumY: root.height - calRect.height
                anchors.fill: parent
                hoverEnabled: true
                onExited: {
                    calRect.hover = false;
                }
                onEntered: {
                    calRect.hover = true;
                }
                onMouseXChanged: if (drag.active) setPointDirty()
                onMouseYChanged: if (drag.active) setPointDirty()
                function setPointDirty() {
                    point0.dirty = true;
                    point1.dirty = true;
                    point2.dirty = true;
                    point3.dirty = true;
                }
            }
        }

    }

    function addStepY() {
        calRect.y += moveStep;
        if (calRect.y > (root.parent.height - calRect.height))
            calRect.y = (root.parent.height - calRect.height);
    }
    function decStepY() {
        calRect.y -= moveStep;
        if (calRect.y < 0)
            calRect.y = 0;
    }

    function addStepX() {
        calRect.x += moveStep;
        if (calRect.x > (root.parent.width - calRect.width))
            calRect.x = (root.parent.width - calRect.width);
    }

    function decStepX() {
        calRect.x -= moveStep;
        if (calRect.x < 0)
            calRect.x = 0;
    }

    function onPressed(event) {
        var accepted = true;
        autoExitTimer.restart();
        switch (event.key) {
        case Qt.Key_Escape:
            exitPanel();
            break;
        case Qt.Key_Left:
            decStepX();
            break;
        case Qt.Key_Right:
            addStepX();
            break;
        case Qt.Key_Up:
            decStepY();
            break;
        case Qt.Key_Down:
            addStepY();
            break;

        case Qt.Key_H:
            calRect.height += moveStep;
            if (calRect.height + calRect.y > (root.parent.height)) {
                decStepY();
                calRect.height = root.parent.height - calRect.y;
            }
            break;
        case Qt.Key_L:
            calRect.height -= moveStep;
            if (calRect.height < 1)
                calRect.height = 1;
            break;
        case Qt.Key_W:
            calRect.width += moveStep;
            if (calRect.width + calRect.x > (root.parent.width)) {
                decStepX();
                calRect.width = root.parent.width - calRect.x;
            }
            break;
        case Qt.Key_N:
            calRect.width -= moveStep;
            if (calRect.width < 1)
                calRect.width = 1;
            break;

        case Qt.Key_Tab:
        case Qt.Key_T:
            event.accepted = accepted;
            stopCaptureTimer();
//            nextPointActive();
            var point = pointList[activePoint];
            point.active = false;
            console.log("last: " + point.lastValue)
            if (point.lastValue !== 0 && point.lastValue === point.maximumValue) {
                point.currentValue = point.lastValue;
            }
            var np = activePoint + 1;
            if (np >= pointList.length)
                np = 0;
            point = pointList[np];

//            console.log("on tab:" + np + " (" + activePoint +")")
            if (point.finished !== true) {
                nextPointActive();
                startCaptureTimer();
                return true;
            }
            point.lastValue = point.currentValue;

            activePoint = np;
            setCalibrationData(activePoint);
            touch.captureCalibrationIndex(activePoint);
            point.active = true;

//            setCalibrationData(np);
            startCaptureTimer();
            break;
        case Qt.Key_R:
            touch.testCaliCapture(5000);
            break;
        default:
            accepted = false;
            break;
        }
        event.accepted = accepted;
    }

//    Keys.onTabPressed: nextPointActive();

    Keys.onPressed: {
//        console.log("cal key pressed");
        onPressed(event);
    }
    Keys.enabled: true
    signal exit();
    function exitPanel() {
        exit();
    }

    function stopCaptureTimer() {
        getCurrentCapture.stop();
    }
    function startCaptureTimer() {
        getCurrentCapture.start();
    }

    property alias calRectX: calRect.x
    property alias calRectY: calRect.y
    property alias calRectWidth: calRect.width
    property alias calRectHeight: calRect.height
    Rectangle {
        id: leftLineRect
        width: Math.max(root.width, root.height) / 40
        height: calRect.height
        x: calRect.x - width / 2;
        y: calRect.y;
        property bool hover: false
        onXChanged: {
            var tx = x;
            var w = calRectX - tx;
            var tw = calRectX + calRectWidth;
            var xx = tx + width / 2;
            calRect.x = xx;
            calRect.width = tw - calRect.x;
        }

        color: (leftLineMouseArea.pressed ? pressedRectColor : (leftLineRect.hover ? hoverRectColor : defaultRectColor))
        MouseArea {
            id: leftLineMouseArea
            anchors.fill: parent
            hoverEnabled: true
            drag.target: leftLineRect
            drag.axis: Drag.XAxis
            drag.minimumX: 0 - width / 2
            drag.maximumX: calRect.x + calRect.width - width / 2
            onExited: {
                leftLineRect.hover = false;
            }
            onEntered: {
                leftLineRect.hover = true;
            }
            property bool change: false
            onReleased: {
                if (change && drag.active) setPointDirty()
                change = false;
            }

            onMouseXChanged: { change = true;}
            onMouseYChanged: { change = true;}
            function setPointDirty() {
                point0.dirty = true;
                point2.dirty = true;
            }
        }
    }

    Rectangle {
        id: rightLineRect
        width: Math.max(root.width, root.height) / 40
        height: calRect.height
        x: calRect.x + calRect.width - rightLineRect.width / 2;
        y: calRect.y;

        property bool hover: false
        onXChanged: {
            var tx = x;
            calRect.width = tx - calRect.x + rightLineRect.width / 2;
        }

        color: (rightLineMouseArea.pressed ? pressedRectColor : (rightLineRect.hover ? hoverRectColor : defaultRectColor))
        MouseArea {
            id: rightLineMouseArea
            anchors.fill: parent
            hoverEnabled: true
            drag.target: rightLineRect
            drag.axis: Drag.XAxis
            drag.minimumX: calRect.x - width / 2
            drag.maximumX: root.width - width / 2
            onExited: {
                rightLineRect.hover = false;
            }
            onEntered: {
                rightLineRect.hover = true;
            }
            property bool change: false
            onReleased: {
                if (change && drag.active) setPointDirty()
                change = false;
            }

            onMouseXChanged: { change = true;}
            onMouseYChanged: { change = true;}
            function setPointDirty() {
                point1.dirty = true;
                point3.dirty = true;
            }
        }
    }

    Rectangle {
        id: upLineRect
        height: Math.max(root.width, root.height) / 40
        width: calRect.width

        x: calRect.x;
        y: calRect.y - upLineRect.height / 2;

        property bool hover: false
        onYChanged: {
            var ty = y;
            var h = calRectY - ty;
            var th = calRectY + calRectHeight;
            var yy = ty + height / 2;
            calRect.y = yy;
            calRect.height = th - calRect.y;
        }

        color: (upLineMouseArea.pressed ? pressedRectColor : (upLineRect.hover ? hoverRectColor : defaultRectColor))
        MouseArea {
            id: upLineMouseArea
            anchors.fill: parent
            hoverEnabled: true
            drag.target: upLineRect
            drag.axis: Drag.YAxis
            drag.minimumY: 0 - upLineRect.height / 2
            drag.maximumY: calRect.y + calRect.height - height / 2
            onExited: {
                upLineRect.hover = false;
            }
            onEntered: {
                upLineRect.hover = true;
            }
            property bool change: false
            onReleased: {
                if (change && drag.active) setPointDirty()
                change = false;
            }

            onMouseXChanged: { change = true;}
            onMouseYChanged: { change = true;}
            function setPointDirty() {
                point0.dirty = true;
                point1.dirty = true;
            }
        }
    }


    Rectangle {
        id: downLineRect
        height: Math.max(root.width, root.height) / 40
        width: calRect.width
        x: calRect.x;
        y: calRect.y + calRect.height - downLineRect.height / 2;

        property bool hover: false
        onYChanged: {
            var ty = y;
            calRect.height = ty - calRectY + downLineRect.height / 2;
        }


        color: (downLineMouseArea.pressed ? pressedRectColor : (downLineRect.hover ? hoverRectColor : defaultRectColor))
        MouseArea {
            id: downLineMouseArea
            anchors.fill: parent
            hoverEnabled: true
            drag.target: downLineRect
            drag.axis: Drag.YAxis
            drag.minimumY: calRectY - height / 2
            drag.maximumY: root.height - height / 2

            onExited: {
                downLineRect.hover = false;
            }
            onEntered: {
                downLineRect.hover = true;
            }
            property bool change: false
            onReleased: {
                if (change && drag.active) setPointDirty()
                change = false;
            }

            onMouseXChanged: { change = true;}
            onMouseYChanged: { change = true;}
            function setPointDirty() {
                point2.dirty = true;
                point3.dirty = true;
            }
        }
    }
}
