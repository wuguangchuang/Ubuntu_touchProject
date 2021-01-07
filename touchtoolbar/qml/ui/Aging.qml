import QtQuick 2.5
import QtQuick.Window 2.2

import QtQuick.Dialogs 1.1
import "qrc:/"
import "qrc:/qml/ui/"

Item {
    property int deviceCount: 40
    property int columns: 8
    property int rows: 5
    property int itemWidth: width / columns
    property int itemHeigth: height / rows
    property int passAgingTime: 10
    visible: true

    function getDeviceCount() {
        return deviceCount;
    }

    function setDeviceStatus(dev, status) {
        deviceModel.get(dev).deviceStatus = status;
    }

    signal agingFinished(int index);

    /**
      * deviceStatus:
      * 0: default, no device
      * 1: connected
      * 2: disconnected
      * 3: error
      * 4: finished
      */
    property int deviceNc: 0
    property int deviceConnected: 1
    property int deviceDisconnected: 2
    property int deviceError: 3
    property int deviceFinished: 4

    property int defaultMargin: 10
    property var timeFlag : [];

    Component {
        id: deviceDelegate;
        Item {
            id: deviceItem
//            property color cNc: "#263238"
//            property color cConnected: "#64DD17"
//            property color cDisconnected: "#FDD835"
//            property color cError: "#FF3D00"
//            property color cFinished: "#FFFFFF"
            property color cNc: "#FF3D00"
            property color cConnected: "#FF3D00"
            property color cDisconnected: "#FF3D00"
            property color cError: "#FF3D00"
            property color cFinished: "#64DD17"

            property var hour : parseInt(passAgingTime / (60 * 60))
            property var minute : parseInt((passAgingTime - (60 * 60 * hour)) / 60)
            property int second : passAgingTime % 60
            property var totalTime : prefixInteger(hour, 2) + ":" + prefixInteger(minute,2) + ":" + prefixInteger(second,2)
        Rectangle {
            width: itemWidth
            height: itemHeigth
            color: "#272822"
            border.width: 1
            border.color: "#007F00"

            Column {
                anchors.left: parent.left
                anchors.leftMargin: defaultMargin
                anchors.rightMargin: defaultMargin
                Text {
                    font.pixelSize: itemWidth / 12
                    text: "#" + number + "# " +
                          (deviceStatus === deviceConnected ? qsTr("accelerated aging") :
                                                    (deviceStatus == deviceDisconnected ?  qsTr("disconnected") :
                                                    (deviceStatus == deviceError ? qsTr("device error") :
                                                    (deviceStatus == deviceFinished ? qsTr("aging completed") : ""))))
                    color: deviceStatus == deviceConnected ? cConnected :
                          (deviceStatus == deviceDisconnected ?  cDisconnected :
                          (deviceStatus == deviceError ? cError :
                          (deviceStatus == deviceFinished ? cFinished : cNc)))
                }
                Text{
                    font.pixelSize: itemWidth / 12
                    text:((deviceStatus === deviceConnected || deviceStatus === deviceFinished)? (qsTr("total time:") + totalTime):" ")
                    color: "red"
                }
                Text {
                    font.pointSize: itemWidth / 10
                    text: info
                    color: deviceStatus == deviceConnected ? cConnected :
                          (deviceStatus == deviceDisconnected ?  cDisconnected :
                          (deviceStatus == deviceError ? cError :
                          (deviceStatus == deviceFinished ? cFinished : cNc)))
                }

            }
        }
        }
    }
    Item {
        anchors.fill: parent
        GridView {
            anchors.fill: parent
            cellWidth: itemWidth
            cellHeight: itemHeigth
            model: DeviceModel {
                id: deviceModel
                count: deviceCount
            }
            delegate: deviceDelegate

        }

    }
    function startAging() {
        countdown.start();
        console.log("start aging")
    }

    function stopAging() {
        console.log("stop aging, clear models");
//        timeFlag = true;
        countdown.stop();
        for (var i = 0; i < deviceCount; i++) {
            var model = deviceModel.get(i);
            model.time = 0;
            model.deviceStatus = deviceNc;
            model.info = "";
        }
    }

    Timer{
        id:countdown
        interval: 1000
        repeat: true
        running: false
        triggeredOnStart: false
        onTriggered: {
//            console.log("time triggered")
            var model;

            for (var i = 0; i < deviceCount; i++) {
                model = deviceModel.get(i);

                //console.log("#" + i + " status: " + model.deviceStatus + " time: " + model.time)
                if (model && model.deviceStatus === deviceConnected) {
                    if(timeFlag[i])
                    {
                        model.time = passAgingTime;

                        timeFlag[i] = false;
                    }
                    else
                    {
                        if(model.time === 0)
                            continue;
                        model.time -= 1;
                    }


                    var hour = parseInt(model.time / (60 * 60));
                    var minute = parseInt((model.time - (60 * 60 * hour)) / 60);
                    var second = model.time % 60;
                    model.info = prefixInteger(hour, 2) + ":" + prefixInteger(minute,2) + ":" + prefixInteger(second,2);
//                    console.log(hour + ":" + minute + ":" + second + " pass:" + passAgingTime);
                    if (model.time <= 0) {
                        model.deviceStatus = deviceFinished;
                        agingFinished(i);
                        timeFlag[i] = false;
                    }
                }
            }
        }
    }
    function prefixInteger(num, n) {
        return (new Array(n).join(0) + num).slice(-n);
    }

}
