import QtQuick 2.5

ListModel {
    property int count: 20
    Component.onCompleted: loadDatas()
    function loadDatas() {
        for (var i = 0; i < count; i++) {
            append({"number" : i, "deviceStatus": 0, "time" : 0, "info": ""});
        }
    }
}

