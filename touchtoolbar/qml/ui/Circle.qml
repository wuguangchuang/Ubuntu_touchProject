import QtQuick 2.0

Item {
    id: thisRoot
    property color color: "#ff0000"
    opacity: 0.5
    Rectangle{

        id: cir1
        width: thisRoot.width
        height: thisRoot.height
        radius: width/2
        color: thisRoot.color

//        Rectangle{
//            anchors.verticalCenter: parent.verticalCenter
//            height: parent.height/3
//            width: parent.width
//            clip: true
//            Rectangle{
//                width: thisRoot.width;
//                height:thisRoot.height
//                radius: width/2
//                anchors.centerIn: parent
//                color: thisRoot.color
//            }
//        }
    }
}
