import QtQuick 2.0

import QtQuick.Controls 2.0
import QtQuick.Controls.Styles 1.4
import QtQuick.Layouts 1.3

import QtGraphicalEffects 1.0

Item {
    id: dialogItem
    property var messageText: ""
    signal accpeted()
    visible: false;

    anchors.fill: parent
    PropertyAnimation { target: dialogItem; property: "opacity";
            duration: 400; from: 0; to: 1;
            id: showAnimation
            easing.type: Easing.InOutQuad ; running: false }
    PropertyAnimation { target: dialogItem; property: "opacity";
            duration: 400; from: 1; to: 0;
            id: closeAnimation;
            onStopped: {dialogItem.visible = false}
            easing.type: Easing.InOutQuad ; running: false }

//    Rectangle  {
//            anchors.fill: parent
//            id: overlay
//            color: "#000000"
//            opacity: 0.05
//            // add a mouse area so that clicks outside
//            // the dialog window will not do anything
//            MouseArea {
//                anchors.fill: parent
//            }
//        }
    property var backgroundColor: "#ffffff"
    property var titleColor: "#FF64B5F6"
    property real defaultMargin: 5
    property real minWidth: 400
    property string diglogTitleText: ""

    property bool showIcon: false
    /*
    QMessageBox::NoIcon	0	the message box does not have any icon.
    QMessageBox::Question	4	an icon indicating that the message is asking a question.
    QMessageBox::Information(success)	1	an icon indicating that the message is nothing out of the ordinary.
    QMessageBox::Warning	2	an icon indicating that the message is a warning, but can be dealt with.
    QMessageBox::Critical	3	an icon indicating that the message represents a critical problem.
    */
    property int iconType: 0

    property bool showAccpetButton: true
    property string defaultAcceptString: "确定"
    property string accpetString: defaultAcceptString
    property bool showCancelButton: true
    property string defaultCancelString: "取消"
    property string cancelString: defaultCancelString

    property var cancelFunction: undefined
    property var accpetFunction: undefined


    Rectangle {

        id: dialog
//        color: backgroundColor
        anchors.centerIn: parent
        width: dialogContent.width
        height: dialogContent.height + 2 * defaultMargin;



        ColumnLayout {
            id: dialogContent
            width: minWidth
            Rectangle {
                width: dialog.width
                height: dialogTitle.height
                border.width: 0
                color: titleColor
                anchors.right: parent.right
                anchors.left: parent.left
                anchors.leftMargin: 0
                anchors.rightMargin: 0
                Label {
                    font.pointSize: 13
                    padding: defaultMargin
                    id: dialogTitle
                    color: "#ffffff"
                    text: diglogTitleText
                }
                id: titleWrap
            }
            Image {
                id: messageIcon;
                visible: showIcon
                anchors.top: titleWrap.bottom
                anchors.topMargin: defaultMargin
                source: "qrc:/dialog/images/success.png";
                anchors.horizontalCenter: parent.horizontalCenter;
            }

            Rectangle {
                width: dialog.width
                //height: Math.max(dialogLabel.paintedHeight, 2 * font.pointSize)
                anchors.leftMargin: 0
                anchors.rightMargin: 0
                Layout.fillWidth: true
                anchors.left: parent.left
                anchors.right: parent.right
                id: messageWrap
                Label {
                    font.pointSize: 20
                    width: parent.width
                    //height: Math.max(dialogLabel.paintedHeight, 2 * font.pointSize)
                    padding: defaultMargin * 2
                    id: dialogLabel
                    wrapMode: "WrapAnywhere"
                    text: messageText
                    anchors.horizontalCenter: parent.horizontalCenter;
                    onTextChanged: {
                        parent.height = height;
                    }
                }
            }
            RowLayout {
                id: buttonLayout
                anchors.top: messageWrap.bottom
                anchors.topMargin: defaultMargin * 2
                spacing: defaultMargin
                anchors.left: parent.left
                anchors.leftMargin: 0
                anchors.rightMargin: defaultMargin
                anchors.right: parent.right
                Button {
                    id: cancelButton;
                    text: cancelString
                    visible: showCancelButton
                    onClicked: {
                        dialogItem.accpeted();
                        closeDialog();
                    }
                    Layout.fillWidth: true
                }
                Button {
                    Layout.fillWidth: true
                    id: accptButton;
                    text: accpetString
                    visible: showAccpetButton
                    onClicked: {
                        dialogItem.accpeted();
                        if (accpetFunction !== undefined) {
                            accpetFunction();
                        }

                        closeDialog();
                    }
                }
            }

        }


//        LinearGradient {
//            width: parent.width
//            anchors.top: parent.bottom
//            height: 2
//            end: Qt.point(0, 0)
//            start: Qt.point(0, height)
//            gradient: Gradient {

//                GradientStop{
//                    position: 0.0;
//                    color: "#BDBDBD";

//                }
//                GradientStop{
//                    position: 1.0;
//                    color: "#FFFFFF";
//                }
//            }
//        }
    }


    function closeDialog() {
        closeAnimation.start();
        dialogItem.destroy();
    }

    function showMessage(params) {
        if (params["title"] !== undefined) {
            diglogTitleText = params["title"];
        }

        if (params["icon"] !== undefined) {
            iconType = params["icon"];
            showIcon = true;
            switch (iconType) {
            case 1:
                messageIcon.source = "qrc:/dialog/images/success.png";
                break;
            case 3:
            case 2:
                messageIcon.source = "qrc:/dialog/images/error.png";
                break;
            case 4:
                messageIcon.source = "qrc:/dialog/images/noTouch.png";
                break;
            case 5:
                messageIcon.source = "qrc:/dialog/images/touch.png";
                break;
            default:
                showIcon = false;
                break;
            }
        } else {
            showIcon = false;
        }

        if (params["message"] !== undefined) {
            messageText = params["message"];
        }

        showCancelButton = true;
        if (params["cancelText"] !== undefined) {
            cancelString = params["cancelText"];
        }

        if (params["showCancel"] !== undefined) {
            showCancelButton = params["showCancel"];
        }

        cancelFunction = undefined;
        if (params["cancelFunction"] !== undefined) {
            cancelFunction = params["cancelFunction"];
        }

        showAccpetButton = true;
        if (params["accpetText"] !== undefined) {
            accpetString = params["accpetText"];
        }

        if (params["showAccpet"] !== undefined) {
            showAccpetButton = params["showAccpet"];
        }

        accpetFunction = undefined;
        if (params["accpetFunction"] !== undefined) {
            accpetFunction = params["accpetFunction"];
        }

        visible = true;
        showAnimation.start();
    }

}
