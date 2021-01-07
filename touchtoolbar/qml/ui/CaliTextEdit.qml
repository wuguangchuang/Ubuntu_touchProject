import QtQuick 2.7
import QtQuick.Controls 2.0 as Cont2

Item {
    id: root
    property var maxValue: ""
    property var value: ""
    height: textField.implicitHeight
    signal textChanged(var text);
    Cont2.TextField {
        id: textField
        property bool showHint: false

        Cont2.Label {
            visible: parent.showHint
            text: maxValue
            anchors.bottom: parent.top
        }
        MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            onEntered: {
                parent.showHint = true;
            }
            onExited: parent.showHint = false;
            focus: false
            acceptedButtons: Qt.NoButton
        }

        Component.onCompleted: {
            root.height = textField.height
            text = value
        }
        width: root.width
        validator: RegExpValidator {
            regExp: /[0-9]+/
        }
        onActiveFocusChanged: {
            if (activeFocus === true)
                return;
            if (text === "") {
                text = "0";
                return;
            }
            if (parseInt(text) > maxValue) {
                text = "" + maxValue;
            }
            root.textChanged(text);
        }
    }
}
