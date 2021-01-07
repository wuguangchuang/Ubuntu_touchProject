import QtQuick 2.7

import QtQuick.Controls 2.0
import QtQuick.Layouts 1.3
Row {

    id: root
    property alias color: colorPicker.color
    property alias index: indexLabel.text
    signal removed();
    signal itemClick();
    spacing: 10
    Row {
        spacing: 10
        Label {
            id: indexLabel
            height: removedButton.height
            width: font.pixelSize * 3
            text: "0"
            verticalAlignment: Text.AlignVCenter
        }
        Button {
            id: removedButton
            padding: 5
            text: "-"
            width: height
            onClicked: {
                removed();
            }
        }
    }

    TextField {
        id: colorText
        padding: 10
        text: root.color
        width: 100
        validator: RegExpValidator {
            regExp: /#[0-9A-Fa-f]+/
        }
//        readOnly: true
        maximumLength: 7
        onFocusChanged: {
            if (focus === true)
                return;
            if (text === "") {
                text = "#";
                return;
            }
            var v = text.toUpperCase();
            color = v;
            colorPicker.color = v;
            colorPicker.colorChanged(colorPicker.color);
        }
        Keys.onReleased: {
            if (event.key === Qt.Key_Return) {
                focus = false;
            }
        }

    }

    ColorPicker {
        id: colorPicker
        showHeight: colorText.height
        color: "#ff0000"
        onColorSelected: {
            colorText.text = (""+color).toUpperCase();
        }
    }
    Connections {
        target: colorPicker
        onItemClick: itemClick();
    }

}
