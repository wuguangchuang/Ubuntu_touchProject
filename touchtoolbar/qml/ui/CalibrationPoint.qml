import QtQuick 2.7

Item {
    id: canvas
    property real parentWidth: parent.width
    property real parentHeight: parent.height
    property color primaryColor: "black"
    property color secondaryColor: "black"
    property color unfinishedColor: "white"
    property color activeColor: "#00B0F0"
    property color finishedColor: "#00CC5B"
    property real primaryRadius: Math.max(parentWidth, parentHeight) / 16 / 2
    property real secondaryRadius: Math.max(parentWidth, parentHeight) / 32 / 2
    property real drawRadius: (primaryRadius - secondaryRadius) / 2 + secondaryRadius
    property real drawWidth: (primaryRadius - secondaryRadius) - lineWidth / 2
    property real centerWidth: width / 2;
    property real centerHeight: height / 2;


    property real minimumValue: 0
    property real maximumValue: 100
    property real currentValue: 0
    property real lastValue: 0
    property bool active: false;
    property bool dirty: false;
    property int index: -1;
    property bool finished: dirty === false && maximumValue > 0 && currentValue === maximumValue

//    onXChanged: dirty = true;
//    onYChanged: dirty = true;
    onActiveChanged: {
        dirty = false;
        drawCanvas.requestPaint();
    }

    onDirtyChanged: {
        if (dirty === true) {
            maximumValue = 0;
            currentValue = 0;
        }
        drawCanvas.requestPaint();
    }

    property real lineWidth: 3
    function reset() {
        currentValue = 0;
        minimumValue = 0;
        maximumValue = 0;
        lastValue = 0;
        active = false;
        dirty = false;
    }

    property real angle: (currentValue - minimumValue) /
                         ((maximumValue > 0 ? maximumValue : 100) - minimumValue) * 2 * Math.PI

    onMaximumValueChanged: drawCanvas.requestPaint()
    onCurrentValueChanged: drawCanvas.requestPaint()
    onWindowChanged: drawCanvas.requestPaint()

    property real angleOffset: -Math.PI / 2
    Canvas {
        id: drawCanvas
        anchors.fill: parent
        onPaint: {
            var ctx = drawCanvas.getContext("2d");
            ctx.reset();

            ctx.beginPath();
            ctx.lineWidth = lineWidth;
            ctx.strokeStyle = primaryColor;

            ctx.fillStyle = primaryColor;
            ctx.arc(canvas.centerWidth,
                    canvas.centerHeight,
                    primaryRadius,
                    0,
                    2*Math.PI);
            ctx.stroke();

            ctx.beginPath();
            ctx.lineWidth = lineWidth;
            ctx.strokeStyle = canvas.secondaryColor;

            ctx.arc(canvas.centerWidth,
                    canvas.centerHeight,
                    secondaryRadius,
                    0,
                    2*Math.PI);
            ctx.stroke();

//            console.log("draw:" + currentValue + "," + maximumValue + " " + active)
            if (active === false && (currentValue !== maximumValue || maximumValue === 0)) {
                ctx.beginPath();
                ctx.lineWidth = drawWidth;
                ctx.strokeStyle = unfinishedColor;

                ctx.arc(canvas.centerWidth,
                        canvas.centerHeight,
                        drawRadius,
                        0,
                        2*Math.PI);
                ctx.stroke();
            } else {
                ctx.beginPath();
                ctx.lineWidth = drawWidth;
                ctx.strokeStyle = activeColor;
                ctx.arc(canvas.centerWidth,
                        canvas.centerHeight,
                        drawRadius,
                        angleOffset + canvas.angle,
                        angleOffset + 2*Math.PI);
                ctx.stroke();

                ctx.beginPath();
                ctx.lineWidth = drawWidth;
                ctx.strokeStyle = finishedColor;
                ctx.arc(canvas.centerWidth,
                        canvas.centerHeight,
                        drawRadius,
                        canvas.angleOffset,
                        canvas.angleOffset + canvas.angle);
                ctx.stroke();
            }

            ctx.lineWidth = lineWidth;
            ctx.strokeStyle = primaryColor;
            ctx.beginPath();
            ctx.moveTo(0, centerHeight);
            ctx.lineTo(width, centerHeight);
            ctx.stroke();

            ctx.beginPath();
            ctx.moveTo(centerWidth, 0);
            ctx.lineTo(centerWidth, height);
            ctx.stroke();

        }
    }
}
