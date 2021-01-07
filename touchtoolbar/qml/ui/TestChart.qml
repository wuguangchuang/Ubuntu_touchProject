import QtQuick 2.7
import QtQuick.Controls 2.0
import QtQuick.Controls 1.4 as Cont1

import QtQuick.Layouts 1.3
import TouchPresenter 1.0


import "qrc:/qml/jbQuick/Charts/SignalChart.js" as Charts

import "qrc:/"

Item {
    visible: false
    id: testChart

    property var normalColor: "#64B5F6"
    property var selectedColor: "#00BCD4"

    property var fontSize: 12;
    property var testInfo: []
    property var testItems: []
    property var signalIndexs: []
    property var signalDatas: []
    property string chartInfo: qsTr("standard range")
    property int currentSignalIndex: 0
    property int scrollHeight: height - 100 - itemHeight
    property int scrollWidth: width - 150
    property real chartScaleX: 1
    property real chartScaleY: 1
    property real maxScale: 10
    property real minScale: 1
    property real chartScaleStep: 0.2
    property real chartDefaultWidth: (scrollWidth - Charts.config.startX)
    property real chartWidth: (chartDefaultWidth) * chartScaleX
    property var standards
    property var items
    property int saveLastTestItemCount

    property string signalImageYes:"qrc:/dialog/images/success.png"
    property string signalImageNo:"qrc:/dialog/images/error.png"
    property var signalResult:[]


    property bool dataDirty: false

    property bool stopRefresh: false

    property Item rtext:testItemBoxView.rtext
    property int itemWidth:Math.min(Math.max(120,signalItemWidth * 120),400)
    property int itemHeight:Math.min(Math.max(40,signalItemHeight * 40),130) - 40


    property var signalColors: [
        "#355F6D",
        "#2962FF",
        "#BDDD4F",
        "#765728",
        "#311B92",
        "#B388FF",
        "#1B5E20",
        "#479500"
    ];
    property var errorSignalColors: "#FF0000"
    property int maxSignal: signalColors.length;
    property var testNames: [
        "ADC_X_TB",
        "ADC_Y_TB",
        "ADC_X_TM",
        "ADC_Y_TM",
        "ADC_X_TF",
        "ADC_Y_TF",
        "ORG_X_TB",
        "ORG_Y_TB",
        "ORG_X_TM",
        "ORG_Y_TM",
        "ORG_X_TF",
        "ORG_Y_TF",
        "RAT_X_TB",
        "RAT_Y_TB",
        "RAT_X_TM",
        "RAT_Y_TM",
        "RAT_X_TF",
        "RAT_Y_TF",
        "TAGC_X_TB",
        "TAGC_Y_TB",
        "TAGC_X_TM",
        "TAGC_Y_TM",
        "TAGC_X_TF",
        "TAGC_Y_TF",
        "UNT_X_TB",
        "UNT_Y_TB",
        "UNT_X_TM",
        "UNT_Y_TM",
        "UNT_X_TF",
        "UNT_Y_TF",
        "RVR_X_TB",
        "RVR_Y_TB",
        "RVR_X_TM",
        "RVR_Y_TM",
        "RVR_X_TF",
        "RVR_Y_TF",
        "ADC_X_TB_ALL",
        "ADC_Y_TB_ALL",
        "ADC_X_TM_ALL",
        "ADC_Y_TM_ALL",
        "ADC_X_TF_ALL",
        "ADC_Y_TF_ALL",
        "ORG_X_TB_ALL",
        "ORG_Y_TB_ALL",
        "ORG_X_TM_ALL",
        "ORG_Y_TM_ALL",
        "ORG_X_TF_ALL",
        "ORG_Y_TF_ALL",
        "RAT_X_TB_ALL",
        "RAT_Y_TB_ALL",
        "RAT_X_TM_ALL",
        "RAT_Y_TM_ALL",
        "RAT_X_TF_ALL",
        "RAT_Y_TF_ALL",
        "AGC_X_TB_ALL",
        "AGC_Y_TB_ALL",
        "AGC_X_TM_ALL",
        "AGC_Y_TM_ALL",
        "AGC_X_TF_ALL",
        "AGC_Y_TF_ALL",
        "",
        "",
        "RSTA_X_TM",
        "RSTA_Y_TM",
        "",
        "",
        "RUNT_X_TB",
        "RUNT_Y_TB",
        "RUNT_X_TM",
        "RUNT_Y_TM",
        "RUNT_X_TF",
        "RUNT_Y_TF",
        "TLED_X",
        "TLED_Y",
        "RLED_X",
        "RLED_Y",
        "",
        "",
        "RAGC_X_TB",
        "RAGC_Y_TB",
        "RAGC_X_TM",
        "RAGC_Y_TM",
        "RAGC_X_TF ",
        "RAGC_Y_TF"
        /*
            "ADC_X_TB",
            "ADC_Y_TB",
            "ADC_X_TM",
            "ADC_Y_TM",
            "ADC_X_TF",
            "ADC_Y_TF",
            "ORG_X_TB",
            "ORG_Y_TB",
            "ORG_X_TM",
            "ORG_Y_TM",
            "ORG_X_TF",
            "ORG_Y_TF",
            "RAT_X_TB",
            "RAT_Y_TB",
            "RAT_X_TM",
            "RAT_Y_TM",
            "RAT_X_TF",
            "RAT_Y_TF",
            "AGC_X_TB",
            "AGC_Y_TB",
            "AGC_X_TM",
            "AGC_Y_TM",
            "AGC_X_TF",
            "AGC_Y_TF",
            "UNT_X_TB",
            "UNT_Y_TB",
            "UNT_X_TM",
            "UNT_Y_TM",
            "UNT_X_TF",
            "UNT_Y_TF",
            "RVR_X_TB",
            "RVR_Y_TB",
            "RVR_X_TM",
            "RVR_Y_TM",
            "RVR_X_TF",
            "RVR_Y_TF"
            */
    ]

    property int selectedSignalCount: 0


    function triggerModel(mode) {

        var _selected = !mode.selected;

        if (_selected && selectedSignalCount >= maxSignal   ) {
            showToast(qsTr("max %1 signal").arg(selectedSignalCount));
            return;
        }
        mode.selected = _selected;
        if (mode.selected === true) {
            if(displaySeparateModel)
            {

                //限制同时只能选择testCount个信号
                if(signalIndexs.length < testCount)
                {
                    signalIndexs.push(mode.number)
                    mode.bColor = signalColors[selectedSignalCount];

                }
                else
                {
                    _selected = !mode.selected;
                    mode.selected = _selected;
                   showToast(qsTr("max %1 signal").arg(testCount));
                    selectedSignalCount--;

                }

            }
            else
            {
                signalIndexs.push(mode.number)
                mode.bColor = signalColors[selectedSignalCount];

            }
            selectedSignalCount++;

        }
        else
        {
            removeSignalByValue(mode.number);
            mode.bColor = normalColor;

            //                            for (var j = 0; j < signalModel.count; j++) {
            //                                signalModel.get(j).bColor = normalColor;
            //                            }
            for (var i = 0; i < signalIndexs.length; i++)
            {
                var index = signalIndexs[i];
                for (var j = 0; j < signalModel.count; j++) {
                    if (index === signalModel.get(j).number) {
                        signalModel.get(j).bColor = signalColors[i];
                        break;
                    }
                }
            }
            selectedSignalCount--;
        }
        dataDirty = true;
        touch.updateSignalList(signalIndexs);
        repaintChart(true);
    }

    property bool running: true
    onRunningChanged: {
        console.log("running:"+running);
        if (running) {
            refreshTimer.start();
            touch.startGetSignalDataBg(1);
        } else {
            refreshTimer.stop();
            touch.stopGetSignalDataBg();
        }
    }

    property var lastClickTimeCount: 0

     RowLayout{
         anchors.fill: parent
         Cont1.ScrollView {
             property Item rtext:rtext
             //滚动条模式
             horizontalScrollBarPolicy: (winVersion === undefined || winVersion !== winXPVersion) ? Qt.ScrollBarAlwaysOff : Qt.ScrollBarAlwaysOn
             verticalScrollBarPolicy: Qt.ScrollBarAlwaysOff
             //左右上与parent对齐，上边缘的距离为10
             anchors.left: parent.left
             anchors.right: parent.right
             anchors.top: parent.top
             anchors.topMargin: 10

             id: testItemBoxView
             height: (rtext === undefined) ? 20 : (rtext.height + 20)

             ListView {
                 id: testItemBox
                 spacing: 10
                 delegate: Rectangle {
                     id: rRect
                     width: rtext.width + 10
                     height: rtext.height + 20

                     color: bColor
                     MouseArea {
                         anchors.fill: parent
                         onClicked: {
                             var mode;
                             for (var i = 0; i < signalModel.count; i++) {
                                 mode = signalModel.get(i);
                                 if (mode.number === number) {
                                     break;
                                 }
                             }

                             triggerModel(mode);
                         }

                         Text {
                             id: rtext
                             color: "#FFFFFF"
                             x: 5
                             y: 5
                             text: " " + name + " \n " + number + " " + standard
                             padding: 5
                             height: Math.min(Math.max(40,signalItemHeight * 40),130);
                             width:Math.min(Math.max(120,signalItemWidth * 120),400);
                             font.pointSize: Math.min((9 + (Math.min(signalItemHeight,signalItemWidth)-1)* 4),20);
                             anchors.verticalCenter: parent.verticalCenter
                         }

                     }
                 }
                 model: ListModel {
                     id: signalModel
                 }
                 orientation: ListView.Horizontal
             }
         }
         Rectangle{
             id: chartTitle
             Layout.maximumWidth: 150
             Layout.minimumWidth: 80
             Layout.preferredWidth: 150
             anchors.right: parent.right
             anchors.leftMargin: defaultMargin
             anchors.top: testItemBoxView.bottom
             anchors.bottom: buttons.top
             anchors.topMargin: -90 + itemHeight
             Layout.fillWidth: true
             Layout.fillHeight: true
             Canvas
             {
                 id: chartTitleInfo
                 width: parent.width
                 height: parent.height
                 Layout.fillHeight: true
                 Layout.fillWidth: true
                 onPaint: {
                     touch.paintLock();
                     var ctx = chartTitleInfo.getContext("2d");
                     //信号的实际高度
                     var actualHeight ;
                     if(signalIndexs.length < testCount)
                          actualHeight = chartBackgroundCanvas.height / signalIndexs.length;
                      else
                          actualHeight = chartBackgroundCanvas.height / testCount;

                     ctx.reset();
                     ctx.font = "normal " + (fontSize + 3) + "px 'Arial'";
                     var textWidth = ctx.measureText("UNT_Y_TM").width
                     var i,k;
                     var max;
                     var min;
                     var standard ;
                     var standardStr ;
                     for (k = 0; k < signalIndexs.length; k++)
                     {
                         //获取项的最大最小值
                         for(i = 0;i < items.length;i++)
                         {
                             if(items[i] === signalIndexs[k])
                             {
                                 standard = standards[i];
                                 break;
                             }
                         }

                         if (standard !== undefined)
                         {
                             if (touch)
                                 appType = touch.getAppType();
                             if (standard["max"] !== 0)
                             {
                                 standardStr = " [" +  standard["min"] + ", " + standard["max"] + "]";
                                 max = standard["max"];
                                 min = standard["min"];
                             }
                             else
                             {
                                 if (appType == 1)
                                 { // client
                                     standardStr = " [" +  standard["client_min"] + ", " + standard["client_max"] + "]";
                                     max = standard["client_max"];
                                     min = standard["client_min"];
                                 }
                                 else
                                 {
                                     standardStr = " [" +  standard["factory_min"] + ", " + standard["factory_max"] + "]";
                                     max = standard["factory_max"];
                                     min = standard["factory_min"];
                                 }
                             }

                         }
                         ctx.fillStyle = signalColors[k];
                         ctx.strokeStyle = Qt.rgba(0, 0, 0, 0.6);
                         ctx.fillText("" + testNames[signalIndexs[k]], 10, actualHeight * k + actualHeight / 2);
                         ctx.fillText("" + signalIndexs[k],10, actualHeight  * k + actualHeight / 2 + fontSize + 10);
                         ctx.fillText("" + standardStr, 30, actualHeight  * k + actualHeight  / 2 + fontSize + 10);
                         if(signalResult[k])
                         {
                             ctx.drawImage(signalImageYes,10,actualHeight  * k + actualHeight  / 2 + fontSize * 2 + 10,25,25);
                         }
                         else
                         {
                             ctx.drawImage(signalImageNo,10,actualHeight  * k + actualHeight  / 2 + fontSize * 2 + 10,25,25);
                         }

                     }
                      touch.paintUnlock();
//                     console.log("Text width: " + chartTitle.width);

                 }
                 Component.onCompleted: {
                     loadImage(signalImageYes);
                     loadImage(signalImageNo);
                 }
                 onImageLoaded: {
                     requestPaint();
                 }
             }


         }

        Cont1.ScrollView {

            id: chartScroll
            Layout.minimumHeight: scrollHeight + 5
            Layout.preferredHeight: scrollHeight + 5
            Layout.maximumHeight: scrollHeight + 5
            anchors.top: testItemBoxView.bottom
            anchors.topMargin: -90 + itemHeight
            anchors.bottom: buttons.top
            anchors.left: parent.left
            anchors.right: chartTitle.left
            anchors.leftMargin: 10
            Layout.fillWidth: true
            Layout.fillHeight: true
            horizontalScrollBarPolicy: (winVersion === undefined || winVersion !== winXPVersion) ? Qt.ScrollBarAlwaysOff : Qt.ScrollBarAlwaysOn
            verticalScrollBarPolicy: (winVersion === undefined || winVersion !== winXPVersion) ? Qt.ScrollBarAlwaysOff : Qt.ScrollBarAlwaysOn

            Rectangle {
                height: scrollHeight * chartScaleY + 5
                width: chartWidth + Charts.config.startX

                Layout.fillWidth: true
                Layout.fillHeight: true
                anchors.bottom: buttons.top
                anchors.top: testItemBoxView.bottom
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (mouse.button == Qt.LeftButton) {
                            var t = new Date().getTime();
    //                        console.log("L:" + lastClickTimeCount + "    " + t)
                            if (t - lastClickTimeCount > 100 && t - lastClickTimeCount < 500) {
    //                            console.log("double click");
                                lastClickTimeCount = 0;
                                chartScaleY = chartScaleX = 1;
                                repaintChart(true);
                            }
                            lastClickTimeCount = t;
                        }
                    }

                    onWheel: {
                        var wheelY = 0, wheelX = 0;
                        var needRepaint = true;
                        if (wheel.modifiers) {
                            if (wheel.modifiers & Qt.ControlModifier) {
                                wheelY = 1;
                                wheelX = 1;
                            }

                            if (wheel.modifiers & Qt.ShiftModifier) {
                                wheelY = 1;
                            }
                        } else {
                            wheelX = 1;
                            wheelY = 0;
                        }
                        if (wheel.angleDelta.y / 120 > 0) {
                            if (wheelY === 1 && chartScaleY < maxScale)
                                chartScaleY += chartScaleStep;
                            if (wheelX === 1 && chartScaleX < maxScale)
                                chartScaleX += chartScaleStep;
                        } else {
                            if (wheelY === 1) {
                                var temp = chartScaleY - chartScaleStep;
                                chartScaleY = temp;
                                if ((chartCanvas.height - fontSize)< chartScroll.height) {
                                    chartScaleY = (chartScroll.height - fontSize) / scrollHeight
                                } else {
                                    chartScaleY = temp;
                                }
                            }
                            if (wheelX === 1) {
                                var tempx = chartScaleX - chartScaleStep;
                                if (tempx < minScale) {
                                    chartScaleX = minScale;
                                } else {
                                    chartScaleX = tempx;
                                }
                            }
                        }
                        if (needRepaint)
                            repaintChart(true);
                    }

                }//MouseArea
                //画背景
            Canvas {
                id: chartBackgroundCanvas
                //画布的宽度与高度
                width: chartWidth + Charts.config.startX
                height: scrollHeight * chartScaleY + 5
                Layout.fillWidth: true
                Layout.fillHeight: true
                anchors.top: testItemBoxView.bottom
                onPaint: {
                    //Canvas只支持2d
                    var ctx = chartBackgroundCanvas.getContext("2d");
                    var yLabelStep = 15;
                    var xLabelStep = 5;
                    //x与y轴的起始位置
                    var startX = Charts.config.startX;
                    var startY = Charts.config.startY;
                    //点击测试的个数

                    var clickTestCount = signalIndexs.length;
                    if(clickTestCount != 0)
                        saveLastTestItemCount = clickTestCount ;
                    else
                        clickTestCount = saveLastTestItemCount;

                    //表示的是信号图的实际高度
                    var actualHeight ;
                    if(clickTestCount > testCount)
                        actualHeight = (height - fontSize - startY - 10) /  testCount;
                    else
                       actualHeight = (height - fontSize - startY - 10) /  clickTestCount;



                    //该值表示的是坐标上每显示15就是信号实际移动的距离
                    var yStep = 9 / 10 * actualHeight  / Charts.config.yMax * yLabelStep;
    //                var yStep = actualHeight / Charts.config.yMax * yLabelStep;

                    var sdata, data;
                    var k;
                    var i;
                    var maxCount = 100;

                    var standard ;
                    for (k = 0; k < signalIndexs.length; k++)
                    {
                        for(i = 0;i < items.length;i++)
                        {
                            if(items[i] === signalIndexs[k])
                            {
                                standard = standards[i];
                                if(standard["count"] > maxCount)
                                {
                                    maxCount = standard["count"];

                                }
                                break;
                            }
                        }
                    }

                    maxDataCount = maxCount;
                    var xStep = (chartWidth - 20)/ maxCount * xLabelStep;

                    /*
                    var xStep = chartWidth / Charts.config.xMax * xLabelStep;
                    */

                   ctx.reset();

                    var y;
                    var x;
                    var labelWidth;
                    var t1 = new Date();
                    var labelValue = 0;
                    if(displaySeparateModel)
                    {
                        if(!histogram)
                        {
                            for(i = 0;i < clickTestCount && i < testCount;i++)
                            {
                                //Y轴
                                ctx.beginPath();//开始绘画路径
                                //actualHeight/10表示留下1/10空闲位置
                                ctx.moveTo(startX , (i * actualHeight) + actualHeight/10 );//移动路径点到（x,y）
                                ctx.strokeStyle = Qt.rgba(0, 0, 0, 1);//画笔颜色
                                ctx.lineWidth = 0.5;//画笔粗细
                                ctx.lineTo(startX , actualHeight*(1 + i) + startY);//从当前点到(startX, actualHeight + startY)点连成一条直线，但是不涂色
                                ctx.stroke();//将当前路劲用strokeStyle涂色
                                //画X轴
                                ctx.beginPath();
                                ctx.moveTo(startX, actualHeight*(1 + i) + startY );
                                ctx.lineWidth = 1;
                                ctx.lineTo(startX + chartWidth, actualHeight*(1 + i) + startY);
                                ctx.stroke();
                                ctx.lineWidth = 0.2;
                                ctx.font = "normal " + fontSize + "px 'Arial'";
                                labelValue = 0;
                                z = 0;
                                //画水平线
                                labelValue = 0;

                                for(y = actualHeight + (i * actualHeight)+ startY ;
                                    y >= startY + (i * actualHeight) + actualHeight/10 -1 ; y -= yStep)
                                {
                                    ctx.beginPath();
                                    ctx.moveTo(startX, y);
                                    ctx.lineTo(startX + chartWidth, y);
                                    ctx.stroke();
                                    ctx.closePath();
                                    ctx.fillText("" + labelValue, 0, y + fontSize / 2);
                                    labelValue += yLabelStep;
                                    if(labelValue > Charts.config.yMax)
                                    {
                                        break;
                                    }

                                }


                                labelValue = 1;
                                //画垂直线
                                z = 0;
                                for (x = startX; x < chartWidth + startX; x += xStep)
                                {
                                    ctx.beginPath();
                                    ctx.moveTo(x,  startY + actualHeight * i + actualHeight / 10);
                                    ctx.lineTo(x, actualHeight*(i +1) + startY );
                                    ctx.stroke();
                                    ctx.closePath();
                                    //measureText返回值是“000”这个指定的宽度，这个为3
                                    labelWidth = ctx.measureText("000").width
                                    if (labelWidth < xStep || z % 2 === 0)
                                        ctx.fillText("" + labelValue, x - labelWidth / 2, actualHeight*(i +1) + startY + fontSize);
                                    z++;
                                    labelValue += xLabelStep;
                                }
                            }
                        }
                        else
                        {
                            //柱状图背景
                            yStep = 9 / 10 * actualHeight  / (Charts.config.yMax + 5) * yLabelStep;
                            for(i = 0;i < clickTestCount && i < testCount;i++)
                            {

                                //Y轴
                                ctx.beginPath();//开始绘画路径
                                //actualHeight/10表示留下1/10空闲位置
                                ctx.moveTo(startX , (i * actualHeight) + actualHeight/10 );//移动路径点到（x,y）
                                ctx.strokeStyle = Qt.rgba(0, 0, 0, 1);//画笔颜色
                                ctx.lineWidth = 0.5;//画笔粗细
                                ctx.lineTo(startX , actualHeight*(1 + i) + startY);//从当前点到(startX, actualHeight + startY)点连成一条直线，但是不涂色
                                ctx.stroke();//将当前路劲用strokeStyle涂色
                                //画X轴
                                ctx.beginPath();
                                ctx.moveTo(startX, actualHeight*(1 + i) + startY );
                                ctx.lineWidth = 1;
                                ctx.lineTo(startX + chartWidth, actualHeight*(1 + i) + startY);
                                ctx.stroke();
                                ctx.lineWidth = 0.2;
                                ctx.font = "normal " + fontSize + "px 'Arial'";
                                labelValue = 0;
                                z = 0;
                                //画水平线
                                labelValue = -5;

                                y = actualHeight + (i * actualHeight)+ startY ;
                                ctx.beginPath();
                                ctx.moveTo(startX, y);
                                ctx.lineTo(startX + chartWidth, y);
                                ctx.stroke();
                                ctx.closePath();
//                                ctx.fillText("" + labelValue, 0, y + fontSize / 2);
                                labelValue += 5;
                                y -= 5 * (9 / 10 * actualHeight  / (Charts.config.yMax + 5));

                                for(;y >= startY + (i * actualHeight) + actualHeight/10 -1 ; y -= yStep)
                                {
                                    ctx.beginPath();
                                    ctx.moveTo(startX, y);
                                    ctx.lineTo(startX + chartWidth, y);
                                    ctx.stroke();
                                    ctx.closePath();
                                    ctx.fillText("" + labelValue, 0, y + fontSize / 2);
                                    labelValue += yLabelStep;
                                    if(labelValue > Charts.config.yMax)
                                    {
                                        break;
                                    }

                                }
                                labelValue = 1;
                                //画垂直线
                                z = 0;
                                for (x = startX; x < chartWidth + startX; x += xStep)
                                {
                                    ctx.beginPath();
                                    ctx.moveTo(x,  startY + actualHeight * i + actualHeight / 10);
                                    ctx.lineTo(x, actualHeight*(i +1) + startY );
                                    ctx.stroke();
                                    ctx.closePath();
                                    //measureText返回值是“000”这个指定的宽度，这个为3
                                    labelWidth = ctx.measureText("000").width
                                    if (labelWidth < xStep || z % 2 === 0)
                                        ctx.fillText("" + labelValue, x - labelWidth / 2, actualHeight*(i +1) + startY + fontSize);
                                    z++;
                                    labelValue += xLabelStep;
                                }

                            }

                        }


                    }
                    else
                    {
                        yLabelStep = 5;
                        xLabelStep = 5;
                        startX = Charts.config.startX;
                        startY = Charts.config.startY;
                        actualHeight = height - fontSize - startY - 10;
                        yStep = actualHeight / Charts.config.yMax * yLabelStep;
                        //画y轴
                        ctx.beginPath();
                        ctx.moveTo(startX, 0);
                        ctx.strokeStyle = Qt.rgba(0, 0, 0, 1);
                        ctx.lineWidth = 0.5;
                        ctx.lineTo(startX, actualHeight + startY);
                        ctx.stroke();
                        //画x轴
                        ctx.beginPath();
                        ctx.moveTo(startX, actualHeight + startY);
                        ctx.lineWidth = 1;
                        ctx.lineTo(startX + chartWidth, actualHeight + startY);
                        ctx.stroke();
                        ctx.lineWidth = 0.2;
                        ctx.font = "normal " + fontSize + "px 'Arial'";
                        labelValue = 0;
                        //  horizontal
                        for (y = actualHeight + startY; y >= startY; y -= yStep) {
                            ctx.beginPath();
                            ctx.moveTo(startX, y);
                            ctx.lineTo(startX + chartWidth, y);
                            ctx.stroke();
                            ctx.closePath();
                            ctx.fillText("" + labelValue, 0, y + fontSize / 2);
                            labelValue += yLabelStep;
                        }

                        labelValue = 1;
                        // vertical
                        i = 0;
                        for (x = startX; x < chartWidth + startX; x += xStep) {
                            ctx.beginPath();
                            ctx.moveTo(x, startY);
                            ctx.lineTo(x, actualHeight + startY);
                            ctx.stroke();
                            ctx.closePath();
                            labelWidth = ctx.measureText("000").width
                            if (labelWidth < xStep || i % 2 === 0)
                                ctx.fillText("" + labelValue, x - labelWidth / 2, actualHeight + startY + fontSize);
                            i++;
                            labelValue += xLabelStep;
                        }
                    }


                    ctx.beginPath();
    //                touch.paintDefaultLock();
    //                var t2 = new Date();
    //                console.log("consume: " + (t2.getTime() - t1.getTime()))
                }

                Component.onCompleted: {
    //                requestPaint();
                }
            }


            //画信号线
            Canvas {
                id: chartCanvas
                //画布的大小
                width: chartWidth + Charts.config.startX
                height: scrollHeight * chartScaleY + 5
                Layout.fillWidth: true
                Layout.fillHeight: true
                anchors.top: testItemBoxView.bottom
                onPaint: {
                    if (!dataDirty)
                        return;

                    touch.paintLock();
                    var ctx = chartCanvas.getContext("2d");
                    //信号X,Y轴的起始位置
                    var startX = Charts.config.startX;
                    var startY = Charts.config.startY;
                    //信号的实际高度
                    var actualHeight ;
                    if(signalIndexs.length < testCount)
                        actualHeight = (height - startY - fontSize - 10) / signalIndexs.length;
                    else
                        actualHeight = (height - startY - fontSize - 10) / testCount;


                    var ySpace = 9 / 10 * actualHeight / Charts.config.yMax;
                    var xSpace = (chartWidth - 20)/ Charts.config.xMax;
                    ctx.reset();
                    ctx.beginPath();
                    ctx.font = "normal " + (fontSize + 3) + "px 'Arial'";
                    var k;
                    var textWidth = ctx.measureText("UNT_Y_TM").width
    //                var t1 = new Date();

                    var sdata, data;
                    var maxCount = 100;
                    for (k = 0; k < signalIndexs.length; k++) {
                        sdata = signalDatas[signalIndexs[k]];
                        if (sdata === undefined) {
                            continue;
                        }
                        data = sdata["datas"];
                        if (maxCount < sdata["count"]) {
                            maxCount = sdata["count"];
                        }
                    }
                    maxDataCount = maxCount;
                     //数据X轴的实际间隙
                    xSpace = (chartWidth - 20)/ maxCount;


                    var lastx;
                    var lasty;
                    //存储最新的数据
                    var tox, toy;
                    var rectWidth,rectHeight;
                    var rectMinheight = 5;
                    var i;
                    var max;
                    var min;
                    var standard ;
                    var standardStr ;
                    var dataRet = true;

                    if(displaySeparateModel)
                    {
                        //柱状图的形式
                        if(histogram)
                        {
                            ySpace = 9 / 10 * actualHeight / (Charts.config.yMax + 5);
                            //绘制所有的信号
                            for (k = 0; k < signalIndexs.length && k < testCount; k++)
                            {

                                dataRet = true;
                                //获取项的最大最小值
                                for(i = 0;i < items.length;i++)
                                {
                                    if(items[i] === signalIndexs[k])
                                    {
                                        standard = standards[i];
        //                                console.log("max count:" + standard["count"] + "from " + signalIndexs[k] + "item" );
                                    }
                                }

                                if (standard !== undefined)
                                {
                                    if (touch)
                                        appType = touch.getAppType();
                                    if (standard["max"] !== 0)
                                    {
                                        standardStr = " [" +  standard["min"] + ", " + standard["max"] + "]";
                                        max = standard["max"];
                                        min = standard["min"];
                                    }
                                    else
                                    {
                                        if (appType == 1)
                                        { // client
                                            standardStr = " [" +  standard["client_min"] + ", " + standard["client_max"] + "]";
                                            max = standard["client_max"];
                                            min = standard["client_min"];
                                        }
                                        else
                                        {
                                            standardStr = " [" +  standard["factory_min"] + ", " + standard["factory_max"] + "]";
                                            max = standard["factory_max"];
                                            min = standard["factory_min"];
                                        }
                                    }

                                }

                                sdata = signalDatas[signalIndexs[k]];
                                if (sdata === undefined) {
                                    continue;
                                }
                                data = sdata["datas"];
                                //选择信号的颜色
                                ctx.fillStyle = signalColors[k];//Qt.rgba(0xff, 0, 0 , 1);
                                ctx.strokeStyle = Qt.rgba(0, 0, 0, 0.6);
                                //显示所有的点击信号的项
//                                ctx.fillText("" + testNames[signalIndexs[k]],width - 90,k * actualHeight + actualHeight / 2,100);
//                                ctx.fillText("" + standardStr,width -70 ,k * actualHeight + actualHeight / 2 + 30,20);
//                                ctx.fillText("" + signalIndexs[k],width -90 ,k * actualHeight + actualHeight / 2 + 30,100);

                                //绘制单个信号图
                                for (i = 0; i < sdata["count"]; i++)
                                {
                                    if(data[i] < min || data[i] > max)
                                    {
                                        dataRet = false;
                                        ctx.fillStyle = errorSignalColors;
                                    }
                                    else
                                    {
                                        ctx.fillStyle = signalColors[k];
                                    }

                                    tox = startX + i * xSpace;
                                    rectWidth = xSpace;
                                    if(data[i] <= 0 && data[i] < min )
                                    {
                                        rectHeight = rectMinheight * ySpace;

                                    }
                                    else
                                    {
                                        rectHeight = (data[i] + rectMinheight) * ySpace;

                                    }

                                    toy = actualHeight * (k + 1) + startY  - rectHeight;
                                    ctx.lineWidth = 1;
                                    ctx.beginPath();
                                    ctx.rect(tox,toy,rectWidth-5,rectHeight);

                                    ctx.strokeStyle = "#000000";
                                    ctx.fill();
                                    ctx.stroke();

                                }
                                if(!dataRet)
                                {
                                    signalResult[k] = false;
                                }
                                else
                                {
                                    signalResult[k] = true;
                                }

                            }
                            chartTitleInfo.requestPaint();
                        }
                        //点线
                        else
                        {
                            //绘制所有的信号
                            for (k = 0; k < signalIndexs.length && k < testCount; k++)
                            {
                                dataRet = true;
                                //获取项的最大最小值
                                for(i = 0;i < items.length;i++)
                                {
                                    if(items[i] === signalIndexs[k])
                                    {
                                        standard = standards[i];
        //                                console.log("max count:" + standard["count"] + "from " + signalIndexs[k] + "item" );
                                    }
                                }

                                if (standard !== undefined)
                                {
                                    if (touch)
                                        appType = touch.getAppType();
                                    if (standard["max"] !== 0)
                                    {
                                        standardStr = " [" +  standard["min"] + ", " + standard["max"] + "]";
                                        max = standard["max"];
                                        min = standard["min"];
                                    }
                                    else
                                    {
                                        if (appType == 1)
                                        { // client
                                            standardStr = " [" +  standard["client_min"] + ", " + standard["client_max"] + "]";
                                            max = standard["client_max"];
                                            min = standard["client_min"];
                                        }
                                        else
                                        {
                                            standardStr = " [" +  standard["factory_min"] + ", " + standard["factory_max"] + "]";
                                            max = standard["factory_max"];
                                            min = standard["factory_min"];
                                        }
                                    }

                                }

                                sdata = signalDatas[signalIndexs[k]];
                                if (sdata === undefined) {
                                    continue;
                                }
                                data = sdata["datas"];
                                //选择信号的颜色
                                ctx.fillStyle = signalColors[k];//Qt.rgba(0xff, 0, 0 , 1);
                                ctx.strokeStyle = Qt.rgba(0, 0, 0, 0.6);
                                //显示所有的点击信号的项
            //                    ctx.fillText("" + testNames[signalIndexs[k]], fontSize + (textWidth + fontSize) * k, fontSize);
    //                            ctx.fillText("" + testNames[signalIndexs[k]],width - 90,k * actualHeight + actualHeight / 2,100);
    //                            ctx.fillText("" + standardStr,width -70 ,k * actualHeight + actualHeight / 2 + 30,20);
    //                            ctx.fillText("" + signalIndexs[k],width -90 ,k * actualHeight + actualHeight / 2 + 30,80);

                                ctx.lineWidth = 0.3;
                                //存储上一个信号的数据坐标点
                                lastx = startX;
                                lasty = startY + k * actualHeight;

                                //绘制单个信号图
                                for (i = 0; i < sdata["count"]; i++) {

                                    ctx.beginPath();
                                    if(data[i] < min || data[i] > max)
                                    {
                                        ctx.fillStyle = Qt.rgba(0xff, 0xFF, 0 , 0);
                                        ctx.fillStyle = errorSignalColors;
                                        dataRet = false;
                                    }
                                    else
                                        ctx.fillStyle = signalColors[k];
                                    ctx.moveTo(lastx, lasty);
                                    tox = startX + i * xSpace ;
                                    toy = actualHeight * (k + 1)  + startY - (data[i] * ySpace);
                                    ctx.lineTo(tox, toy);
                                    ctx.closePath();
                                    ctx.stroke();
                                    lastx = tox;
                                    lasty = toy;

                                    ctx.arc(tox, toy, 3, 0, Math.PI*2, true);
                                    ctx.fill();
                                }
                                if(!dataRet)
                                {
                                    signalResult[k] = false;
                                }
                                else
                                {
                                    signalResult[k] = true;
                                }
                            }
                            chartTitleInfo.requestPaint();
                        }

                    }
                    else
                    {
                        startX = Charts.config.startX;
                        startY = Charts.config.startY;
                        actualHeight = height - startY - fontSize - 10;
                        ySpace = actualHeight / Charts.config.yMax;
    //                    xSpace = chartWidth / Charts.config.xMax;

                        for (k = 0; k < signalIndexs.length; k++)
                        {
                            dataRet = true;
                            //获取项的最大最小值
                            for(i = 0;i < items.length;i++)
                            {
                                if(items[i] === signalIndexs[k])
                                {
                                    standard = standards[i];
                                }
                            }

                            if (standard !== undefined)
                            {
                                if (touch)
                                    appType = touch.getAppType();
                                if (standard["max"] !== 0)
                                {
                                    standardStr = " [" +  standard["min"] + ", " + standard["max"] + "]";
                                    max = standard["max"];
                                    min = standard["min"];
                                }
                                else
                                {
                                    if (appType == 1)
                                    { // client
                                        standardStr = " [" +  standard["client_min"] + ", " + standard["client_max"] + "]";
                                        max = standard["client_max"];
                                        min = standard["client_min"];
                                    }
                                    else
                                    {
                                        standardStr = " [" +  standard["factory_min"] + ", " + standard["factory_max"] + "]";
                                        max = standard["factory_max"];
                                        min = standard["factory_min"];
                                    }
                                }

                            }

                            sdata = signalDatas[signalIndexs[k]];
                            if (sdata === undefined) {
                                continue;
                            }
                            data = sdata["datas"];
                            ctx.fillStyle = signalColors[k];//Qt.rgba(0xff, 0, 0 , 1);
                            ctx.strokeStyle = Qt.rgba(0, 0, 0, 0.6);
//                            ctx.fillText("" + testNames[signalIndexs[k]], width - 90, actualHeight / signalIndexs.length * k + actualHeight / signalIndexs.length / 2,fontSize);
//                            ctx.fillText("" + signalIndexs[k], width - 90, actualHeight / signalIndexs.length * k + actualHeight / signalIndexs.length / 2 + fontSize + 10);
//                            ctx.fillText("" + standardStr, width - 70, actualHeight / signalIndexs.length * k + actualHeight / signalIndexs.length / 2 + fontSize + 10);

                            ctx.lineWidth = 0.3;
                            lastx = startX;
                            lasty = startY;
                            for (i = 0; i < sdata["count"]; i++) {

                                if(data[i] < min || data[i] > max)
                                {
                                    ctx.fillStyle = errorSignalColors;
                                    dataRet = false;
                                }
                                else
                                {
                                    ctx.fillStyle = signalColors[k];

                                }

                                ctx.beginPath();
                                ctx.moveTo(lastx, lasty);
                                tox = startX + i * xSpace;
                                toy = actualHeight + startY - (data[i] * ySpace);
                                ctx.lineTo(tox, toy);
                                ctx.closePath();
                                ctx.stroke();
                                lastx = tox;
                                lasty = toy;

                                ctx.arc(tox, toy, 3, 0, Math.PI*2, true);
                                ctx.fill();
                            }
                            if(!dataRet)
                            {
                                signalResult[k] = false;

                            }
                            else
                            {
                                signalResult[k] = true;

                            }
                        }
                        chartTitleInfo.requestPaint();
                    }

                    touch.paintUnlock();
                    dataDirty = false;

    //                var t2 = new Date();
    //                console.log("Signal consume: " + (t2.getTime() - t1.getTime()))
                }
                Component.onCompleted: {

                }
            }

            }
        }

     }

    RowLayout {
        id: buttons
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 10
        anchors.left: parent.left
        anchors.leftMargin: 10
        Cont1.Button {
            style: TButtonStyle {
                height: 20
                label: Text {
                    color: "#FFFFFF"
                    text: qsTr("refresh real-time")
                    font.pointSize: 10
                    verticalAlignment: Text.AlignVCenter
                    horizontalAlignment: Text.AlignHCenter
                }
                backgroundColor: (running) ? "#0277BD" : "#64B5F6"
            }
            onClicked: {
                running = !running;
                stopRefresh = !stopRefresh;
            }

            visible: true
        }
        Cont1.Button {
            style: TButtonStyle {
                height: 20
                label: Text {
                    color: "#FFFFFF"
                    text: qsTr("initialize signal")
                    font.pointSize: 10
                    verticalAlignment: Text.AlignVCenter
                    horizontalAlignment: Text.AlignHCenter
                }
            }
            onClicked: {
//                clearCharts();
                touch.signalInit(1);
            }
        }

        Cont1.Button {

            style: TButtonStyle {
                height: 20
                label: Text {
                    color: "#FFFFFF"
                    text: qsTr("audo close coordinate")
                    font.pointSize: 10
                    verticalAlignment: Text.AlignVCenter
                    horizontalAlignment: Text.AlignHCenter
                }
                backgroundColor: (currentStatus) ? "#0277BD" : "#64B5F6"
            }
            onClicked: {
                currentStatus = !currentStatus;
                click();
            }
        }
        Cont1.Button {

            style: TButtonStyle {
                height: 20
                label: Text {
                    color: "#FFFFFF"
                    text: qsTr("test mode")
                    font.pointSize: 10
                    verticalAlignment: Text.AlignVCenter
                    horizontalAlignment: Text.AlignHCenter
                }
                backgroundColor: (enterTest) ? "#0277BD" : "#64B5F6"
            }
            onClicked: {
                enterTest = !enterTest;
//                            console.log("test qml settest: " + enterTest);
            }
        }
    }
    property bool enterTest: false
    property bool currentStatus: false
    property bool needRestoreStatus: false
    signal click();

    property int maxDataCount: 100
    function updateSignalData(datas) {

        //console.log("Result:" + datas["result"])
        if (datas["result"] === 1) {
            return
        }
        touch.paintLock();
//        console.log("ready get signalDatas");
        signalDatas[datas["index"]] = datas;
        dataDirty = true;
        touch.paintUnlock();
//        touch.paintDefaultLock();
//        touch.paintSemRelease(); // +1
        if (datas["count"] > maxDataCount)
            maxDataCount = datas["count"];
//        repaintChart(false);
    }

    function showSingalChart(index) {
        if (touch) {
            var datas = touch.getSignalData(index);
            showSignal(datas);

        }
    }

    function showChart(data) {
        testChart.visible = true;

    }
    function hideChart() {
        testChart.visible = false;
    }

    function clearCharts(){
        for (var j = 0; j < signalModel.count; j++) {
            signalModel.get(j).bColor = normalColor;
            signalModel.get(j).selected = false;
        }
        saveNumbers();
        signalIndexs = [];
        selectedSignalCount = 0;
    }

    function clearModels() {
        signalModel.clear();
        saveNumbers();
        signalIndexs = [];

        selectedSignalCount = 0;
        running = true;
    }

    function clearAndRefreshItems() {
        if (saveIndexs.length > 0)
            return;
        clearModels();
        refreshItems(true);
    }

    property var saveIndexs : [];
    function saveNumbers() {
        if (signalIndexs.length <= 0)
            return;
        saveIndexs = []
        for (var i = 0; i < signalIndexs.length; i++)  {
            console.log("i=" + i)
            saveIndexs[i] = signalIndexs[i];
        }
    }
    function setSignalItems(list) {
        if (list === undefined) {
            return;
        }
        signalIndexs = [];
        console.log("set signal items:" + list);
        console.log("model = " + signalModel.count);
        selectedSignalCount = 0;
        for (var i = 0; i < list.length; i++) {
            for (var j = 0; j < signalModel.count; j++) {
                var mode = signalModel.get(j);
                if (mode.number === list[i]) {
                    signalIndexs.push(list[i]);
                    mode.bColor = signalColors[selectedSignalCount];
                    selectedSignalCount++;
                    mode.selected = true;
                }
            }
        }
//        console.log("after " + selectedSignalCount);
        touch.updateSignalList(signalIndexs);
        repaintChart(true)
    }

    function restoreNumbers() {
        var mode;
        for (var i = 0; i < saveIndexs.length; i++) {
            console.log("restore: " + saveIndexs[i]);
            for (var j = 0; j < signalModel.count; j++) {
                mode = signalModel.get(j);
                if (saveIndexs[i] === mode.number && mode.selected !== true) {
                    signalIndexs.push(saveIndexs[i]);
                    mode.bColor = signalColors[selectedSignalCount];
                    selectedSignalCount++;
                    mode.selected = true;
//                } else {
//                    if (!mode.selected)
//	                    mode.selected = false;
                }
            }
        }
        touch.updateSignalList(signalIndexs);
        repaintChart(true);
    }

    function getSelectedCount() {
        return selectedSignalCount;
    }

    function refreshItems(force) {
        if (touch) {
            console.log("refreshItems signalModel.count = " + signalModel.count);
            if (!force && signalModel.count > 0)
                return;
            var data = touch.getSignalItems();
            var result = data['result'];
            console.log("force="+force +"," + signalModel.count);
            console.log("refreshItems result:" + result)
            if (result === 0) {
                items = data['items'];
                standards = data["standards"]

                var infos = [];
                for (var i = 0; i < items.length; i++) {
                    var standard = standards[i];
                    var standardStr = "";
                    var info = testNames[items[i]] + " " + items[i];
                    if (standard !== undefined) {
                        var appType = 0;
                        if (touch)
                            appType = touch.getAppType();
                        if (standard["max"] !== 0) {
                            standardStr = " [" +  standard["min"] + ", " + standard["max"] + "]";
                        } else {
                            if (appType == 1) { // client
                                standardStr = " [" +  standard["client_min"] + ", " + standard["client_max"] + "]";
                            } else {
                                standardStr = " [" +  standard["factory_min"] + ", " + standard["factory_max"] + "]";
                            }
                        }
                        info += standardStr;
                    }
                    infos.push(info);
                    signalModel.append(
                                {name:testNames[items[i]], number:items[i],
                                 standard:standardStr, selected:false,
                                 bColor: normalColor})
                }
                testInfo = infos;
                //console.log(testInfo)
                testItems = items;
            }
        }
    }

    function removeSignalByValue(value) {
        var i = signalIndexs.indexOf(value);
        if (i >= 0)
            signalIndexs.splice(i, 1);
    }

    Component.onCompleted: {
    }

    function startAutoRefresh() {
        refreshTimer.restart();
        console.log("start refresh");
        running = true;
    }

    function stopAutoRefresh() {
        refreshTimer.stop();
        console.log("stop refresh");
    }

    Timer{
        id: refreshTimer
        interval: 16
        repeat: true
        running: false
        triggeredOnStart: false
        onTriggered: {
//            console.log("dirty " + (new Date().getTime()))
//            chartCanvas.requestPaint();
        }
    }
    onDataDirtyChanged: {
//        console.log("dirty " + (new Date().getTime()))
        chartCanvas.requestPaint();
    }

    function repaintChart(bg) {
        chartBackgroundCanvas.requestPaint();
        chartCanvas.requestPaint();
        chartTitleInfo.requestPaint();
    }

    onScrollHeightChanged: {
//        chartBackgroundCanvas.requestPaint();
//        chartCanvas.requestPaint();
    }

    onHeightChanged: {
//        scrollHeight = height - 100;
        //console.log("height: " + height)
    }

    property var toaskInfo: ""
    function showToast(info) {
        toask.opacity = 1;
       toaskInfo = info;
    }

    Rectangle {
        id: toask
        color: "#00ff00"
        visible: true
        radius: 4
        opacity: 0
        Behavior on opacity {
            PropertyAnimation{ duration : 500 }
        }
        onOpacityChanged: {
            if (opacity === 1) {
                delay(3000, function() {
                    opacity = 0;
                })
            }
        }
        Rectangle {
            width: toaskLabel.paintedWidth + toaskLabel.rightPadding * 2
            height: toaskLabel.height
            border.width: 0
            color: "#263238"
            radius: 4
            anchors.centerIn: parent

            Label {
                id: toaskLabel
                padding: 20
                color: "#FFFFFF";
                text: toaskInfo
                font.pointSize: 12
                anchors.centerIn: parent
            }

        }

        anchors.centerIn: parent
    }
    Timer {
        id: timer
    }

    function delay(delayTime, cb) {
        timer.interval = delayTime;
        timer.repeat = false;
        timer.triggered.connect(cb);
        timer.start();
    }
    Keys.enabled: true
    Keys.onPressed: {

        if (event.key >= Qt.Key_0 && event.key <= Qt.Key_9) {
            if (event.key === Qt.Key_0) {
                triggerModel(signalModel.get(9));
            } else {
                triggerModel(signalModel.get(event.key - Qt.Key_1));
            }
        }

    }

}
