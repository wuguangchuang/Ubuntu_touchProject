/*
import QtQuick 2.0
import QtQuick.Window 2.2
import QtQuick.Controls 1.4
import QtQuick.Controls 2.0 as Cont2
import QtQuick.Controls.Styles 1.4
import QtQuick.Dialogs 1.1
import QtQuick.Layouts 1.3


import TouchPresenter 1.0
import QDrawPanel 1.0
import "qrc:/"
import "qrc:/qml/ui/"

Window
{

    visible: false
    title: qsTr("PlateLoadTest")
    id:pltWindowID

    property int downBoard:3
    property var downBoardOrder:[]
    property var downBoardColor:[]
    property var downBoardState:[]
    property var downLamp:[]
    property int downAllLampCount:0
    property var downLampColor:[]
    property var downLampState:[]
    property var downConnectorColor:[]


    property int rightBoard:2
    property var rightBoardOrder:[]
    property var rightBoardColor:[]
    property var rightBoardState:[]
    property var rightLamp:[]
    property int rightAllLampCount:0
    property var rightLampColor:[]
    property var rightLampState:[]
    property var rightConnectorColor:[]


    property int upBoard:3
    property var upBoardOrder:[]
    property var upBoardColor:[]
    property var upBoardState:[]
    property var upLamp:[]
    property int upAllLampCount:0
    property var upLampColor:[]
    property var upLampState:[]
    property var upConnectorColor:[]

    property int leftBoard:2
    property var leftBoardOrder:[]
    property var leftBoardColor:[]
    property var leftBoardState:[]
    property var leftLamp:[]
    property int leftAllLampCount:0
    property var leftLampColor:[]
    property var leftLampState:[]
    property var leftConnectorColor:[]

    property string leftUpConnectorColor:"black"
    property string leftDownConnectorColor:"black"
    property string rightDownConnectorColor:"black"

    property var standardColor:[]


    //板与板之间的间距
    property int boardSpace:30
    property int defaultMargin:30
    //每条边框的宽度
    property int edgesSize:50
    //边框颜色
    property string edgesBoardColor:"gray"
    //边框大小
    property int edgesBoard:5

    property bool _exit : false
    property string midRecttextString:""
    Rectangle
    {
        id:upRect
        height: edgesSize
        width:parent.width - 2 * (defaultMargin + edgesSize)

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: defaultMargin
        anchors.leftMargin: defaultMargin + edgesSize
        anchors.rightMargin: defaultMargin + edgesSize

        color:"#D5D5D5"
        border.color: edgesBoardColor
        border.width: edgesBoard


        Canvas
        {
            id:pltUpCanvas
            anchors.fill: parent
            onPaint:
            {
                touch.paintLock();
                var ctx = pltUpCanvas.getContext("2d");
                ctx.reset();

                var avgSpace = (pltUpCanvas.width - (upBoard - 1)* boardSpace - edgesBoard * 2) / upAllLampCount;

                var rectWidth ;
                if(avgSpace >= pltUpCanvas.height - 2 * edgesBoard - 10)
                    rectWidth = pltUpCanvas.height - 2 * edgesBoard - 10;
                else
                    rectWidth = avgSpace - 4;

                var rectHeight = pltUpCanvas.height - 2 * edgesBoard - 10;
                var tox ;
                var toy ;
                var lampNum = 0;
                var boardTox = 0;
                var boardtoy = 0;
                var boardWidth;
                var boardHeight = pltUpCanvas.height;
                for(var i = 0;i < upBoard;i++)
                {
                    ctx.beginPath();
                    ctx.lineWidth = edgesBoard;
                    ctx.strokeStyle = upBoardColor[i];
                    if(i === 0)
                        boardWidth = edgesBoard + upLamp[i] * avgSpace + boardSpace / 2 - edgesBoard;
                    else if(i === upBoard - 1)
                        boardWidth = edgesBoard + upLamp[i] * avgSpace + boardSpace / 2;
                    else
                        boardWidth = upLamp[i] * avgSpace + 2 * boardSpace / 2 - edgesBoard;

                    ctx.rect(boardTox,boardtoy,boardWidth, boardHeight);

                    boardTox += boardWidth + 5;

                    ctx.stroke();
                    for(var j = 0;j < upLamp[i];j++)
                    {
                        tox = avgSpace * lampNum + (avgSpace - rectWidth) / 2 + edgesBoard + i * boardSpace;
                        toy = edgesBoard + 5;
                        ctx.beginPath();
                        if(rectWidth > 6)
                            ctx.lineWidth = 0.5;
                        else
                            ctx.lineWidth = 0.25;

                        if(rectWidth > 3)
                            ctx.strokeStyle = "black";
                        else
                            ctx.strokeStyle = upLampColor[lampNum];

                        ctx.fillStyle = upLampColor[lampNum];
                        ctx.rect(tox,toy, rectWidth, rectHeight);
                        ctx.fill();
                        if(rectWidth > 3)
                            ctx.stroke();
                        lampNum++;

                    }
                }
                var lineCount = 3;
                lampNum = 0;
                for(i = 0;i < upBoard - 1;i++)
                {
                    lampNum += upLamp[i]
                    for(var k = 0;k < lineCount;k++)
                    {
                        ctx.beginPath();
                        ctx.moveTo(lampNum * avgSpace + boardSpace * i + edgesBoard ,(pltUpCanvas.height - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard);
                        ctx.lineWidth = 3;
                        ctx.strokeStyle = upConnectorColor[i];
                        ctx.lineTo(lampNum * avgSpace  + boardSpace * (i + 1) + edgesBoard,(pltUpCanvas.height - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard);
                        ctx.stroke();
                    }
                }
                touch.paintUnlock();
            }
        }
    }

        Rectangle
        {
            id:leftRect
            x:defaultMargin
            y:defaultMargin + edgesSize
            height:pltWindowID.height - 2 * (defaultMargin + edgesSize)
            width:edgesSize

            color:"#D5D5D5"
            border.width: edgesBoard
            border.color: edgesBoardColor

            Canvas
            {
                id:pltLeftCanvas
                anchors.fill: parent
                onPaint:
                {
                    touch.paintLock();
                    var ctx = pltLeftCanvas.getContext("2d");
                    ctx.reset();

                    var avgSpace = (pltLeftCanvas.height - (leftBoard - 1)* boardSpace - 2 * edgesBoard) / leftAllLampCount ;
                    var rectHeight ;
                    if(avgSpace >= pltLeftCanvas.width - 2 * edgesBoard - 10)
                        rectHeight = pltLeftCanvas.width - 2 * edgesBoard - 10;
                    else
                        rectHeight = avgSpace - 4;

                    var rectWidth = pltLeftCanvas.width - 2 * edgesBoard - 10;

                    var tox, toy;
                    var lampNum = 0;
                   var boardTox = 0;
                   var boardToy = 0;
                   var boardWidth = pltLeftCanvas.width;
                   var boardHeight ;
                    for(var i = 0;i < leftBoard;i++)
                    {
                        ctx.beginPath();
                        ctx.lineWidth = edgesBoard;
                        ctx.strokeStyle = leftBoardColor[i];
                        if(i === 0)
//                            boardHeight = edgesBoard + leftLamp[i] * avgSpace + boardSpace / 2 - edgesBoard;
                            boardHeight =  leftLamp[i] * avgSpace + boardSpace / 2  ;
                        else if(i === leftBoard - 1)
                            boardHeight = edgesBoard + leftLamp[i] * avgSpace + boardSpace / 2;
                        else
                            boardHeight = leftLamp[i] * avgSpace + boardSpace - edgesBoard;

//                        ctx.rect(boardTox,boardToy,boardWidth, boardHeight);
                         ctx.rect(boardTox,pltLeftCanvas.height - boardHeight - boardToy,boardWidth, boardHeight);

                        boardToy += boardHeight + edgesBoard;

                        ctx.stroke();
                        for(var j = 0;j < leftLamp[i];j++)
                        {
                            tox = edgesBoard + 5;
//                            toy = avgSpace * lampNum + (avgSpace - rectHeight) / 2 + edgesBoard + i * boardSpace;
                            toy = pltLeftCanvas.height - (edgesBoard + avgSpace * (lampNum + 1) - (avgSpace - rectHeight) / 2 + i * boardSpace)
                            ctx.beginPath();
                            if(rectHeight > 6)
                                ctx.lineWidth = 0.5;
                            else
                                ctx.lineWidth = 0.25;
                            if(rectHeight > 3)
                                ctx.strokeStyle = "black";
                            else
                                ctx.strokeStyle = leftLampColor[lampNum];

                            ctx.fillStyle = leftLampColor[lampNum];
                            ctx.rect(tox,toy, rectWidth, rectHeight);
                            ctx.fill();
                            if(rectHeight > 3)
                                ctx.stroke();

                            lampNum++;
                        }
                    }
                    var lineCount = 3;
                    lampNum = 0;
                    for(i = 0;i < leftBoard - 1;i++)
                    {
                        lampNum += leftLamp[i];
                        for(var k = 0;k < lineCount;k++)
                        {
                            ctx.beginPath();
                            ctx.moveTo((pltLeftCanvas.width - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard,pltLeftCanvas.height - (lampNum * avgSpace + boardSpace * i + edgesBoard) );
                            ctx.lineWidth = 3;
                            ctx.strokeStyle = leftConnectorColor[i];
                            ctx.lineTo((pltLeftCanvas.width - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard,pltLeftCanvas.height - (lampNum * avgSpace  + boardSpace * (i + 1) + edgesBoard));
                            ctx.stroke();
                        }
                    }
                    touch.paintUnlock();
                }
            }
        }
        Rectangle
        {
            id:midRect
            x:defaultMargin + edgesSize
            y:defaultMargin + edgesSize
            height: pltWindowID.height - 2 * (defaultMargin + edgesSize)
            width: pltWindowID.width - 2 * (defaultMargin + edgesSize)

            Text
            {
                anchors.centerIn: parent
                id:midRectText
                font.pixelSize: 30
                color: "blue"
                text:midRecttextString
            }


        }
        Rectangle
        {
            id:rightRect
            x:pltWindowID.width - (defaultMargin + edgesSize);
            y:defaultMargin + edgesSize
            height:pltWindowID.height - 2 * (defaultMargin + edgesSize)
            width:edgesSize
            border.width: edgesBoard
            border.color: edgesBoardColor

            Canvas
            {
                id:pltRightCanvas
                anchors.fill: parent
                onPaint:
                {
                    touch.paintLock();
                    var ctx = pltRightCanvas.getContext("2d");
                    ctx.reset();

                    var avgSpace = (pltRightCanvas.height - (rightBoard - 1)* boardSpace - 2 * edgesBoard) / rightAllLampCount ;
                    var rectHeight ;
                    if(avgSpace >= pltRightCanvas.width - 2 * edgesBoard - 10)
                        rectHeight = pltRightCanvas.width - 2 * edgesBoard - 10;
                    else
                        rectHeight = avgSpace - 4;

                    var rectWidth = pltRightCanvas.width - 2 * edgesBoard - 10;

                    var tox, toy;
                    var lampNum = 0;
                    var boardTox = 0;
                    var boardToy = 0;
                    var boardWidth = pltRightCanvas.width;
                    var boardHeight ;
                    for(var i = 0;i < rightBoard;i++)
                    {
                        ctx.beginPath();
                        ctx.lineWidth = edgesBoard;
                        ctx.strokeStyle = rightBoardColor[i];
                        if(i === 0)
//                            boardHeight = edgesBoard + leftLamp[i] * avgSpace + boardSpace / 2 - edgesBoard;
                            boardHeight =  rightLamp[i] * avgSpace + boardSpace / 2  ;
                        else if(i === rightBoard - 1)
                            boardHeight = edgesBoard + rightLamp[i] * avgSpace + boardSpace / 2;
                        else
                            boardHeight = rightLamp[i] * avgSpace + boardSpace - edgesBoard;

//                        ctx.rect(boardTox,boardToy,boardWidth, boardHeight);
                         ctx.rect(boardTox,pltRightCanvas.height - boardHeight - boardToy,boardWidth, boardHeight);

                        boardToy += boardHeight + edgesBoard;

                        ctx.stroke();
                        for(var j = 0;j < rightLamp[i];j++)
                        {
                            tox = edgesBoard + 5;
                            toy = pltRightCanvas.height - (edgesBoard + avgSpace * (lampNum + 1) - (avgSpace - rectHeight) / 2 + i * boardSpace)
                            ctx.beginPath();
                            if(rectHeight > 6)
                                ctx.lineWidth = 0.5;
                            else
                                ctx.lineWidth = 0.25;

                            if(rectHeight > 2)
                                ctx.strokeStyle = "black";
                            else
                            {
                                if(rightLampColor[lampNum] === "white")
                                {
                                    ctx.strokeStyle = "black";
                                }
                                else
                                {
                                    ctx.strokeStyle = rightLampColor[lampNum];
                                }
                            }


                            ctx.fillStyle = rightLampColor[lampNum];
                            ctx.rect(tox,toy, rectWidth, rectHeight);
                            ctx.fill();
                            ctx.stroke();

                            lampNum++;
                        }
                    }
                    var lineCount = 3;
                    lampNum = 0;
                    for(i = 0;i < rightBoard - 1;i++)
                    {
                        lampNum += rightLamp[i];
                        for(var k = 0;k < lineCount;k++)
                        {
                            ctx.beginPath();
                            ctx.moveTo((pltRightCanvas.width - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard,pltRightCanvas.height - (lampNum * avgSpace + boardSpace * i + edgesBoard));
                            ctx.lineWidth = 3;
                            ctx.strokeStyle = rightConnectorColor[i];
                            ctx.lineTo((pltRightCanvas.width - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard,pltRightCanvas.height - (lampNum * avgSpace  + boardSpace * (i + 1) + edgesBoard));
                            ctx.stroke();
                        }
                    }
                    touch.paintUnlock();
                }
            }

        }


    Rectangle
    {
        id:downRect
        height: edgesSize
        width:parent.width - 2 * (defaultMargin + edgesSize)

        border.width: edgesBoard
        border.color: edgesBoardColor
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottomMargin: defaultMargin
        anchors.leftMargin: defaultMargin + edgesSize
        anchors.rightMargin: defaultMargin + edgesSize

        Canvas
        {
            id:pltDownCanvas
            anchors.fill: parent
            onPaint:
            {
                touch.paintLock();
                var ctx = pltDownCanvas.getContext("2d");
                ctx.reset();

                var avgSpace = (pltDownCanvas.width - (downBoard - 1)* boardSpace - edgesBoard * 2) / downAllLampCount;

                var rectWidth ;
                if(avgSpace >= pltDownCanvas.height - 2 * edgesBoard - 10)
                    rectWidth = pltDownCanvas.height - 2 * edgesBoard - 10;
                else
                    rectWidth = avgSpace - 4;

                var rectHeight = pltDownCanvas.height - 2 * edgesBoard - 10;

                var tox, toy;
                var lampNum = 0;
                var boardTox = 0;
                var boardtoy = 0;
                var boardWidth;
                var boardHeight = pltDownCanvas.height;
                for(var i = 0;i < downBoard;i++)
                {
                    ctx.beginPath();
                    ctx.lineWidth = edgesBoard;
                    ctx.strokeStyle = downBoardColor[i];
                    if(i === 0)
                        boardWidth = edgesBoard + downLamp[i] * avgSpace + boardSpace / 2 - edgesBoard;
                    else if(i === downBoard - 1)
                        boardWidth = edgesBoard + downLamp[i] * avgSpace + boardSpace / 2;
                    else
                        boardWidth = downLamp[i] * avgSpace + 2 * boardSpace / 2 - edgesBoard;

                    ctx.rect(boardTox,boardtoy,boardWidth, boardHeight);

                    boardTox += boardWidth + 5;

                    ctx.stroke();
                    for(var j = 0;j < downLamp[i];j++)
                    {
                        tox = avgSpace * lampNum + (avgSpace - rectWidth)/2 + edgesBoard + i * boardSpace;
                        toy = edgesBoard + 5;
                        ctx.beginPath();
                        if(rectWidth > 6)
                            ctx.lineWidth = 0.5;
                        else
                            ctx.lineWidth = 0.25;
                        if(rectWidth > 2)
                            ctx.strokeStyle = "black";
                        else
                        {
                            if(downLampColor[lampNum] === "white")
                            {
                                ctx.strokeStyle = "black";
                            }
                            else
                            {
                                ctx.strokeStyle = downLampColor[lampNum];
                            }

                        }


                        ctx.fillStyle = downLampColor[lampNum];
                        ctx.rect(tox,toy, rectWidth, rectHeight);
                        ctx.fill();
                        ctx.stroke();
                        lampNum++;
                    }
                }
                var lineCount = 3;
                lampNum = 0;
                for(i = 0;i < downBoard - 1;i++)
                {
                    lampNum += downLamp[i];
                    for(var k = 0;k < lineCount;k++)
                    {
                        ctx.beginPath();
                        ctx.moveTo(lampNum * avgSpace + boardSpace * i + edgesBoard,(pltDownCanvas.height - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard);
                        ctx.lineWidth = 3;
                        ctx.strokeStyle = downConnectorColor[i];
                        ctx.lineTo(lampNum * avgSpace  + boardSpace * (i + 1) + edgesBoard,(pltUpCanvas.height - 2 * edgesBoard)/(lineCount +1 ) *(k+1) + edgesBoard);
                        ctx.stroke();
                    }
                }
                touch.paintUnlock();
            }
        }

    }
    Rectangle
    {
        id:leftUpConnector
        x:defaultMargin
        y:defaultMargin
        height:edgesSize
        width:edgesSize

        Canvas
        {
           id: leftUpConnectorCanvas
           anchors.fill: parent
           onPaint:
           {
               touch.paintLock();
               var ctx = leftUpConnectorCanvas.getContext("2d");
               ctx.reset();
               var tox = leftUpConnectorCanvas.width;
               var toy = leftUpConnectorCanvas.height;
               for(var i = 1;i <= 3;i++)
               {
                   var radius = edgesSize -10*i;
                   ctx.beginPath();
                   ctx.lineWidth = 3;
                   ctx.strokeStyle = leftUpConnectorColor;
                   ctx.arc(tox, toy, radius, 180, Math.PI/2, false);
                   ctx.stroke();
               }
               touch.paintUnlock();
           }
        }
    }
    Rectangle
    {
        id:leftDownConnector
        x:defaultMargin
        y:defaultMargin + edgesSize + leftRect.height
        height:edgesSize
        width:edgesSize

        Canvas
        {
           id: leftDownConnectorCanvas
           anchors.fill: parent
           onPaint:
           {
               touch.paintLock();
               var ctx = leftDownConnectorCanvas.getContext("2d");
               ctx.reset();
               var tox = leftDownConnectorCanvas.width;
               var toy = 0;
               for(var i = 1;i <= 3;i++)
               {
                   var radius = edgesSize -10*i;
                   ctx.beginPath();
                   ctx.lineWidth = 3;
                   ctx.strokeStyle = leftDownConnectorColor;
                   ctx.arc(tox, toy, radius, 90, Math.PI/2, false);
                   ctx.stroke();
               }
               touch.paintUnlock();
           }
        }
    }
    Rectangle
    {
        id:rightDownConnector
        x:defaultMargin + edgesSize + downRect.width
        y:defaultMargin + edgesSize + rightRect.height
        height:edgesSize
        width:edgesSize

        Canvas
        {
           id: rightDownConnectorCanvas
           anchors.fill: parent
           onPaint:
           {
               touch.paintLock();
               var ctx = rightDownConnectorCanvas.getContext("2d");
               ctx.reset();
               var tox = 0;
               var toy = 0;
               for(var i = 1;i <= 3;i++)
               {
                   var radius = edgesSize -10*i;
                   ctx.beginPath();
                   ctx.lineWidth = 3;
                   ctx.strokeStyle = rightDownConnectorColor;
                   ctx.arc(tox, toy, radius, 0, Math.PI/2, false);
                   ctx.stroke();
               }
               touch.paintUnlock();
           }
        }
    }
    Rectangle
    {
        id:numUp
        x:defaultMargin + edgesSize
        y:0
        height: defaultMargin
        width: upRect.width

        Canvas
        {
            id:numupCanvas
            anchors.fill: parent
             onPaint:
             {
                 touch.paintLock();
                 var ctx = numupCanvas.getContext("2d");
                 ctx.reset();
                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc((numupCanvas.height - 4)/2 + 20, numupCanvas.height / 2,(numupCanvas.height - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 4 ,(numupCanvas.height - 4)/2 + 13,numupCanvas.height - 4);

                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc(numupCanvas.width - (numupCanvas.height - 4)/2 - 20, numupCanvas.height / 2,(numupCanvas.height - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 5 ,numupCanvas.width - (numupCanvas.height - 4)/2 - 27,numupCanvas.height - 4);

                 touch.paintUnlock();
             }
        }
    }
    Rectangle
    {
        id:numDown
        x:defaultMargin + edgesSize
        y:parent.height - defaultMargin
        height: defaultMargin
        width: downRect.width

        Canvas
        {
            id:numDownCanvas
            anchors.fill: parent
             onPaint:
             {
                 touch.paintLock();
                 var ctx = numDownCanvas.getContext("2d");
                 ctx.reset();
                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc((numDownCanvas.height - 4)/2 + 20, numDownCanvas.height / 2,(numDownCanvas.height - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 1 ,(numDownCanvas.height - 4)/2 + 13,numDownCanvas.height - 4);

                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc(numDownCanvas.width - (numDownCanvas.height - 4)/2 - 20, numDownCanvas.height / 2,(numDownCanvas.height - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 8 ,numDownCanvas.width - (numDownCanvas.height - 4)/2 - 27,numDownCanvas.height - 4);

                 touch.paintUnlock();
             }
        }
    }
    Rectangle
    {
        id:numLeft
        x:0
        y:edgesSize + defaultMargin
        height: leftRect.height
        width: defaultMargin

        Canvas
        {
            id:numLeftCanvas
            anchors.fill: parent
             onPaint:
             {
                 touch.paintLock();
                 var ctx = numLeftCanvas.getContext("2d");
                 ctx.reset();
                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc( numLeftCanvas.width/2, (numLeftCanvas.width -4)/ 2 + 20,(numLeftCanvas.width - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 3 ,7,20 + numLeftCanvas.width - 7);

                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc(numLeftCanvas.width/2,numLeftCanvas.height - (numLeftCanvas.width - 4)/2 - 20,(numLeftCanvas.width - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 2 , 7,numLeftCanvas.height - 23);

                 touch.paintUnlock();
             }
        }
    }
    Rectangle
    {
        id:numRight
        x:parent.width - defaultMargin
        y:edgesSize + defaultMargin
        height: leftRect.height
        width: defaultMargin

        Canvas
        {
            id:numRightCanvas
            anchors.fill: parent
             onPaint:
             {
                 touch.paintLock();
                 var ctx = numRightCanvas.getContext("2d");
                 ctx.reset();
                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc( numRightCanvas.width/2, (numRightCanvas.width -4)/ 2 + 20,(numRightCanvas.width - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 6 ,7,20 + numRightCanvas.width - 7);

                 ctx.beginPath();
                 ctx.lineWidth = 1;
                 ctx.strokeStyle = "black";
                 ctx.arc(numRightCanvas.width/2,numRightCanvas.height - (numRightCanvas.width - 4)/2 - 20,(numRightCanvas.width - 4)/2, 0, Math.PI*2, true)
                 ctx.stroke();
                 ctx.fillStyle = "blue";
                 ctx.font='bold 25px 微软雅黑';
                 ctx.fillText("" + 7 , 7,numRightCanvas.height - 23);

                 touch.paintUnlock();
             }
        }
    }



    onVisibleChanged:
    {
        if(visible)
        {
            emptyData();
            initStandardColor();
            getAllBoardAttributeData();
            initplatLoadTestColor();
            midRecttextString = "正在检测!请使用1点触摸!";

            refreshCanvas();
        }
        else
        {
            emptyData();
        }
    }

    function emptyData()
    {
        downBoard = 0;
        downBoardOrder.length = 0;
        downBoardColor.length = 0;
        downLamp.length = 0;
        downAllLampCount = 0;
        downLampColor.length = 0;
        downConnectorColor.length = 0;
        downBoardState.length = 0;
        downLampState.length = 0;


        rightBoard = 0;
        rightBoardOrder.length = 0;
        rightBoardColor.length = 0;
        rightLamp.length = 0;
        rightAllLampCount = 0;
        rightLampColor.length = 0;
        rightConnectorColor.length = 0;
        rightBoardState.length = 0;
        rightLampState.length = 0;


        upBoard = 0;
        upBoardOrder.length = 0;
        upBoardColor.length = 0;
        upLamp.length = 0;
        upAllLampCount = 0;
        upLampColor.length = 0;
        upConnectorColor.length = 0;
        upBoardState.length = 0;
        upLampState.length = 0;

        leftBoard = 0;
        leftBoardOrder.length = 0;
        leftBoardColor.length = 0;
        leftLamp.length = 0;
        leftAllLampCount = 0;
        leftLampColor.length = 0;
        leftConnectorColor.length = 0;
        leftBoardState.length = 0;
        leftLampState.length = 0;
    }
    function refreshCanvas()
    {
        pltUpCanvas.requestPaint();
        pltDownCanvas.requestPaint();
        pltLeftCanvas.requestPaint();
        pltRightCanvas.requestPaint();
        leftUpConnectorCanvas.requestPaint();
        leftDownConnectorCanvas.requestPaint();
        rightDownConnectorCanvas.requestPaint();
        numDownCanvas.requestPaint();
    }

    function initplatLoadTestColor()
    {
        var z;
        for(z = 0;z < upBoard;z++)
        {
            upBoardColor[z] = edgesBoardColor;
            if(z < upBoard -1)
                upConnectorColor[z] = "gray"
        }

        for(z = 0;z < downBoard;z++)
        {
            downBoardColor[z] = edgesBoardColor;
            if(z < upBoard -1)
                downConnectorColor[z] = "gray"
        }

        for(z = 0;z < leftBoard;z++)
        {
            leftBoardColor[z] = edgesBoardColor;
            if(z < leftBoard -1)
                leftConnectorColor[z] = "gray"
        }

        for(z = 0;z < rightBoard;z++)
        {
            rightBoardColor[z] = edgesBoardColor;
            if(z < rightBoard -1)
                rightConnectorColor[z] = "gray"
        }

        for(z = 0;z < upAllLampCount;z++)
        {
            upLampColor[z] = "black";
        }

        for(z = 0;z < downAllLampCount;z++)
        {
            downLampColor[z] = "white"
        }

        for(z = 0;z < leftAllLampCount;z++)
        {
            leftLampColor[z] = "black";

        }

        for(z = 0;z < rightAllLampCount;z++)
        {
            rightLampColor[z] = "white";
        }
    }
    function getAllBoardAttributeData()
    {
        var U = 0;
        var D = 0;
        var L = 0;
        var R = 0
        var items;
        var attritubeData;
        var boardAttribute;
        if(touch)
        {
            var boardData = touch.getBoardAndLampData();
            var result = boardData["result"];
            if(result === 0)
            {
                items = boardData["items"];
                console.log("items.length = " + items.length)

                attritubeData = boardData["attritubeData"];
                downBoard = 0;
                upBoard = 0;
                leftBoard = 0;
                rightBoard = 0;

                for(var i = 0;i < items.length;i++)
                {
                    boardAttribute = attritubeData[i];

                    if(boardAttribute["direction"] === 0x00)
                    {
                        downBoard++;
                        downBoardOrder[D++] = boardAttribute["order"];

                    }
                    else if(boardAttribute["direction"] === 0x01)
                    {
                        leftBoard++;
                        leftBoardOrder[L++] = boardAttribute["order"];

                    }
                    else if(boardAttribute["direction"] === 0x02)
                    {
                        upBoard++;
                        upBoardOrder[U++] = boardAttribute["order"];

                    }
                    else if(boardAttribute["direction"] === 0x03)
                    {
                        rightBoard++;
                        rightBoardOrder[R++] = boardAttribute["order"];
                    }
                }
                var j,k;
               for(j = 0;j < downBoard;j++)
               {
                   for(k = 0;k < downBoard - j - 1;k++)
                   {
                       if(downBoardOrder[k] > downBoardOrder[k+1])
                       {
                           downBoardOrder[k+1] = downBoardOrder[k+1] ^ downBoardOrder[k];
                           downBoardOrder[k] = downBoardOrder[k+1] ^ downBoardOrder[k];
                           downBoardOrder[k+1] = downBoardOrder[k+1] ^ downBoardOrder[k];
                       }
                   }
               }
               for(j = 0;j < leftBoard;j++)
               {
                   for(k = 0;k < leftBoard - j - 1;k++)
                   {
                       if(leftBoardOrder[k] > leftBoardOrder[k+1])
                       {
                           leftBoardOrder[k+1] = leftBoardOrder[k+1] ^ leftBoardOrder[k];
                           leftBoardOrder[k] = leftBoardOrder[k+1] ^ leftBoardOrder[k];
                           leftBoardOrder[k+1] = leftBoardOrder[k+1] ^ leftBoardOrder[k];

                       }
                   }
               }
               for(j = 0;j < upBoard;j++)
               {
                   for(k = 0;k < upBoard - j - 1;k++)
                   {
                       if(upBoardOrder[k] > upBoardOrder[k+1])
                       {
                           upBoardOrder[k+1] = upBoardOrder[k+1] ^ upBoardOrder[k];
                           upBoardOrder[k] = upBoardOrder[k+1] ^ upBoardOrder[k];
                           upBoardOrder[k+1] = upBoardOrder[k+1] ^ upBoardOrder[k];
                       }
                   }
               }
               for(j = 0;j < rightBoard;j++)
               {
                   for(k = 0;k < rightBoard - j - 1;k++)
                   {
                       if(rightBoardOrder[k] > rightBoardOrder[k+1])
                       {
                           rightBoardOrder[k+1] = rightBoardOrder[k+1] ^ rightBoardOrder[k];
                           rightBoardOrder[k] = rightBoardOrder[k+1] ^ rightBoardOrder[k];
                           rightBoardOrder[k+1] = rightBoardOrder[k+1] ^ rightBoardOrder[k];


                       }
                   }
               }

               for(j = 0;j < downBoard;j++)
               {
                   for(i = 0;i < items.length;i++)
                   {
                       boardAttribute = attritubeData[i];
                       if(boardAttribute["order"] === downBoardOrder[j] && boardAttribute["direction"] === 0x00)
                       {
                           downLamp.push(boardAttribute["lampCount"]);
                           downAllLampCount += boardAttribute["lampCount"];
                           break;
                       }
                   }
               }
               for(j = 0;j < leftBoard;j++)
               {
                   for(i = 0;i < items.length;i++)
                   {
                       boardAttribute = attritubeData[i];
                       if(boardAttribute["order"] === leftBoardOrder[j] && boardAttribute["direction"] === 0x01)
                       {
                           leftLamp.push(boardAttribute["lampCount"]);
                           leftAllLampCount += boardAttribute["lampCount"];
                           break;
                       }
                   }
               }
               for(j = 0;j < upBoard;j++)
               {
                   for(i = 0;i < items.length;i++)
                   {
                       boardAttribute = attritubeData[i];
                       if(boardAttribute["order"] === upBoardOrder[j] && boardAttribute["direction"] === 0x02)
                       {
                           upLamp.push(boardAttribute["lampCount"]);
                           upAllLampCount += boardAttribute["lampCount"];
                           break;
                       }
                   }
               }
               for(j = 0;j < rightBoard;j++)
               {
                   for(i = 0;i < items.length;i++)
                   {
                       boardAttribute = attritubeData[i];
                       if(boardAttribute["order"] === rightBoardOrder[j] && boardAttribute["direction"] === 0x03)
                       {
                           rightLamp.push(boardAttribute["lampCount"]);
                           rightAllLampCount += boardAttribute["lampCount"];
                           break;
                       }
                   }
               }

            }
        }

    }
    function initStandardColor()
    {
        standardColor[0] = "red";
        standardColor[1] = "yellow";
//        standardColor[2] = "gray"
        standardColor[3] = "blue";
        standardColor[4] = "#009707";
    }
    function setMidRectText(title,message,type)
    {
        onboardtestShowDialog(title,message,type);
//        midRecttextString = message;
    }
    function mrefreshOnboardTestData(map)
    {
//        console.log("mrefreshOnboardTestData@@@@@@@@@@")
        var i;
        if(touch)
        {
            downBoardState = map["downBoardState"];
            downLampState = map["downLampState"];
            upBoardState = map["upBoardState"];
            upLampState = map["upLampState"];
            leftBoardState = map["leftBoardState"];
            leftLampState = map["leftLampState"];
            rightBoardState = map["rightBoardState"];
            rightLampState = map["rightLampState"];

            for(i = 0;i < downLampState.length;i++)
            {
                if(downLampState[i] === 2)
                    continue;
                downLampColor[i] = standardColor[downLampState[i]];
            }
            for(i = 0;i < leftLampState.length;i++)
            {
                if(leftLampState[i] === 2)
                    continue;
                leftLampColor[i] = standardColor[leftLampState[i]];
            }
            for(i = 0;i < upLampState.length;i++)
            {
                if(upLampState[i] === 2)
                    continue;
                upLampColor[i] = standardColor[upLampState[i]];
            }
            for(i = 0;i < rightLampState.length;i++)
            {
                if(rightLampState[i] === 2)
                    continue;
                rightLampColor[i] = standardColor[rightLampState[i]];
            }

            for(i = 0;i < downBoardState.length;i++)
            {
                if(downBoardState[i] === 2)
                    continue;
                downBoardColor[i] = standardColor[downBoardState[i]];
            }
            for(i = 0;i < leftBoardState.length;i++)
            {
                if(leftBoardState[i] === 2)
                    continue;
                leftBoardColor[i] = standardColor[leftBoardState[i]];
            }
            for(i = 0;i < upBoardState.length;i++)
            {
                if(upBoardState[i] === 2)
                    continue;
                upBoardColor[i] = standardColor[upBoardState[i]];
            }
            for(i = 0;i < rightBoardState.length;i++)
            {
                if(rightBoardState[i] === 2)
                    continue;
                rightBoardColor[i] = standardColor[rightBoardState[i]];
            }


            refreshCanvas();
//            printfColorValue();
        }

    }
    function printfColorValue()
    {
        var i = 0;
        for(i = 0;i < downLampColor.length;i++)
        {
            console.log("downLampColor[" + i + "]  = " + downLampColor[i]);
        }
        for(i = 0;i < leftLampColor.length;i++)
        {
            console.log("leftLampColor[" + i + "]  = " + leftLampColor[i]);
        }
        for(i = 0;i < upLampColor.length;i++)
        {
            console.log("upLampColor[" + i + "]  = " + upLampColor[i]);
        }
        for(i = 0;i < rightLampColor.length;i++)
        {
            console.log("rightLampColor[" + i + "]  = " + rightLampColor[i]);
        }

        for(i = 0;i < downBoardColor.length;i++)
        {
            console.log("downBoardColor[" + i + "]  = " + downBoardColor[i]);
        }
        for(i = 0;i < leftBoardColor.length;i++)
        {
            console.log("leftBoardColor[" + i + "]  = " + leftBoardColor[i]);
        }
        for(i = 0;i < upBoardColor.length;i++)
        {
            console.log("upBoardColor[" + i + "]  = " + upBoardColor[i]);
        }
        for(i = 0;i < rightBoardColor.length;i++)
        {
            console.log("rightBoardColor[" + i + "]  = " + rightBoardColor[i]);
        }
    }
    function onboardtestShowDialog(title, msg, type)
    {
        midRecttextString = msg;
        console.log("PlateLoadTest  showDialog =======================")
        var tt = Qt.createComponent("qrc:qml/ui/TDialog.qml");

        if (tt.errorString())
            touch.error("chart erros:" + tt.errorString());
        tt = tt.createObject(pltWindowID);
        tt.showMessage({
                           title: title,
                           message: msg,
                           icon: type,
                           accpetText: qsTr("close"),
                           showCancel: false
                       })

    }
    Component.onCompleted:
    {
        mainPage.sendOnboardTestFinish.connect(setMidRectText);
        mainPage.sendRefreshOnboardTestData.connect(mrefreshOnboardTestData);
        mainPage.sendOnboardTestShowDialog.connect(onboardtestShowDialog);
        mainPage.sendCloseOnboardTestWindow.connect(closePlateLoadtest);
    }
    function closePlateLoadtest()
    {
        pltWindowID.close();
    }

    onClosing:
    {
        touch.setTestThreadToStop(true);
//        if(!_exit)
//        {
//            close.accepted = false;
//            pltWindowID.visible = false;
//        }

//        else
//            close.accepted = true;

    }



}
*/
