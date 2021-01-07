import QtQuick 2.0
import QtQuick.Window 2.2
import QtQuick.Controls 1.4
import QtQuick.Controls 2.0 as Cont2
import QtQuick.Controls.Styles 1.4
import QtQuick.Dialogs 1.1
import QtQuick.Layouts 1.3


import TouchPresenter 1.0
import QDrawPanel 1.0
import "qml/ui"


Window {
    property int buttonMinWidth: 150
    property int buttonMinHeight:60
    property int fontSize: 12
    property int marginWidth: 20
    property int defaultMargin: 10
    property int minMargin: 5

    property int chart_width: 300;
    property int chart_height: 300;
    property int chart_spacing: 20;
    property int text_height: 80;
    property int row_height: 8;

    property int mWidth: 980;
    property int mHeight: 680;
    property int passAgingTime: 10
    property bool setTest: defaultSetTest

    id: mainPage
    visible:true
    width: mWidth
    height: mHeight
    visibility: Window.Maximized

    // see also TouchTool.h
    property int mAPP_Factory: 0
    property int mAPP_Client: 1
    property int mAPP_RD: 2
    property int mAPP_PCBA: 3

    property int mTAB_Upgrade: 0
    property int mTAB_Test: 1
    property int mTAB_Signal: 2
    property int mTAB_Info: 3
    property int mTAB_Settings: 4
    property int mTAB_Palette: 5
    property int mTAB_Aging: 6
    property int deviceCount: 0

    title: qsTr("TouchAssistant")

    property var confirmStopAging: qsTr("sure to stop aging?")

    property string messageTextStringUpdate: ""
    property string messageTextStringTest: ""
    property string messageTextString: ""

    property real windowWidth: mWidth
    property real windowHeight: mHeight

    property string aboutInfo:""
    property string deviceInfoString: ""
    property string deviceInfoName:""
    property string softwareInfoName:""
    property string softwareInfo:""
    property int deviceHeight:0
    property int deviceWidth:0
    property int deviceInfoHeight:50

    property alias updateComBoxId:updatePage.updateComBoxId
    property var messageBox: (mainTabView.currentIndex === 0 || testPage === null ) ? updatePage.messageBox : testPage.messageBox
    property var messageView: (mainTabView.currentIndex === 0 || testPage === null) ? updatePage.messageView : testPage.messageView

    property int lastTabIndex: 0
    function onDestroyed() {
        signalPageTab.restoreCoordsOrNot();
    }
    property bool updatingFw: false
    property bool testingFw: false
    property string testBtnName: "Test"
    property bool isSupportOnboardtest:false
    property bool showPage:false
//    property var testMessage : ""
    property int testMessagLength : 0
    property var testMessage : []
    property int maxMessageLeng:15000

//    property var updateMessage:""
    property var updateMessage:[]
    property int updateMessageLength:0
    property var upgradeShowStr:""
    property int tabViewHeight:Math.max(Math.min(windowHeight / 5.0,tabHeight),20)


    signal sendOnboardTestFinish(var title,var message,var type);
    signal sendRefreshOnboardTestData(var map);
    signal sendOnboardTestShowDialog(var title,var msg,var type);
    signal sendCloseOnboardTestWindow();
    signal sendDestroyDialog();

    Rectangle {
        anchors.fill: parent
        Keys.enabled: true
        focus: true
        Keys.onPressed: {
        }
        Keys.forwardTo: [calibrationUi]
        TabView {//一个可以切换界面的窗口
            id: mainTabView
            anchors.fill: parent
            anchors.margins: (mainPage.visibility === 5) ? 0 : defaultMargin
            tabsVisible: (mainPage.visibility === 5 || updatingFw || testingFw) ? false : true
            Keys.enabled: false
            KeyNavigation.tab: null
//            onFocusChanged: console.log("focus:" + focus)
//            onTabPositionChanged: {
////                drawPage
//            }
//            tabsVisible: updatePage.updateButton.enabled
            onCurrentIndexChanged: {
                var item = getTab(currentIndex);
                if (item.what !== undefined && item.what === mTAB_Palette) {
                    currentIndex = 0;
                    touch.run("drawpanel.exe");

                }
                if(item.what !== mTAB_Test)
                {
//                    onboardTest.visible = false;
                    testProgressBar.value = 0;
                    isSupportOnboardtest = false;
                }

                lastTabIndex = currentIndex;
            }

            Tab {
                title: qsTr("Upgrade")
                id: updatePage
                anchors.fill: parent
                property Item updateButton: item.upgradeBtn

                property Item updateComBoxId:item.updateComBoxId
                property string messageText: item.messageText.text
                property Item messageView: item.messageText
                property Item messageBox: item.messageBox
                property Item upgradeProgressBar: item.upgradeProgressBar
                property Item updateShowMsgId:item.updateShowMsgId
                property Item updateShowDialog:item.updateShowDialog

                property int what: mTAB_Upgrade
                property bool flag: true
                property int messageBoxWidth:updateShowMsgId.width
                property int showDialogWidth:0


                Rectangle {
                    property Item upgradeBtn: upgradeBtn

                    property Item updateComBoxId:updateComBoxId
                    property Item messageText: messageText
                    property Item messageBox:item.messageBox
                    property Item upgradeProgressBar: upgradeProgressBar
                    property Item updateShowMsgId:updateShowMsgId
                    property Item updateShowDialog:updateShowDialog
                    anchors.fill: parent

                    ColumnLayout {//纵向布局
                        anchors.fill: parent
                        anchors.top: parent.top
                        anchors.topMargin: defaultMargin

                        RowLayout {//横向布局
                            Button{
                                id:upgradeBtn;
                                property var text: qsTr("Upgrade")
                                Layout.minimumWidth: fileSeleected.width
                                Layout.minimumHeight: fileSeleected.height
                                style: TButtonStyle {
                                    text: upgradeBtn.text

                                }

                                onEnabledChanged: {
                                    if (enabled) {
                                        text = qsTr("Upgrade");

                                        flag = true;


                                    } else {
                                        text = qsTr("During upgrade");

                                        flag = false;
                                    }
                                }

                                onClicked: {

                                    //Qt.quit();
//                                    touch.testMultiPoint();
                                    if (testChartPage != null) {
                                        touch.debug("clear models");
                                        testChartPage.clearModels();

                                    }
                                    mainPage.sendDestroyDialog();
                                    touch.startUpgrade();
//                                    updatePage.showDialogWidth = updateShowMsgId.width/2;
                                    updatePage.messageBoxWidth = updateShowMsgId.width/2;

                                }

                            }
                            ProgressBar{
                                id: upgradeProgressBar
                                minimumValue: 0;
                                maximumValue: 100;
                                value: 0;
                                Layout.preferredHeight: upgradeBtn.height
                                Layout.fillWidth: true
                                style: ProgressBarStyle {
                                    background: Rectangle {
                                        radius: 2
                                        color: "white"
                                        border.color: "gray"
                                        border.width: 1
                                        implicitWidth: 200
                                        implicitHeight: 24
                                    }
                                    progress: Rectangle {
                                        color: "#64B5F6"
                                        border.color: "#64B5F6"
                                    }
                                }
                            }
                        }
                        RowLayout {
                            Button{
                                id:fileSeleected;
//                                property color backgroundColor: ((control.enabled === true) ? ((control.pressed === true) ? "#42A5F5" : "#64B5F6") : "#BDBDBD")
                                Layout.preferredWidth: Math.min(Math.max(buttonMinWidth,upgradeTestWidth * buttonMinWidth),windowWidth / 2.0);
                                Layout.preferredHeight:Math.min(Math.max(buttonMinHeight,upgradeTestHeight * buttonMinHeight),windowHeight / 5.0);
                                style: ButtonStyle {
                                    label: Text {
                                        color: "#FFFFFF"
                                        text: qsTr("Select upgrade file")
                                        font.pointSize: Math.min(fontSize + (Math.min(upgradeTestWidth,upgradeTestHeight) - 1)*5,30)
                                        verticalAlignment: Text.AlignVCenter
                                        horizontalAlignment: Text.AlignHCenter
                                    }
                                    background: Rectangle{

                                        implicitWidth: upgradeBtn.width
                                        implicitHeight: upgradeBtn.height
                                        border.width: info.borderWidth
                                        color: (flag ? "#64B5F6":"#BDBDBD")
                                        radius: 2
                                    }
                                }



                                onClicked: {
                                    //Qt.quit();
                                    if(flag)
                                    {
                                        fileDialog.open();
                                    }
                                }

                            }

//                            Rectangle {
//                                id: upgradeFileRectangle
////                                height: fileSeleected.height
//                                implicitHeight: upgradeBtn.height;
//                                Layout.fillWidth: true
//                                border.width: 1
//                                radius: 2
//                                property Item filetext:filetext


                                ComboBox
                                {
                                    id:updateComBoxId
                                    Layout.preferredHeight: upgradeBtn.height
                                    Layout.fillWidth: true
//                                    editable: true
                                    currentIndex: 0
                                    visible: true
                                    model:fileText

                                    onCurrentTextChanged:
                                    {

                                        if(currentText === qsTr("clear history(up to ten)"))
                                        {
                                            touch.clearComboBoxData();
                                            fileText.insert(0,{"text":""});
                                            updateComBoxId.currentIndex = 0;
                                            fileText.clear();
                                            touch.setUpdatePath("");
                                        }
                                        else
                                        {
                                            touch.setUpdatePath(currentText);
                                        }

//                                        console.log("onCurrentTextChanged@@@@@@@currentText = " + currentText);
                                    }
                                    property bool firstTime:true
                                    Component.onCompleted:
                                    {
                                        if(firstTime)
                                        {
                                            firstTime = false;
                                            fileText.insert(0,{"text":qsTr("clear history(up to ten)")});
                                        }

                                    }

                                }
//                                Text {
//                                    id: fileText
//                                    anchors.left: parent.left
//                                    anchors.leftMargin: 10
//                                    width: parent.width - 10 * 2
//                                    elide: Text.ElideLeft
//                                    text: qsTr("")
//                                    font.pixelSize: 0
//                                    anchors.verticalCenter: parent.verticalCenter
//                                }

                            }
//                        }


                        Rectangle
                        {
                            border.width: 1
                            border.color: "#aaaaaa"
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            id:updateShowMsgId
                            property Item messageBox:messageBox
//                            property Item updateShowDialog:updateShowDialog
                            RowLayout
                            {
                                anchors.fill:parent
                                Rectangle
                                {
                                    border.width: 1
                                    border.color: "#aaaaaa"
//                                    Layout.preferredWidth: updatePage.messageBoxWidth
                                    Layout.preferredWidth: parent.width / 2.0
                                    Layout.preferredHeight:parent.height
                                    ScrollView {
                                        anchors.fill: parent

                                        horizontalScrollBarPolicy: Qt.ScrollBarAlwaysOff
                                        id: messageBox

                                        Text {
                                            id: messageText
//                                            renderType: Text.NativeRendering
                                            text:upgradeShowStr
                                            wrapMode: Text.Wrap
                                            onTextChanged:
                                            {
                                                if (messageText.contentHeight > messageBox.height) {
                                                    messageBox.flickableItem.contentY = messageText.contentHeight - messageBox.height;
                                                }
                                            }
                                        }


                                    }

                                }

                                Rectangle
                                {
                                    id:updateShowDialog
                                    border.width: 1
                                    border.color: "#aaaaaa"
                                    anchors.top: parent.top
                                    anchors.left: messageBox.right
                                    anchors.right: parent.right
                                    Layout.preferredWidth: parent.width / 2.0
                                    Layout.preferredHeight:parent.height
                                }
                            }

                        }
                    }

                }
                onVisibleChanged:
                {
                    if(visible)
                    {
                        touch.tPrintf("升级模式:");
//                        showPage = false;
//                        console.log("升级界面的信息：" + upgradeShowStr);
                        messageText.text = upgradeShowStr;

                    }
                        
                }
            }

            Tab {
                id: testPage;
                title: qsTr("Test")
                property Item messageView: (item !== null) ? item.messageView : null
                property Item messageBox: (item != null) ? item.messageBox : null
                property Item onboardTest:(item != null) ? item.onboardTest : null
                property Item testBtn: (item != null) ? item.testBtn : null
                property Item testProgressBar: (item != null) ? item.testProgressBar : null
                property Item testShowDialog:item.testShowDialog

                signal sendOnboardTestStart()


                property int what: mTAB_Test

                Rectangle {
                    id: rectangle
                    property Item messageView: (isSupportOnboardtest ?onboardTest.onboardTestMessage:messageTextTest)
                    property Item messageBox: (isSupportOnboardtest ? onboardTest.showFailMessage:testRect.messageBoxTest)
                    property Item testShowDialog:testShowDialog
//                    property Item messageView: onboardTest.onboardTestMessage
//                    property Item messageBox: onboardTest.showFailMessage
                    property Item onboardTest:onboardTest
                    property Item testBtn: testBtn
                    property Item testProgressBar: testProgressBar

                    anchors.fill: parent
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.top: parent.top
                        anchors.topMargin: defaultMargin
                        RowLayout {
                            Button{
                                id:testBtn;
                                checkable: true
                                Layout.preferredWidth: Math.min(Math.max(buttonMinWidth,upgradeTestWidth * buttonMinWidth),windowWidth / 2.0);
                                Layout.preferredHeight:Math.min(Math.max(buttonMinHeight,upgradeTestHeight * buttonMinHeight),windowHeight / 5.0);
                                onVisibleChanged: {
                                    if (visible) {
                                        messageTextStringUpdate = messageTextString;
                                        messageTextString = messageTextStringTest;
                                    } else {
                                        messageTextStringTest = messageTextString;
                                        messageTextString = messageTextStringUpdate;
                                    }
                                }
                                style: TButtonStyle {
                                    label: Text {
                                        color: "#FFFFFF"
                                        text:qsTr(testBtnName)
                                        font.pointSize: Math.min(fontSize + (Math.min(upgradeTestWidth,upgradeTestHeight) - 1)*5,30)
                                        verticalAlignment: Text.AlignVCenter
                                        horizontalAlignment: Text.AlignHCenter
                                    }

                                }


                                onClicked: {

                                    if(checked)
                                    {
                                        onboardTest.midRecttextString = "";
                                        isSupportOnboardtest = false;
                                        onboardTest.visible = false;
                                        testBtnName = qsTr("Cancel test");
                                        mainPage.sendDestroyDialog();
                                        touch.setTestThreadToStop(false);
                                        touch.startTest();


                                    }
                                    else
                                    {
                                        touch.cancelTest(true);
                                        mainPage.sendDestroyDialog();
                                        touch.setTestThreadToStop(true);
//                                        setTestButtonEnable(false);

                                    }

                                }

                            }
                            //测试进展的情况
                            ProgressBar{
                                id: testProgressBar
                                minimumValue: 0;
                                maximumValue: 100;
                                value: 0;
                                implicitHeight: testBtn.height;
                                Layout.fillWidth: true
                                style: ProgressBarStyle {
                                    background: Rectangle {
                                        radius: 2
                                        color: "white"
                                        border.color: "gray"
                                        border.width: 1
                                        implicitWidth: 200
                                        implicitHeight: 24
                                    }
                                    progress: Rectangle {
                                        color: "#64B5F6"
                                        border.color: "#64B5F6"
                                    }
                                }
                            }
                        }
                        Rectangle
                        {
                            id:testTextInfo
                            border.width: 1
                            border.color: "#aaaaaa"
                            Layout.fillHeight: true
                            Layout.fillWidth: true


                            OnboardTestInterface
                            {
                                id:onboardTest
                                anchors.fill: parent
                                anchors.top: parent.top
                                anchors.topMargin: 5
                                anchors.leftMargin: 5
                                anchors.rightMargin: 5
                                anchors.bottomMargin: 5
                                visible: false

                                function startOnboardTest()
                                {
                                    messageTextTest.text = " " + "\n";

                                    onboardTest.visible = true;
                                }
                                Component.onCompleted:
                                {
                                    testPage.sendOnboardTestStart.connect(startOnboardTest);
                                }
                                onVisibleChanged:
                                {
                                    messageTextTest.text = "";
                                    onboardTest.onboardTestMessage.text = "";
                                    if(visible)
                                    {
                                        onboardTest.onboardTestMessage.text += testMessage;
//                                        messageBoxTest.visible = false;
                                        testRect.visible = false;
                                    }
                                    else
                                    {

                                        testRect.visible = true;
                                        testRect.messageBoxTest.text += testMessage;
//                                        messageBoxTest.visible = true;
//                                        messageTextTest.text += testMessage;

                                    }
                                }
                            }

                            Rectangle
                            {
                                anchors.fill: parent
                                id:testRect
                                border.width: 1
                                border.color: "#aaaaaa"
                                visible: true
                                property Item messageBoxTest:messageTextTest

                                RowLayout
                                {
                                    anchors.fill: parent
                                    Rectangle
                                    {
                                        id:showMessageLog
                                        border.width: 1
                                        border.color: "#aaaaaa"
                                        Layout.preferredWidth: parent.width / 2
                                        Layout.preferredHeight: parent.height
                                        ScrollView
                                        {
                                            id: messageBoxTest
                                            anchors.fill: parent
                                            horizontalScrollBarPolicy: Qt.ScrollBarAlwaysOff

                                            Text {
                                                id: messageTextTest
                                                renderType: Text.NativeRendering
                                                onTextChanged:
                                                {
                                                    if (messageTextTest.contentHeight > messageBoxTest.height) {
                                                        messageBoxTest.flickableItem.contentY = messageTextTest.contentHeight - messageBoxTest.height;
                                                    }
                                                }
                                            }

                                        }
                                    }

                                    Rectangle
                                    {
                                        id:testShowDialog
                                        border.width: 1
                                        border.color: "#aaaaaa"
                                        anchors.top: parent.top
                                        anchors.left: showMessageLog.right
                                        anchors.right: parent.right
                                        Layout.preferredWidth: parent.width / 2.0
                                        Layout.preferredHeight:parent.height

                                    }
                                }

                            }



                        }

                    }

                }
                onVisibleChanged:
                {
                    if(visible)
                    {
                        touch.tPrintf("测试模式:");
                        showPage = true;

                        var str1 = "";
                        for(var i = 0;i < testMessage.length;i++)
                        {
                            str1 += testMessage[i];
                        }
                        messageView.text = str1;
                    }
                    else
                    {
                        showPage = false;
                    }
                }


            } // Tab test

            Tab {

                title: qsTr("Signal chart")
                id: signalPageTab
                property int what: mTAB_Signal
                property Item testChartPage: (item !== null) ? item.testChartPage : null
                property bool usbStatus: false       // 1
                property bool serialStatus: false    // 2
                property int usb_channel: 1
                property int serial_channel: 2
                property bool firstDeviceConnect:false
                Rectangle {
                    property Item testChartPage: testChartPage
                    anchors.fill: parent
                    TestChart {

                        anchors.fill: parent
                        id: testChartPage
                        visible: true

                        Component.onCompleted: {
                            currentStatus = autoDisableCoordinate;
                            enterTest = setTest;
                        }
                        onClick: {
                            if (currentStatus) {
                                signalPageTab.disableCoords();
                            } else if (testChartPage.needRestoreStatus) {
                                restoreCoords();
                            }
                        }
                        onEnterTestChanged: {
                            setTest = enterTest;
                            touch.setTest(setTest ? 1 : 0);
                        }
                    }

                }
                //坐标通道失能
                function disableCoords() {
                    touch.debug("disableCoords");
                    usbStatus = touch.isCoordsEnables(usb_channel);
                    serialStatus = touch.isCoordsEnables(serial_channel);
                    var str = usbStatus?"usbStatus = 当前USB为打开状态":"usbStatus = 当前USB为关闭状态";
                    touch.tPrintf(str);
                    touch.tPrintf("disenable USB channel","disableCoords:");
                    touch.setCoordsEnabled(usb_channel, false);
                    touch.setCoordsEnabled(serial_channel, false);
                    testChartPage.needRestoreStatus = testChartPage.currentStatus;
                }

                function restoreCoords() {

                    touch.tPrintf("restoreCoords: ");
                    var str = usbStatus ? "usbStatus :设置USB状态为打开":"usbStatus:设置USB状态为关闭";
                    touch.tPrintf(str);
                    touch.setCoordsEnabled(usb_channel, usbStatus);
                    touch.setCoordsEnabled(serial_channel, serialStatus);
                }

                function restoreCoordsOrNot() {
                    if (testChartPage  !== null) {
                        if (testChartPage.needRestoreStatus) {
                            restoreCoords();
                        }
                    }
                }

                // handle signal chart
                onVisibleChanged: {
                    if (!visible) {

                        touch.stopGetSignalDataBg();
                        if (testChartPage.needRestoreStatus) {
                            restoreCoords();
                        }
                    } else {
                        touch.tPrintf("信号图模式:")
                        startSignalChart(false);
                        console.log("selected count = " + testChartPage.getSelectedCount());
                        console.log("deviceCount = " + deviceCount);
                        console.log("defaultTestItems.length = " + defaultTestItems.length);
//                        if (testChartPage.getSelectedCount() === 0 && defaultTestItems !== undefined) {
                        if (testChartPage.getSelectedCount() === 0 && deviceCount == 1 && defaultTestItems !== undefined && firstDeviceConnect) {
                            firstDeviceConnect = false;
                            testChartPage.setSignalItems(defaultTestItems);
                            console.log("defaultTestItems is ok");
                        } else {
                            testChartPage.restoreNumbers();
                        }

                    }
//                    console.log(">>" + defaultTestItems);
                }

            } // Tab signal

            Tab {

                title: qsTr("Accelerate aging")
                id: agingPageTab
                property int what: mTAB_Aging
                property Item agingPage: (item !== null) ? item.agingPageV : null


                Rectangle {
                    anchors.fill: parent
                    property Item agingPageV: agingPageId
                Aging {
                    anchors.fill: parent
                    anchors.top: parent.top
                    anchors.topMargin: defaultMargin
                    passAgingTime: mainPage.passAgingTime

                    id: agingPageId

                    onAgingFinished: {
                        rectangle.setp();
                        mainPage.agingFinished(index);

                    }

                }
                }
                onVisibleChanged: {

                    if (visible) {
                        for(var i = 0;i < agingPageTab.agingPage.deviceCount;i++)
                            agingPageTab.agingPage.timeFlag[i] = true;
                        startAging();
                        startAgingTest();
                    } else {
                        stopAgingTest();
                        showToast(qsTr("stop accelerate aging"))
                    }
                }

            } // Tab aging

            Tab {

                title: qsTr("Paint")
                id: drawPage
                property int what: mTAB_Palette

                Rectangle {

                    width: 1080
                    height: 1920
                    x: 0
                    y: 0
                }
                onVisibleChanged: {
                    touch.tPrintf("全屏画图模式：");
//                    drawPanel.visible = visible;
                }
            }

            Tab {

                id: settingsTabId
                property Item settingsPage: (item !== null) ? item.settingsPageV : null
                title: qsTr("Settings")
                property int what: mTAB_Settings
                Rectangle {
                    anchors.fill: parent
                    property Item settingsPageV: settingsId
                    Settings {
                        id: settingsId
                        anchors.fill: parent
                        Component.onCompleted: {
//                            settingsId.caliDataDelegate = calibrationDataDelegate;
                            settingsId.caliDataModel = calibrationDataModel;
                        }
                        onClickCalibration: {
                            calibrationUi.visible = true;
                            lastVisibility = mainPage.visibility;
                            showFullScreen();
//                            showToast("无操作" + "后自动退出")
                        }
                    }
                }
                onVisibleChanged: {
                    if (visible)
                    {
                        touch.tPrintf("设置模式:");
                        settingsPage.refreshSettings();
                    }
                }
            }

            Tab {
                title: qsTr("About")
                id: infoTab
                property int what: mTAB_Info
                signal refreshInfo();
                Rectangle{
                    anchors.fill: parent
                    ColumnLayout {
                        anchors.fill: parent

                        RowLayout
                        {
                            id:deviceID
                            height: deviceHeight
                            anchors.left: parent.left
                            anchors.top: parent.top
                            Rectangle
                            {
                                id:deviceInfoNameID
//                                width:300
                                width:parent.width
                                height: parent.height
                                anchors.top:parent.top
                                anchors.left: parent.left
                                Cont2.Label {
                                    width: parent.width
                                    height: parent.height
                                    textFormat: Text.AutoText
                                    anchors.left: parent.left
                                    anchors.top: parent.top
                                    padding: 20     //间距
                                    font.pointSize: 13
//                                    text: deviceInfoName + "\n" +softwareInfoName
                                    text:aboutInfo
                                    lineHeight: 1.5     //行距
                                    lineHeightMode: Text.ProportionalHeight  //按比例
                                }
                            }
                            Rectangle
                            {
                                visible: false

                                anchors.top:parent.top
                                anchors.left: deviceInfoNameID.right
                                anchors.leftMargin: defaultMargin
//                                height: deviceInfoHeight
                                height: parent.height
                                Cont2.Label
                                {
                                    textFormat: Text.AutoText
                                    anchors.left: parent.left
                                    anchors.top: parent.top
                                    padding: 20     //间距
                                    font.pointSize: 13
                                    text: deviceInfoString + "\n" +softwareInfo
                                    lineHeight:1.5     //行距
                                    lineHeightMode: Text.ProportionalHeight  //按比例
                                }
                            }

                        }
                        //软件部分
//                        RowLayout
//                        {
//                            anchors.left: parent.left
//                            anchors.top: deviceID.bottom
//                            Rectangle
//                            {
//                                id:softwareInfoNameID
//                                width: 250
//                                anchors.left: parent.left
//                                anchors.top: parent.top
//                                Cont2.Label
//                                {
//                                    textFormat: Text.AutoText
//                                    anchors.left: parent.left
//                                    anchors.top: parent.top
//                                    padding: 20     //间距
//                                    font.pointSize: 13
//                                    text: softwareInfoName
//                                    lineHeight: 1.5     //行距
//                                    lineHeightMode: Text.ProportionalHeight  //按比例
//                                }
//                            }
//                            Rectangle
//                            {
//                                id:softwareInfoID
//                                anchors.top: parent.top
//                                anchors.left: softwareInfoNameID.right
//                                anchors.leftMargin: defaultMargin
//                                Cont2.Label
//                                {
//                                    textFormat: Text.AutoText
//                                    anchors.left: parent.left
//                                    anchors.top: parent.top
//                                    padding: 20     //间距
//                                    font.pointSize: 13
//                                    text: softwareInfo
//                                    lineHeight: 1.5     //行距
//                                    lineHeightMode: Text.ProportionalHeight  //按比例
//                                }
//                            }
//                        }
                    }
                }
                function showDeviceInfo()
                {
//                    deviceInfoString = touch.getDeviceInfo();
                    aboutInfo = touch.getRelativeInfo();

                    if(!touch.whetherDeviceConnect())
                    {
                        deviceInfoName = deviceInfoString;
                        deviceInfoString = "";
                        deviceHeight = 50;
                        deviceWidth = 250;
                        deviceInfoHeight = 0;
                    }
                    else
                    {
                        deviceInfoName = touch.getDeviceInfoName();
                        deviceHeight = 300;
                        deviceWidth = 250;
                        deviceInfoHeight = deviceHeight
                    }
                    softwareInfoName = touch.getSoftwareInfoName();
                    softwareInfo = touch.getSoftwareInfo();
                }
                Component.onCompleted:
                {
                    infoTab.refreshInfo.connect(showDeviceInfo);
                }
                onVisibleChanged: {
                    if (visible) {
                        showDeviceInfo();
                        touch.tPrintf("关于界面");
                    }
                }

            } // Tab info

            //================================================


            style: TabViewStyle {
                    frameOverlap: 1
                    tab: Rectangle {
                        color: styleData.selected ? "steelblue" :"#E1F5FE"
                        border.color:  "steelblue"
                        implicitWidth:Math.max(Math.min(Math.max(text.width + 4, 80) * tabWidth,windowWidth / mainTabView.count),Math.max(text.width + 4, 80));
                        implicitHeight: Math.max(Math.min(windowHeight / 5.0,20 * tabHeight),20)
                        radius: 2
                        Text {
                            id: text
                            anchors.centerIn: parent
                            text: styleData.title
                            font.pointSize: Math.min(8 + (tabHeight - 1) * 2,20)
                            color: styleData.selected ? "white" : "black"
                        }

//                        MouseArea {
//                            anchors.fill: parent
//                            propagateComposedEvents: true
//                            onPressed: {
//                                if ("全屏画图" === text.text && mainPage.visibility != Window.FullScreen) {
//                                    drawPanel.visible = false;
//                                    drawPanel.visible = true;
//                                }
//                                mouse.accepted = false;
//                            }
//                        }
                    }
                    frame: Rectangle { color: "steelblue" }
                }
        } // tabview

        //校准界面
        Calibration {
            id: calibrationUi
            Keys.enabled: true
            x: 0
            y: 0
            z: 1

            width: Screen.width
            height: Screen.height
            focus: true
            visible: false
            onExit: {
                focus = false;
                visible = false;
                mainPage.visibility = lastVisibility;
            }

        }

    }


    property alias agingPage: agingPageTab.agingPage

    ListModel
    {
        id: fileText
    }
    function setUpgradeFile(file) {

        file = "" + file;
        var existFlsg = false;
        for(var i = 0;i < fileText.count;i++)
        {

            if(fileText.get(i).text === file)
            {
                existFlsg = true;
                break;
            }
        }
//        if(fileText.count === 10)
//        {
//            existFlsg = true;
//            file = fileText.get(0).text;
//            showToast(qsTr("Up to 10 pieces of firmware can be stored"));
//        }
        if(!existFlsg)
        {
            fileText.insert(0,{"text":file});
            touch.setUpgradeFile(file);
            if(fileText.count > 10)
            {
                fileText.remove(fileText.count - 1);
            }
        }
        for(i = 0;i < fileText.count;i++)
        {
            if(fileText.get(i).text === file)
            {
                updateComBoxId.currentIndex = i;
                break;
            }
        }
        touch.setUpdatePath(file);

        file = file.replace("file://", "");
        var regex = /[^/]*bin/g;
        file = file.replace(regex, '');
        var folder = "file:///" + file.replace(new RegExp("/", 'g'), "\\");
//        folder = folder.replace(new RegExp("[^\/]*bin", 'g'), "")
//        folder = folder.replace(regex, '');
//        console.log("fFF: " + folder)
        fileDialog.folder = folder;
    }

    FileDialog {
        id: fileDialog
        nameFilters: [ qsTr("bin file")+"(*.bin)", qsTr("all files")+"(*)" ]
        title: "Please choose a file"
        onAccepted: {
//            console.log("You chose: " + fileDialog.fileUrls)
            this.close();
            setUpgradeFile(fileDialog.fileUrl);
            //touch.updateFireware(fileDialog.fileUrl);
        }

//        folder: "file:///F:"
        onRejected: {
            console.log("Canceled")
            this.close();
        }
        //Component.onCompleted: visible = true
    }

    FileDialog {
        property int mode: 0
        id: calibrationfileDialog
        nameFilters: [ qsTr("json file") + "(*.json)", qsTr("all files") + "(*)" ]
        selectExisting: mode === 0
        onAccepted: {
            if (mode === 0) {
                loadCalibrationData(calibrationfileDialog.fileUrl);
            } else if (mode === 1) {
                saveCalibrationData(calibrationfileDialog.fileUrl);
            }
        }
        folder: "file://F://"
        onRejected: {
            this.close();
        }
        //Component.onCompleted: visible = true
    }

    function setFileText(file) {

//        setUpgradeFile(file)
        var existFlsg = false;
        for(var i = 0;i < fileText.count;i++)
        {

            if(fileText.get(i).text === file)
            {
                existFlsg = true;
                break;
            }
        }
        if(fileText.count === 10)
        {
            existFlsg = true;
            file = fileText.get(0).text;
            showToast(qsTr("Up to 10 pieces of firmware can be stored"));
        }
        if(!existFlsg)
        {
            console.log("++++++++++++++++++++++++++++++++++++++++++++++++");
            fileText.insert(0,{"text":file});
        }
        for(i = 0;i < fileText.count;i++)
        {
            if(fileText.get(i).text === file)
            {
                updateComBoxId.currentIndex = i;
                break;
            }
        }
        touch.setUpdatePath(file);

//        fileText.insert(0,{"text":file});
    }
    function getFileText(){
//        return fileText.text;
        return updateComBoxId.currentText;
    }

    /*
QMessageBox::NoIcon	0	the message box does not have any icon.
QMessageBox::Question	4	an icon indicating that the message is asking a question.
QMessageBox::Information	1	an icon indicating that the message is nothing out of the ordinary.
QMessageBox::Warning	2	an icon indicating that the message is a warning, but can be dealt with.
QMessageBox::Critical	3	an icon indicating that the message represents a critical problem.
      */

    function showDialog(title, msg, type) {

        var tt;
        var titleName;
        var accpetTextBtn;
        var currentPage;
//        if(type >= 4  && type <= 7)
//        {
            tt = Qt.createComponent("qrc:qml/ui/InformationSign.qml");
            //        console.log("chart erros:" + tt.errorString())
            if (tt.errorString())
                touch.error("chart erros:" + tt.errorString());
                if(showPage)
                {
                    currentPage = isSupportOnboardtest?onboardTest.midRectText:testPage.testShowDialog;
                }
                else
                {
                    currentPage = updatePage.updateShowDialog;
                }

            tt = tt.createObject(currentPage);
            tt.showMessage({
                               message: msg,
                               icon: type,
                               showCancel: false
                           })

//        }
        /*
        else
        {
//            if(isSupportOnboardtest)
//                onboardTest.midRecttextString = msg;

            tt = Qt.createComponent("qrc:qml/ui/TDialog.qml");
            //        console.log("chart erros:" + tt.errorString())
            if (tt.errorString())
                touch.error("chart erros:" + tt.errorString());

            if(showPage)
            {

                currentPage = isSupportOnboardtest?onboardTest.midRectText:testPage.testShowDialog;
            }
            else
            {
                currentPage = updatePage.updateShowDialog;

            }
            tt = tt.createObject(currentPage);
            tt.showMessage({
                               title: title,
                               message: msg,
                               icon: type,
                               accpetText: qsTr("close"),
                               showCancel: false
                           })

        }
        */

        mainPage.sendDestroyDialog.connect(tt.closeDialog);
    }
    function destroyDialog()
    {
        mainPage.sendDestroyDialog();
    }

    property alias upgradeProgressBar: updatePage.upgradeProgressBar
    function updateUpgradeProgress(progess) {
        upgradeProgressBar.value = progess;
//        console.debug("upgrade " + progess)
    }

    property alias testProgressBar: testPage.testProgressBar
    function updateTestProgress(progess) {
        testProgressBar.value = progess;
    }

    //type 0 == 设备连接与断开
    //type 1 == 升级模式
    //type 2 == 测试模式
    function appendText(message, type) {
        var tmpLength = 0;
        var tmpArray = [];
        var index = 0;
        var tmpSaveLeng = 0;
        var str = "";
        var i = 0;
        var str1 = "";
        str = message + "\n";

        if(type === 0)
        {
            var finalMessage = "";
            finalMessage = message.split(":");
            if(finalMessage[3].search("TouchApp") !== -1)
            {
                showToast(finalMessage[3]);
            }

        }
        if(type === 1 || type === 0)
        {
            updateMessage.push(str);
            updateMessageLength += str.length;

            if(updateMessageLength < maxMessageLeng)
            {
                str1 = "";
                for(i = 0;i < updateMessage.length;i++)
                {
                    str1 += updateMessage[i];
                }
//                mv.text = str1;
                upgradeShowStr = str1;
            }
            else
            {
                var tmpUpdateLength = 0;
                var tmpUpdateArray = [];
                var updateIndex = 0;
                var tmpUpdateSaveLeng = 0;
                str1 = "";
                for(i = 0;i < updateMessage.length;i++)
                {
                    tmpUpdateLength += updateMessage[i].length;
                    if((updateMessageLength - tmpUpdateLength) > maxMessageLeng)
                    {
                        continue;
                    }
                    tmpUpdateArray[updateIndex++] = updateMessage[i];
                    str1 += updateMessage[i];
                    tmpUpdateSaveLeng += updateMessage[i].length;
                }
//                mv.text = str1;
                upgradeShowStr = str1;
                updateMessage = tmpUpdateArray;
                updateMessageLength = tmpUpdateSaveLeng;
            }
            updatePage.messageView.text = str1;
        }
        if(type === 2 || type === 0)
        {
            testMessage.push(str);
            testMessagLength += str.length;

            if(testMessagLength < maxMessageLeng)
            {
                str1 = "";
                for(i = 0;i < testMessage.length;i++)
                {
                    str1 += testMessage[i];
                }
//                mv.text = str1;
//                testStr = str1;
            }
            else
            {
                tmpLength = 0;
                tmpArray = [];
                index = 0;
                tmpSaveLeng = 0;
                str1 = "";
                for(i = 0;i < testMessage.length;i++)
                {
                    tmpLength += testMessage[i].length;
                    if((testMessagLength - tmpLength) > maxMessageLeng)
                    {
                        continue;
                    }
                    tmpArray[index++] = testMessage[i];
                    str1 += testMessage[i];
                    tmpSaveLeng += testMessage[i].length;
                }
//                mv.text = str1;

                testMessage = tmpArray;
                testMessagLength = tmpSaveLeng;
//                testStr = str1;
            }
            testPage.messageView.text = str1;
        }



    }
    function setText(message) {
        if (messageView === null)
            return;
        messageView.text = message
    }

    property alias testChartPage: signalPageTab.testChartPage
    function updateSignalData(data) {
        testChartPage.updateSignalData(data);
    }
    function updateChart() {
        testChartPage.updateChart(0);
    }

    function getSignalData(index) {
        return touch.getSignalData(index);
    }

    function setVisibleValue()
    {
        console.log("testPage.sendOnboardTestStart()");
        testPage.sendOnboardTestStart();
        isSupportOnboardtest = true;
    }
    property alias onboardTest : testPage.onboardTest
    function changeOnboardtestString(info)
    {
        onboardTest.midRecttextString = info;
    }

    property alias testBtn: testPage.testBtn
    function setTestButtonEnable(enable) {
        testBtn.enabled = enable;
    }
    function setTestButtonCheck(check)
    {
        testBtn.checked = check;

//        if(testBtn.checked)
//            testBtnName = "取消测试";
//        else
//            testBtnName = "test";

//        console.log("testBtnName = ",testBtnName);
    }
    function setTextButtonText(text)
    {
        testBtnName = text;
    }

    function setUpgradeButtonText(text) {
        updatePage.updateButton.text = text;
    }

    function setUpgradeButtonEnable(enable) {
        updatePage.updateButton.enabled = enable;
    }

    function setUpgrading(u){
        updatingFw = u;
    }
    function setTesting(u){
        testingFw = u;
    }
    function autoTestConnect(){
        if(showPage)
        {
            if(testingFw)
            {
                return;
            }
            testBtn.checked  = true;
            onboardTest.midRecttextString = "";
            isSupportOnboardtest = false;
            onboardTest.visible = false;
            testBtnName = qsTr("Cancel test");
            mainPage.sendDestroyDialog();
            touch.setTestThreadToStop(false);
            touch.startTest();
        }


    }
    function clearTestInfo()
    {
        if(showPage)
        {
            testProgressBar.value = 0;
            touch.cancelTest(true);
            mainPage.sendDestroyDialog();
            touch.setTestThreadToStop(true);
            isSupportOnboardtest = false;
            onboardTest.visible = false;
        }

    }
    function showUpgradePage() {

    }

    function showTestPage() {
    }


    signal agingFinished(int index);
    signal stopAgingTest();
    signal startAgingTest();

    function refreshSettings() {
        if (settingsTabId.settingsPage != null)
            settingsTabId.settingsPage.refreshSettings();
        if (calibrationUi.visible) {
            calibrationUi.exitPanel();
        }
    }

    function startAging() {

        agingPage.startAging();
    }
    function stopAging() {
        agingPage.stopAging();
    }
    function setDeviceStatus(dev, status) {
        agingPage.setDeviceStatus(dev, status);
        console.log("setDeviceStatus")
    }

    property int appType: -1
    function setAppType(type) {
        appType = type;
    }
    onAppTypeChanged: {
        console.log("type:" + appType);
        switch (appType) {
        case mAPP_Client:
            mainTabView.removeTab(3);
            mainTabView.removeTab(3);
//            mainTabView.removeTab(1);
//            mainTabView.removeTab(1);
//            mainTabView.removeTab(1);
//            mainTabView.removeTab(1);
//            mainTabView.removeTab(1);

            break;
        case mAPP_PCBA:
            mainTabView.removeTab(3);
            break;
        case mAPP_Factory:
//            mainTabView.removeTab(5);
            break;
        case mAPP_RD:
            break;
        }
    }

    onHeightChanged: {
        windowHeight = height;
//        testChartPage.scrollHeight = height - 170;
//        testChartPage.height = height - 100;
        if(isSupportOnboardtest)
            onboardTest.refreshCanvas();

    }
    onWidthChanged: {
        windowWidth = width;
//        testChartPage.scrollWidth = width;
//        testChartPage.width = width;
        if(isSupportOnboardtest)
            onboardTest.refreshCanvas();
    }

    //    Timer{
    //        id: refreshTimer
    //        interval: 150
    //        repeat: true
    //        running: true
    //        triggeredOnStart: true
    //        property int xxx: 1
    //        onTriggered: {
    //            appendText("xxx" + xxx + "\n");
    //            xxx++;
    //        }
    //    }

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

            Cont2.Label {
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

    function onHotplug(plugin) {   
        infoTab.refreshInfo();
        if (plugin) {
            deviceCount++;
            if(deviceCount == 1)
            {
                signalPageTab.firstDeviceConnect = true;
            }
            if(testChartPage.getSelectedCount() === 0 && signalPageTab.firstDeviceConnect && mainTabView.currentIndex == mTAB_Signal)
            {
                signalPageTab.firstDeviceConnect = false;
                startSignalChart(false);
                testChartPage.setSignalItems(defaultTestItems);
                console.log("testChartPage.setSignalItems(defaultTestItems) is ok");
            }

        }

        if (!plugin) {
            if (testChartPage !== null) {
                console.log("onHotplug @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                testChartPage.saveNumbers();
                testChartPage.clearAndRefreshItems();
                testChartPage.stopAutoRefresh();
                touch.stopGetSignalDataBg();
                //            testChartPage.refreshItems(true);
            }
        }

        if (signalPageTab.visible && plugin && testChartPage !== null) {
            console.log("start signal chart");
            testChartPage.clearModels();
            startSignalChart(true);
            testChartPage.restoreNumbers();
        } else if (plugin && testChartPage !== null) {
//            console.log("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
        }



    }

    function startSignalChart(force) {

        var da = {};
        da.setTest = setTest ? 1 : 0;
        touch.enterSignalMode(da);
        testChartPage.refreshItems(force);
        if (testChartPage.currentStatus) {
            signalPageTab.disableCoords();
        }
        testChartPage.needRestoreStatus = testChartPage.currentStatus;

        if (testChartPage.stopRefresh === false) {
            touch.startGetSignalDataBg(1);
            testChartPage.startAutoRefresh();
        }
    }

    function setDeviceInfo(info) {
//        deviceInfoString = info;
    }
    function newRunner() {
        touch.debug("new runner");
        requestActivate();
        showMinimized();
        showMaximized();
        raise();
    }


    DrawPanel {
        anchors.fill: parent
        id: drawPanel
        visible: false

        onVisibleChanged: {
            if (visible) {
                lastVisibility = mainPage.visibility;
                anchors.topMargin = 0;
                showFullScreen();
            }
        }

        onWidthChanged: repaintPath();
        onHeightChanged: repaintPath();

        onExit: {
            if (anchors.topMargin === 0) {
                mainPage.visibility = lastVisibility;
                anchors.topMargin = 50;
            }
            visible = true;
            mainTabView.tabsVisible = true;
        }
    }



    ListModel {
        id: calibrationDataModel
    }


    Component.onCompleted: {
        showUpgradePage();
        var i;
        for (i = 0; i < 4; i++) {
            calibrationDataModel.append({
                index: i,
                targetX: 0,
                targetY: 0,
                collectX: 0,
                collectY: 0,
                maxX: Screen.width,
                maxY: Screen.height
            });
        }
    }
    property var lastVisibility: visibility
    function readFile(fileUrl) {
        var request = new XMLHttpRequest();
        request.open("GET", fileUrl, false);
        request.send(null);
        return request.responseText;
    }
    function saveFile(fileUrl, text) {
        var request = new XMLHttpRequest();
        request.open("PUT", fileUrl, false);
        request.send(text);
        return request.status;
    }

    function createCalibrationData() {
        var points = [];
        var model;
        var i;
        for (i = 0; i < calibrationDataModel.count; i++) {
            model = calibrationDataModel.get(i);
            points[i] = {
                index: model.index,
                targetX: model.targetX,
                targetY: model.targetY,
                collectX: model.collectX,
                collectY: model.collectY,
                maxX: model.maxX,
                maxY: model.maxY
            }
        }
        return {count: calibrationDataModel.count, points: points,};
    }

    function saveCalibrationData(file) {

        showProgessing();
        var calJson = JSON.stringify(createCalibrationData());
        touch.debug(calJson);
        saveFile(file, "" + calJson);

        hideProgessing();
        showToast(qsTr("Saved successfully"));
    }

    function resetCalibrationData(){
        var datas = touch.getCalibrationDatas(2);
        touch.debug(JSON.stringify(datas));
        if (datas.count === undefined || datas.count <= 0)
            return;
        var i;
        var points = datas.points;
        calibrationDataModel.clear();
        for (i = 0; i < datas.count; i++) {
            var point = points[i];
            calibrationDataModel.append({
                                            index: point.index,
                                            targetX: point.targetX,
                                            targetY: point.targetY,
                                            collectX: point.collectX,
                                            collectY: point.collectY,
                                            maxX: point.maxX,
                                            maxY: point.maxY
                                        });
        }
        touch.setCalibrationDatas(datas);
    }

    function refreshCalibrationData(){
        var datas = touch.getCalibrationDatas(1);
        touch.debug(JSON.stringify(datas));
        if (datas.count === undefined || datas.count <= 0)
            return;
        var i;
        var points = datas.points;
        calibrationDataModel.clear();
        for (i = 0; i < datas.count; i++) {
            var point = points[i];
            calibrationDataModel.append({
                                            index: point.index,
                                            targetX: point.targetX,
                                            targetY: point.targetY,
                                            collectX: point.collectX,
                                            collectY: point.collectY,
                                            maxX: point.maxX,
                                            maxY: point.maxY
                                        });
        }
    }

    function loadCalibrationData(file) {
        showProgessing();
        var xhr = new XMLHttpRequest();
        xhr.open("GET",file,true);
        xhr.onreadystatechange = function() {
            if ( xhr.readyState == xhr.DONE) {
                if ( xhr.status == 200) {
                    var jsonObject = JSON.parse(xhr.responseText);
                    var model;
                    var i;
                    var points = jsonObject.points;
                    touch.debug("load cali:" + xhr.responseText);
                    calibrationDataModel.clear();
                    for (i = 0; i < jsonObject.count; i++) {
                        var point = points[i];
                        calibrationDataModel.append({
                            index: point.index,
                            targetX: point.targetX,
                            targetY: point.targetY,
                            collectX: point.collectX,
                            collectY: point.collectY,
                            maxX: point.maxX,
                            maxY: point.maxY
                        });
                    }
                }
            }
            hideProgessing();
        }
        xhr.send();
    }

    function showProgessing() {
        progressing.visible = true;
    }
    function hideProgessing() {
        progressing.visible = false;
    }

    Rectangle {
        id: progressing
        anchors.fill: parent
        visible: false
        color: "#00000000"
        Cont2.ProgressBar {
            width: 200
            height: 30
            anchors.centerIn: parent

            indeterminate: true
        }
    }

    DropArea {
        id: dropArea;
        anchors.fill: parent;
        keys: ['application/x-qt-windows-mime;value="FileNameW"']
        onEntered: {
            if (drag.hasUrls) {
                drag.accept(Qt.LinkAction);
            }
        }
        onDropped: {
            if (drop.hasUrls) {
//                console.log(drop.urls[0])
                setUpgradeFile(drop.urls[0]);
            }
        }
        onExited: {
//            console.log ("onExited");
        }
    }

    onClosing: {

        if (!updatePage.updateButton.enabled) {

            showToast(qsTr("Upgrading! Please do not close the program"));
            close.accepted = false;
        }
       else if (testPage != null && testPage.testBtn != null && !testPage.testBtn.enabled) {
           showToast(qsTr("Testing! Please do not close the program"));
           close.accepted = false;
       }

        if (close.accepted) {
            mainPage.sendCloseOnboardTestWindow();

        }
    }

    function setAgingTime(time) {
        passAgingTime = time;
//        agingPage.passAgingTime = time;
    }
    function onboardTestFinish(title,message,type)
    {

    }
    function onboardShowDialog(title,message,type)
    {
//        mainPage.sendOnboardTestShowDialog(title,message,type);
    }
    function refreshOnboardTestData(map)
    {
        mainPage.sendRefreshOnboardTestData(map);
    }
    function setCurrentIndex(index)
    {
        if(1 === touch.getAppType())
        {
            if(index === 3)
                index = 0;
            if(index > 3)
                index -= 2;
        }
        mainTabView.currentIndex = index;
    }
    function setWindowHidden(visibled)
    {
        if(mainPage.visible && visibled)
        {
            return;
        }

        mainPage.setVisible(visibled);
        if(visibled)
            mainPage.visibility =  Window.Maximized;
    }


}
