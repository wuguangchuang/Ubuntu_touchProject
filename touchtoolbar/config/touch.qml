import QtQml 2.0

QtObject {
    // 显示测试过程中的数据
    property bool showTestData: false
    // 忽略测试失败项
    property bool ignoreFailedTestItem:true
	
    // log level:
    // VERBOSE: 4, DEBUG: 3, INFO: 2, WARNING: 1, ERROR: 0
    property int logLevel: 3

    //property string lang: "zh_CN"
	property string lang: "en_US"

    // 硬件加速， openGL
    property bool hardwareAcceleration:true

    // 自动屏蔽坐标
    property bool autoDisableCoordinate: true

        // 校准退出时间设置
    // 无操作后自动退出的时间
    property int calAutoCancelTime: 60 * 1000
    // 校准完成后自动退出的时间
    property int calFinishExitTime: 3 * 1000

    // 默认测试项
    property var defaultTestItems: [0,2,4,20]
    //分开显示或者堆叠显示:true or false
    property bool displaySeparateModel: true
    //测试项个数最大值，最多八个：只对信号分开显示有效
    property int testCount: 8
	//选择柱状图的形式显示信号：必须是分开显示才有效
	property bool histogram:false
	//默认切换到所需要的界面：  升级界面为0、 测试界面为1、 信号图界面为2、 加速老化界面为3
	//全屏画图界面为4、 设置界面为5、  关于界面设置为6 
	property int currentIndex:0
}