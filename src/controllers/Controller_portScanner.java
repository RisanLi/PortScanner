package controllers;

import javafx.application.Platform;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static controllers.Main.stage;
import static controllers.Main.welcomeScene;
import static tools.Alert.alertError;
import static tools.Alert.alertInformation;

/**
 * Created with IntelliJ IDEA.
 * User: Netzhang
 * Description:
 * Date: 2018-09-12
 * Time: 9:56
 */
public class Controller_portScanner {
    public MenuBar menuBar;
        public Menu menu_menu;
            public MenuItem menuItem_startScan;
            public MenuItem menuItem_export;
            public MenuItem menuItem_exit;
        public Menu menu_about;
            public MenuItem menuItem_author;
            public MenuItem menuItem_connect;
            public MenuItem menuItem_version;
            public MenuItem menuItem_help;
    public TextField textField_IP;
    public TextField textField_thread;
    public ToggleGroup scanChoose;
    public RadioButton radioButton_commonPort;
    public TextField textField_commonPort;
    public RadioButton radioButton_continuousPort;
    public TextField textField_startPort;
    public TextField textField_endPort;
    public Button button_start;
    public Button button_export;
    public volatile TextArea textArea_scanProcess;
    public volatile TextArea textArea_result;
    private String currentDomain;
    private String currentPorts;
    private ExecutorService threadPool;

    /**
     * 根据输入的字符串提取出其中的域名字符串或者IP字符串，如：www.baidu.com或者baidu.com或者192.168.2.1
     *
     * @param str 输入的包含域名的字符串
     * @return 域名或IP字符串
     */
    private static String getDomainString(String str) {
        //先判断是不是IP
        String reg = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
        Pattern pattern = Pattern.compile(reg);
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            return matcher.group();
        }
        //不是则判断是不是域名
        reg = "[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+";
        pattern = Pattern.compile(reg);
        matcher = pattern.matcher(str);
        if (matcher.find()) {
            return matcher.group();
        }
        //都不是就返回null
        return null;
    }

    /**
     * 启动扫描
     */
    public void startScan() {
        currentDomain = getDomainString(textField_IP.getText().trim());     //获取域名并确认是否合法
        System.out.println("    域名：" + currentDomain);
        int threadNum = Integer.parseInt(textField_thread.getText().trim());   //获取线程数
        System.out.println("    线程数：" + threadNum);
        if (currentDomain == null) {
            alertError("Error Run", "执行失败，检查是否包含以下错误:", "1. 域名或IP不为空!\n" + "" + "2. 请检查域名或IP是否输入正确!");
            return;
        }

        //上个扫描结束，域名合法，可以清空扫描结果
        if (threadPool != null && !threadPool.isTerminated()) {
            alertInformation("提示", "正在进行端口扫描：", "1. 等待扫描结束\n" + "" + "2. 重启该软件");
            return;
        } else {
            textArea_scanProcess.clear();
            textArea_result.clear();
        }
        if (radioButton_commonPort.isSelected()) {
            System.out.println("常见端口扫描:");
            //获取创建端口
            //currentPorts = textField_commonPort.getText();
            String[] portsString = textField_commonPort.getText().split(",");
            //端口转化为int型
            int[] ports = new int[portsString.length];
            for (int i = 0; i < portsString.length; i++) {
                try {
                    ports[i] = Integer.parseInt(portsString[i].trim());
                    if (ports[i] < 0 || ports[i] > 65535)
                        throw new Exception("传入的端口号超出范围大小：");
                } catch (Exception e1) {
                    alertError("Error", "常见端口输入错误", "1. 请按照规定正确输入格式：如：端口号,端口号！\n" + "2. 端口号范围在0~65535之间！");
                    return;
                }
            }
            currentPorts = textField_commonPort.getText();
            textArea_scanProcess.appendText("开始扫描" + currentDomain + ":\n");
            threadPool = Executors.newCachedThreadPool();
            for (int i = 0; i < threadNum; i++) {           //newCachedThreadPool是根据创建的线程数来决定的。
                ScanThread1 scanThread1 = new ScanThread1(currentDomain, ports, threadNum, i, 1000);
                threadPool.execute(scanThread1);
            }
            threadPool.shutdown();      //此时线程池不能够接受新的任务，它会等待所有任务执行完毕

        } else if (radioButton_continuousPort.isSelected()) {
            System.out.println("连续端口扫描：");
            int startPortInt;
            int endPortInt;
            try {
                startPortInt = Integer.parseInt(textField_startPort.getText().trim());
                endPortInt = Integer.parseInt(textField_endPort.getText().trim());
                if (startPortInt < 0 || startPortInt > 65535 || endPortInt < 0 || endPortInt > 65535 || startPortInt > endPortInt)
                    throw new Exception("端口范围出错");
            } catch (Exception e1) {
                alertError("Error", "常见端口输入错误", "1. 请按照规定正确输入格式：如：端口号,端口号！\n" + "2. 端口号范围在0~65535之间！\n" + "3. 起始端口应小于等于结束端口！");
                return;
            }
            currentPorts = Integer.toString(startPortInt) + "~" + Integer.toString(endPortInt);
            threadPool = Executors.newCachedThreadPool();
            for (int i = 0; i < threadNum; i++) {
                ScanThread2 scanThread2 = new ScanThread2(currentDomain, startPortInt, endPortInt, threadNum, i, 800);
                threadPool.execute(scanThread2);
            }
            threadPool.shutdown();
        }
    }

    /**
     * 导出结果
     */
    public void exportRes() {
        if (threadPool != null && !threadPool.isTerminated()) {
            alertInformation("结果提示", "正在扫描" + currentDomain + ":", "        请稍后再进行导出！");
        } else if (currentDomain == null) {
            alertInformation("结果提示", "导出失败", "        未输入域名，请先输入域名，扫描完成后再导出！");
        } else {
            //打开文件选择器，设置文件保存名，保存文件
            FileChooser fileChooser = new FileChooser();
            FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
            fileChooser.getExtensionFilters().add(extFilter);
            File file = fileChooser.showSaveDialog(stage);
            BufferedWriter wr;
            try {
                wr = new BufferedWriter(new FileWriter(file));
                String res = "扫描域名:" + currentDomain + "\r\n" + "端口范围:" + currentPorts + "\r\n" + "结果:\r\n" + textArea_result.getText().replaceAll("\n", "\r\n");
                wr.write(res);
                wr.close();
            } catch (IOException e) {
                System.out.println("文件保存出错");
            }
        }
    }

    /**
     * 第一种线程池扫描
     */
    class ScanThread1 implements Runnable {
        private String domain;      // 待扫描的端口
        private int[] ports;        // 待扫描的端口的Set集合
        private int threadNum, serial, timeout; // 线程数，这是第几个线程，超时时间

        //初始化当前线程参数
        ScanThread1(String domain, int[] ports, int threadNum, int serial, int timeout) {
            this.domain = domain;
            this.ports = ports;
            this.threadNum = threadNum;
            this.serial = serial;
            this.timeout = timeout;
        }

        @Override
        public void run() {
            int port;
            try {
                InetAddress address = InetAddress.getByName(domain);        //通过主机名获取对应的ip地址
                Socket socket;
                SocketAddress socketAddress;
                if (ports.length < 1)       //若扫描端口为空，则不进行扫描
                    return;
                for (port = serial; port <= ports.length - 1; port += threadNum) {      //每个线程循环扫描自己的一部分端口。  如线程数5，再当前线程扫描ports[0],port[5]...
                    Platform.runLater(new ProgressRunnable(ports[port]));  //更新界面
                    socket = new Socket();
                    socketAddress = new InetSocketAddress(address, ports[port]);

                    try {
                        socket.connect(socketAddress, timeout);
                        socket.close();
                        //事实证明如果端口连接失败了，就会异常，从而跳过执行更新界面的程序
                        Platform.runLater(new ResultRunnable(ports[port]));  //更新界面
                        Thread.sleep(200);
                    } catch (Exception e) {
//                        System.out.println();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 第二种线程池跑动
     */
    class ScanThread2 implements Runnable {
        private String domain;
        private int startPort = 80, endPort = 443; // 待扫描的端口的Set集合
        private int threadNum, serial, timeout; // 线程数，这是第几个线程，超时时间

        ScanThread2(String domain, int startPort, int endPort, int threadNum, int serial, int timeout) {
            this.domain = domain;
            this.startPort = startPort;
            this.endPort = endPort;
            this.threadNum = threadNum;
            this.serial = serial;
            this.timeout = timeout;
        }

        @Override
        public void run() {
            int port;
            try {
                InetAddress address = InetAddress.getByName(domain);
                Socket socket;
                SocketAddress socketAddress;
                for (port = startPort + serial; port <= endPort; port += threadNum) {       //当前线程只需要执行完他需要扫描的端口就够了，就可以结束了。
                    Platform.runLater(new ProgressRunnable(port));  //更新界面

                    socket = new Socket();
                    socketAddress = new InetSocketAddress(address, port);
                    try {
                        socket.connect(socketAddress, timeout); // 超时时间
                        socket.close();
                        Platform.runLater(new ResultRunnable(port));  //更新界面
                        Thread.sleep(200);
                    } catch (Exception e) {
//                        System.out.println();
                    }
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        }
    }

    /**
     * 由EDT调用来更新界面的线程
     * 在 JavaFx 中，如果在非Fx线程要执行Fx线程相关的任务，必须在 Platform.runlater 中执行，
     * 而 runlater 中代码将不会阻塞当前线程，所以当需要 runlater 中代码执行返回值，再顺序执行后续代码
     */
    class ProgressRunnable implements Runnable {
        private int currentPort = 0;

        ProgressRunnable(int currentPort) {
            this.currentPort = currentPort;
        }

        public void run() {
            textArea_scanProcess.setEditable(false);
            textArea_scanProcess.appendText("正在扫描端口：" + currentPort + "\n");
            textArea_scanProcess.selectAll();
            textArea_scanProcess.end();
        }

    }

    /**
     * 同上
     */
    class ResultRunnable implements Runnable {
        private int currentPort = 0;

        ResultRunnable(int currentPort) {
            this.currentPort = currentPort;
        }

        public void run() {
            textArea_result.setEditable(false);
            textArea_result.appendText("端口：" + currentPort + "    开放\n");
            textArea_result.selectAll();
            textArea_result.end();
        }
    }

    public void backMain(){
        textArea_result.clear();
        textArea_scanProcess.clear();
        stage.setScene(welcomeScene);
    }
    public void getAuthor(){
        alertInformation("作者","网络课程设计小组","Netzhangheng & RisanLi & WangShiJie");
    }
    public void getConnect(){
        alertInformation("联系方式","Tel:","xxxxxxx6670");
    }
    public void getVersion(){
        alertInformation("版本","测试版:","v0.1.1");
    }
    public void getUse(){
        alertInformation("使用说明","帮助：","1. 注意输入域名和IP的规范！\n"+"2. 注意常用端口号的规范，端口号之间需要使用“，”进行分割！\n"+"3. 注意连续端口扫描时，起始端口号应小于等于结束端口号");
    }
}