package controllers;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.scene.control.*;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.*;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static controllers.Main.*;
import static tools.Alert.alertInformation;

/**
 * Created with IntelliJ IDEA.
 * User: RisanLi
 * Description:
 * Date: 2018-09-12
 * Time: 16:27
 */
public class Controller_sniffer {
    public MenuBar menuBar;
    public Menu menu;
    public MenuItem menuItem_startSniff;
    public MenuItem menu_back;
    public Menu about;
    public MenuItem menuItem_author;
    public MenuItem menuItem_connect;
    public MenuItem menuItem_version;
    public MenuItem menuItem_use;
    public TableView<tableRow> tableView;
    public TableColumn<tableRow, String> tableColumn_time;
    public TableColumn<tableRow, String> tableColumn_sourceIP;
    public TableColumn<tableRow, String> tableColumn_destIP;
    public TableColumn<tableRow, String> tableColumn_protocol;
    public TableColumn<tableRow, String> tableColumn_length;
    public ComboBox<String> comboBox_net;
    public ComboBox<String> comboBox_protocol;
    public Button button_start;
    public TextField textField_filter;

    private ExecutorService threadPool;
    private static volatile boolean stop = false;

    /**
     * 获取网卡名
     */
    public void selectNet() {
        comboBox_net.getItems().clear();
        for (jpcap.NetworkInterface i : devices) {
            comboBox_net.getItems().add(i.description);
        }
    }

    /**
     * 选择获取协议包
     */
    public void selectProtocol() {
        comboBox_protocol.getItems().clear();
        comboBox_protocol.getItems().addAll("All", "TCP", "UDP", "ICMP");
    }

    /**
     * 开启抓包模式
     */
    public void start() {
        stop = false;
        //将数据和表格绑定
        tableColumn_time.setCellValueFactory(cellData -> cellData.getValue().timeProperty());
        tableColumn_sourceIP.setCellValueFactory(cellData -> cellData.getValue().sourceIPProperty());
        tableColumn_destIP.setCellValueFactory(cellData -> cellData.getValue().destIPProperty());
        tableColumn_protocol.setCellValueFactory(cellData -> cellData.getValue().protocolProperty());
        tableColumn_length.setCellValueFactory(cellData -> cellData.getValue().lengthProperty());

        //获取用户选择抓包网卡
        if (comboBox_net.getSelectionModel().getSelectedItem() == null) {
            alertInformation("提示:", "网卡选择:", "请选择需要监控的网卡！");
            return;
        }
        jpcap.NetworkInterface captor = devices[comboBox_net.getSelectionModel().getSelectedIndex()];

        //获取用户选择抓取得协议包
        String protocol = comboBox_protocol.getSelectionModel().getSelectedItem();
        if (protocol == null) {
            alertInformation("提示:", "协议选择:", "请选择抓取的协议包！");
            return;
        }

        //创建线程进行抓包
        if (threadPool != null && !threadPool.isTerminated()) {
            stop = true;
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("打算关闭之前线程！");
            tableView.getItems().clear();
        }
        threadPool = Executors.newCachedThreadPool();
        PacketCapture packetCapture = new PacketCapture(captor, protocol, tableView);
        stop = false;
        threadPool.execute(packetCapture);
        threadPool.shutdown();
    }

    /**
     * 抓包线程
     */
    class PacketCapture implements Runnable {
        NetworkInterface device;              //抓取的网卡
        TableView<tableRow> tableView;              //展示的视图控件
        String filterMess = "";                     //过滤的包

        //线程的初始化
        PacketCapture(NetworkInterface d, String protocol, TableView<tableRow> tv) {
            this.device = d;
            this.filterMess = protocol;
            this.tableView = tv;
        }

        @Override
        public void run() {
            try {
                //开启这个网卡设备
                JpcapCaptor captor = JpcapCaptor.openDevice(device, 200, true, 20);
                captor.setFilter(textField_filter.getText(), true);      //设置过滤规则
                while (!stop) {
//                    captor.loopPacket(1, new TestPacketReceiver(tableView, filterMess));
                    Packet packet = captor.getPacket();     //获取包
                    TestPacketReceiver testPacketReceiver = new TestPacketReceiver(tableView, filterMess, packet);
                    testPacketReceiver.run();
                }
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                System.out.println("过滤规则出错");
            }
        }
    }

    /**
     * 界面刷新线程
     */
    class TestPacketReceiver implements Runnable {
        TableView<tableRow> tableView;                        //展示的视图控件
        String filterMess = "";                     //过滤的包
        Packet packet;
        //ArrayList<Packet> packetList = new ArrayList<>();   //截获的包

        //抓包初始化
        TestPacketReceiver(TableView<tableRow> tableView, String filterMess, Packet packet) {
            this.tableView = tableView;
            this.filterMess = filterMess;
            this.packet = packet;
        }

        @Override
        public void run() {
            receivePacket(packet);
        }

        void receivePacket(Packet packet) {
            if (packet != null && TestFilter(packet)) {       //TestFilter 检测包是否为ICMP，UDP，TCP
                //packetList.add(packet);
                showTable(packet);
            }
        }

        //将抓到包的信息添加到列表
        void showTable(Packet packet) {
            String[] rowData = getObj(packet);
            if (rowData[0] != null) {
                tableRow tmp = new tableRow(rowData[0], rowData[1] + ":" + rowData[5], rowData[2] + ":" + rowData[6], rowData[3], rowData[4]);
                tableView.getItems().add(tmp);
            }
        }

        //设置过滤规则
        boolean TestFilter(Packet packet) {
            switch (filterMess) {
                case "ICMP":
                    if (new PacketAnalyze(packet).packetClass().get("协议").equals("ICMP")) {
                        return true;
                    }
                    break;
                case "UDP":
                    if (new PacketAnalyze(packet).packetClass().get("协议").equals("UDP")) {
                        return true;
                    }
                    break;
                case "TCP":
                    if (new PacketAnalyze(packet).packetClass().get("协议").equals("TCP")) {
                        return true;
                    }
                    break;
                case "All":
                    if (new PacketAnalyze(packet).packetClass() != null) {
                        return true;
                    }
            }
            return false;
        }

        //将抓的包的基本信息显示在列表上，返回信息的String[]形式
        String[] getObj(Packet packet) {
            String[] data = new String[8];
            if (packet != null) {
                HashMap<String, String> att = new PacketAnalyze(packet).packetClass();
                if (att != null && att.size() > 3) {
                    Date d = new Date();
                    DateFormat df = new SimpleDateFormat("HH:mm:ss");
                    data[0] = df.format(d);
                    data[1] = att.get("源IP");
                    data[2] = att.get("目的IP");
                    data[3] = att.get("协议");
                    data[4] = att.get("长度");
                    data[5] = att.get("源端口");
                    data[6] = att.get("目的端口");
                }
            }
            return data;
        }
    }

    /**
     * 抓包分析
     */
    class PacketAnalyze {
        Packet packet;
        HashMap<String, String> att;

        PacketAnalyze(Packet packet) {
            this.packet = packet;
        }

        HashMap<String, String> packetClass() {
            if (packet.getClass().equals(ICMPPacket.class)) {
                return ICMPAnalyze();
            } else if (packet.getClass().equals(TCPPacket.class)) {
                return TCPAnalyze();
            } else if (packet.getClass().equals(UDPPacket.class)) {
                return UDPAnalyze();
            }
            return null;
        }

//        HashMap<String, String> IPAnalyze() {
//            att = new HashMap<>();
//            if (packet instanceof IPPacket) {           //判断这个包是否是TCP包
//                IPPacket ippacket = (IPPacket) packet;  //它转换成TCP数据包
////                EthernetPacket ep = (EthernetPacket) packet.datalink;       //取出数据链路层的头部
//                att.put("协议", "IP");
//                att.put("源IP", ippacket.src_ip.toString().substring(1, ippacket.src_ip.toString().length()));
//                att.put("目的IP", ippacket.dst_ip.toString().substring(1, ippacket.dst_ip.toString().length()));
//                att.put("TTL", String.valueOf(ippacket.hop_limit));
//                att.put("长度", String.valueOf(ippacket.length));
//                att.put("是否有其他切片", String.valueOf(ippacket.more_frag));
//            }
//            return att;
//        }

        HashMap<String, String> ICMPAnalyze() {
            att = new HashMap<>();
            ICMPPacket icmppacket = (ICMPPacket) packet;
            EthernetPacket ethernetPacket = (EthernetPacket) icmppacket.datalink;
            att.put("协议", "ICMP");
            att.put("源IP", icmppacket.src_ip.toString().substring(1, icmppacket.src_ip.toString().length()));
            att.put("目的IP", icmppacket.dst_ip.toString().substring(1, icmppacket.dst_ip.toString().length()));
            att.put("长度", String.valueOf(icmppacket.length));
            att.put("源MAC", ethernetPacket.getSourceAddress());
            att.put("目的MAC", ethernetPacket.getDestinationAddress());
            att.put("源端口", "");
            att.put("目的端口", "");
            return att;
        }

        /**
         * TCP包分析
         */
        HashMap<String, String> TCPAnalyze() {
            att = new HashMap<>();
            TCPPacket tcppacket = (TCPPacket) packet;
            EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
            att.put("协议", "TCP");
            att.put("源IP", tcppacket.src_ip.toString().substring(1, tcppacket.src_ip.toString().length()));
            att.put("源端口", String.valueOf(tcppacket.src_port));
            att.put("目的IP", tcppacket.dst_ip.toString().substring(1, tcppacket.dst_ip.toString().length()));
            att.put("长度", String.valueOf(tcppacket.length));
            att.put("目的端口", String.valueOf(tcppacket.dst_port));
            att.put("源MAC", ethernetPacket.getSourceAddress());
            att.put("目的MAC", ethernetPacket.getDestinationAddress());
            try {
                att.put("数据", new String(tcppacket.data, "utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return att;
        }

        /**
         * UDP包分析
         */
        HashMap<String, String> UDPAnalyze() {
            att = new HashMap<>();
            UDPPacket udpppacket = (UDPPacket) packet;
            EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
            att.put("协议", "UDP");
            att.put("源IP", udpppacket.src_ip.toString().substring(1, udpppacket.src_ip.toString().length()));
            att.put("源端口", String.valueOf(udpppacket.src_port));
            att.put("目的IP", udpppacket.dst_ip.toString().substring(1, udpppacket.dst_ip.toString().length()));
            att.put("长度", String.valueOf(udpppacket.length));
            att.put("目的端口", String.valueOf(udpppacket.dst_port));
            att.put("源MAC", ethernetPacket.getSourceAddress());
            att.put("目的MAC", ethernetPacket.getDestinationAddress());
            try {
                att.put("数据", new String(udpppacket.data, "utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return att;
        }
    }

    /**
     * 表数据类
     */
    class tableRow {
        private final StringProperty time;
        private final StringProperty sourceIP;
        private final StringProperty destIP;
        private final StringProperty protocol;
        private final StringProperty length;

        tableRow(String t, String s, String d, String p, String l) {
            this.time = new SimpleStringProperty(t);
            this.destIP = new SimpleStringProperty(d);
            this.sourceIP = new SimpleStringProperty(s);
            this.protocol = new SimpleStringProperty(p);
            this.length = new SimpleStringProperty(l);
        }

        StringProperty timeProperty() {
            return time;
        }

        StringProperty sourceIPProperty() {
            return sourceIP;
        }

        StringProperty destIPProperty() {
            return destIP;
        }

        StringProperty protocolProperty() {
            return protocol;
        }

        StringProperty lengthProperty() {
            return length;
        }
    }

    public void showFilters() {
        alertInformation("提示", "过滤规则使用说明:", "1. 关键字tcp udp icmp src dst port length等\n" + "2. 单条规则后添加过滤数据，例如src 192.168.1.1,dst port 443\n" + "3. 多条过滤规则之间使用and进行连接！");
    }

    public void backMain() {
        stop = true;
        tableView.getItems().clear();
        stage.setScene(welcomeScene);
    }

    public void getAuthor() {
        alertInformation("作者", "网络课程设计小组", "Netzhangheng & RisanLi & WangShiJie");
    }

    public void getConnect() {
        alertInformation("联系方式", "Tel:", "xxxxxxx6670");
    }

    public void getVersion() {
        alertInformation("版本", "测试版:", "v0.1.0");
    }

    public void getUse() {
        alertInformation("使用说明", "帮助：", "1. 请选择抓取的包！\n" + "2. 选择自己正在联网的网卡，否则可以没有包流过网卡\n" + "3. 仅用于学习交流。谢谢！！！");
    }
}