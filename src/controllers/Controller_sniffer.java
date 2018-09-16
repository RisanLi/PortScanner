package controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.*;
import javafx.scene.control.cell.MapValueFactory;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.*;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.NetworkInterface;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static controllers.Main.devices;

/**
 * Created with IntelliJ IDEA.
 * User: RisanLi
 * Description:
 * Date: 2018-09-12
 * Time: 16:27
 */
public class Controller_sniffer {

    public Button button_sourceIP;
    public Button button_destIP;
    public Button button_start;
    public TableView<tablerow> tableview;
    public TableColumn<tablerow,String> tableColumn_time;
    public TableColumn<tablerow,String> tableColumn_sourceIP;
    public TableColumn<tablerow,String> tableColumn_destIP;
    public TableColumn<tablerow,String> tableColumn_protocol;
    public TableColumn<tablerow,String> tableColumn_length;
    public ComboBox<String> comboBox_net;
    public ComboBox<String> comboBox_protocol;

    public void selectNet(){
        comboBox_net.getItems().clear();
        for(jpcap.NetworkInterface i : devices){ comboBox_net.getItems().add(i.name);}
    }

    public void selectProtocol(){
        comboBox_protocol.getItems().addAll("TCP","UDP","ICMP");
    }

    public void start(){
        jpcap.NetworkInterface captor = devices[comboBox_net.getSelectionModel().getSelectedIndex()];
        String protocol = comboBox_protocol.getSelectionModel().getSelectedItem();
        PacketCapture packetCapture = new PacketCapture(captor,protocol,tableview);
        packetCapture.run();
    }




    class PacketCapture implements Runnable {

        jpcap.NetworkInterface device;
        TableView tableview;
        String FilterMess = "";
        ArrayList<Packet> packetlist = new ArrayList<Packet>();
        PacketCapture(jpcap.NetworkInterface d, String protocol,TableView tv) {   //传入设备和协议名
            this.device = d;
            this.FilterMess = protocol;
            this.tableview = tv;
        }
//        public void setTable(TableView tv){
//            this.tableview = tv;
//        }
//        public void setFilter(String FilterMess){
//            this.FilterMess = FilterMess;
//        }
        public void clearpackets(){
            packetlist.clear();
        }
        @Override
        public void run() {
            // TODO Auto-generated method stub
            Packet packet;
            try {
                JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535,true, 20);
                //System.out.println(device.name);
                while(true){
                    long startTime = System.currentTimeMillis();
                    while (startTime + 600 >= System.currentTimeMillis()) {
                        //captor.setFilter(FilterMess, true);
                        packet = captor.getPacket();

                        // 设置过滤器
                        if(packet!=null&&TestFilter(packet)){       //TestFilter 检测包是否为ICMP，UDP，TCP
                            //System.out.println(packet);
                            packetlist.add(packet);
                            showTable(packet);
                        }
                    }
                    Thread.sleep(2000);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //将抓到包的信息添加到列表
        void showTable(Packet packet){
            String[] rowData = getObj(packet);
//            tablemodel.addRow(rowData);
            ObservableList<tablerow> list = FXCollections.observableArrayList();
//            tablerow tr = new tablerow(rowData[0],rowData[1],rowData[2],rowData[3],rowData[4]);
            tablerow tr = new tablerow("1","2","3","4","5");
            list.add(tr);
            tableview.setItems(list);
//            System.out.println("tessssssssssssssst :      "+rowData[0]+rowData[1]+rowData[2]);
        }
        //其他类通过此方法获取Packet的列表
        public ArrayList<Packet> getpacketlist(){
            return packetlist;
        }
        //设置过滤规则
        boolean TestFilter(Packet packet){

            if(FilterMess.contains("ICMP")){
                if(new PacketAnalyze(packet).packetClass().get("协议").equals("ICMP")){
                    return true;
                }
            }
            else if(FilterMess.contains("UDP")){
                if(new PacketAnalyze(packet).packetClass().get("协议").equals("UDP")){
                    return true;
                }
            }else if(FilterMess.contains("TCP")){
                System.out.println(packet);
                if(new PacketAnalyze(packet).packetClass().get("协议").equals("TCP")){
                    return true;
                }
            }else if(FilterMess.equals("")){
                return true;
            }
            return false;
        }
        //将抓的包的基本信息显示在列表上，返回信息的String[]形式
        public  String[] getObj(Packet packet){
            String[] data = new String[5];
            if (packet != null&&new PacketAnalyze(packet).packetClass().size()>=3) {
                Date d = new Date();
                DateFormat df = new SimpleDateFormat("HH:mm:ss");
                data[0]=df.format(d);
                data[1]=new PacketAnalyze(packet).packetClass().get("源IP");
                data[2]=new PacketAnalyze(packet).packetClass().get("目的IP");
                data[3]=new PacketAnalyze(packet).packetClass().get("协议");
                data[4]=String.valueOf(packet.len);
            }
            return data;
        }
    }



  class PacketAnalyze {
        Packet packet;
        HashMap<String,String> att,att1;
        PacketAnalyze(Packet packet){
            this.packet = packet;
        }
        HashMap<String,String> packetClass(){
            att1 = new HashMap<String,String>();
            if(packet.getClass().equals(ICMPPacket.class)){
                att1 = ICMPanalyze();
            }else if(packet.getClass().equals(TCPPacket.class)){
                att1 = TCPanalyze();
            }else if(packet.getClass().equals(UDPPacket.class)){
                att1 = UDPanalyze();
            }
            return att;
        }
        HashMap<String,String> IPanalyze(){
            att = new HashMap<String,String>();
            if(packet instanceof IPPacket){
                IPPacket ippacket = (IPPacket) packet;
                att.put("协议", "IP");
                att.put("源IP", ippacket.src_ip.toString().substring(1, ippacket.src_ip.toString().length()));
                att.put("目的IP", ippacket.dst_ip.toString().substring(1, ippacket.dst_ip.toString().length()));
                att.put("TTL", String.valueOf(ippacket.hop_limit));
                att.put("头长度", String.valueOf(ippacket.header.length));
                att.put("是否有其他切片", String.valueOf(ippacket.more_frag));
            }
            return att;
        }
        HashMap<String,String> ICMPanalyze(){
            att = new HashMap<String,String>();
            ICMPPacket icmppacket = (ICMPPacket) packet;
            att.put("协议", "ICMP");
            att.put("源IP", icmppacket.src_ip.toString().substring(1, icmppacket.src_ip.toString().length()));
            att.put("目的IP", icmppacket.dst_ip.toString().substring(1, icmppacket.dst_ip.toString().length()));
            return att;
        }
        HashMap<String,String> TCPanalyze(){
            att = new HashMap<String,String>();
            TCPPacket tcppacket = (TCPPacket) packet;
            EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
            att.put("协议", new String("TCP"));
            att.put("源IP", tcppacket.src_ip.toString().substring(1, tcppacket.src_ip.toString().length()));
            att.put("源端口", String.valueOf(tcppacket.src_port));
            att.put("目的IP", tcppacket.dst_ip.toString().substring(1, tcppacket.dst_ip.toString().length()));
            att.put("目的端口", String.valueOf(tcppacket.dst_port));
            att.put("源MAC", ethernetPacket.getSourceAddress());
            att.put("目的MAC", ethernetPacket.getDestinationAddress());
            try {
                att.put("数据", new String(tcppacket.data,"utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return att;
        }
        HashMap<String,String> UDPanalyze(){
            att = new HashMap<String,String>();
            UDPPacket udpppacket = (UDPPacket) packet;
            EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
            att.put("协议", "UDP");
            att.put("源IP", udpppacket.src_ip.toString().substring(1, udpppacket.src_ip.toString().length()));
            att.put("源端口", String.valueOf(udpppacket.src_port));
            att.put("目的IP", udpppacket.dst_ip.toString().substring(1, udpppacket.dst_ip.toString().length()));
            att.put("目的端口", String.valueOf(udpppacket.dst_port));
            att.put("源MAC", ethernetPacket.getSourceAddress());
            att.put("目的MAC", ethernetPacket.getDestinationAddress());
            try {
                att.put("数据", new String(udpppacket.data,"utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }

            return att;
        }
    }

    public class tablerow{
        String time;
        String sourceIP;
        String destIP;
        String protocol;
        String length;

        tablerow(String t, String s, String d, String p, String l){
            this.time = t;
            this.destIP = d;
            this.sourceIP = s;
            this.length = l;
            this.protocol = p;
        }

        public String getTime() {
            return time;
        }

        public String getSourceIP() {
            return sourceIP;
        }

        public String getDestIP() {
            return destIP;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getLength() {
            return length;
        }
    }

    public void test(){
//        tablerow tr = new tablerow(rowData[0],rowData[1],rowData[2],rowData[3],rowData[4]);

        tableColumn_time = new TableColumn<>();
        tableColumn_sourceIP = new TableColumn<>();
        tableColumn_destIP = new TableColumn<>();
        tableColumn_protocol = new TableColumn<>();
        tableColumn_length = new TableColumn<>();
        tableColumn_length.setCellValueFactory(new PropertyValueFactory<>("length"));
        tableColumn_time.setCellValueFactory(new PropertyValueFactory<>("time"));
        tableColumn_sourceIP.setCellValueFactory(new PropertyValueFactory<>("sourceIP"));
        tableColumn_destIP.setCellValueFactory(new PropertyValueFactory<>("destIP"));
        tableColumn_protocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        tableColumn_length.setCellValueFactory(new PropertyValueFactory<>("length"));
        tableColumn_time.setCellFactory(TextFieldTableCell.forTableColumn());
        tableColumn_sourceIP.setCellFactory(TextFieldTableCell.forTableColumn());
        tableColumn_destIP.setCellFactory(TextFieldTableCell.forTableColumn());
        tableColumn_protocol.setCellFactory(TextFieldTableCell.forTableColumn());
        tableColumn_length.setCellFactory(TextFieldTableCell.forTableColumn());

        tablerow tr = new tablerow("1aaaa","2bbbb","3cccc","4ddddd","5eeee");
//        tableColumn_time.setCellValueFactory(new PropertyValueFactory<>("time"));

        tableview.getItems().add(tr);
    }
}


