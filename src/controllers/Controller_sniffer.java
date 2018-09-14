package controllers;

import javafx.collections.FXCollections;
import javafx.scene.control.*;
import javafx.scene.control.cell.MapValueFactory;
import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.*;

import java.io.IOException;
import java.net.NetworkInterface;
import java.util.*;

import static controllers.Main.map;

/**
 * Created with IntelliJ IDEA.
 * User: RisanLi
 * Description:
 * Date: 2018-09-12
 * Time: 16:27
 */
public class Controller_sniffer {
    public MenuBar menu_menu;
//    public TableView tableview;
//    public TableColumn tableColumn_time;
//    public TableColumn tableColumn_source;
//    public TableColumn tableColumn_destination;
//    public TableColumn tableColumn_protocal;
//    public TableColumn tableColumn_data;
    public TextArea textArea;
    public Button button_start;
    public Button button_terminate;
    public ChoiceBox choiceBox;
    boolean stop;
    public String s = "";
    // 开启一个静态线程，能够让buttonStart和buttonTerminate控制
    //将每个Captor放到独立线程中运行
    public void  startCapThread(final JpcapCaptor jpcap ){
        JpcapCaptor jp=jpcap;
        java.lang.Runnable rnner= new Runnable(){         //创建线程
            public void run(){
                //使用接包处理器循环抓包
                while(stop){
                    jpcap.processPacket(1,new TestPacketReceiver(map.get(choiceBox.getValue())));
                }
//                jpcap.loopPacket(stop,new TestPacketReceiver(map.get(choiceBox.getValue())) );   //-1无限抓取包，抓包监听器获取包
            }
        };
        new Thread(rnner).start();//启动抓包线程

    }

    public void setChoiceBox(){
        choiceBox.setTooltip(new Tooltip("选择包类型"));

        choiceBox.setItems(FXCollections.observableArrayList("TCP","UDP","ICMP"));
    }

    public void buttonStart() {
        stop = true;
        try {
            //获取本机上的网络接口对象数组
            final jpcap.NetworkInterface[] devices = JpcapCaptor.getDeviceList();
            for (int i = 0; i < devices.length; i++) {
                jpcap.NetworkInterface nc = devices[i];
                //创建某个卡口上的抓取对象,最大为2000个
                JpcapCaptor jpcap = JpcapCaptor.openDevice(nc, 5, true, 20);
                startCapThread(jpcap);       //线程执行抓包
                System.out.println("开始抓取第" + i + "个卡口上的数据");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void buttonTerminate(){
        stop = false;
    }


    class TestPacketReceiver  implements PacketReceiver {

        public int model;

        public TestPacketReceiver(int n) {
            this.model = n;
        }

        /**
         * 实现的接包方法:
         */
        public void receivePacket(Packet packet) {
            //Tcp包
            if (packet instanceof jpcap.packet.TCPPacket && model == 1) {
                TCPPacket p = (TCPPacket) packet;
                s += "TCPPacket:| 目的ip及端口 " + p.dst_ip + ":" + p.dst_port
                        + "|源ip及端口 " + p.src_ip + ":" + p.src_port
                        + " |数据长度: " + p.len + "\n";
                textArea.setText(s);
                System.out.println(s);
            }
            //UDP包
            else if (packet instanceof jpcap.packet.UDPPacket && model == 2) {
                UDPPacket p = (UDPPacket) packet;
                s += "UDPPacket:| 目的ip及端口 " + p.dst_ip + ":" + p.dst_port
                        + "||源ip及端口 " + p.src_ip + ":" + p.src_port
                        + " |数据长度: " + p.len+"\n";
                textArea.setText(s);
                System.out.println(s);
            }
            //ICMPPacket包
            else if (packet instanceof jpcap.packet.ICMPPacket && model == 3) {
                ICMPPacket p = (ICMPPacket) packet;
                //ICMP包的路由链
                String router_ip = "";
                for (int i = 0; i < p.router_ip.length; i++) {
                    router_ip += " " + p.router_ip[i].getHostAddress();
                }
                s += "@ @ @ ICMPPacket:| 路由IP: " + router_ip
                        + " |redir_ip: " + p.redir_ip
                        + " |最大传输单元: " + p.mtu
                        + " |长度: " + p.len + "\n";
                textArea.setText(s);
                System.out.println(s);
            }
            //ARP请求包
            else if (packet instanceof jpcap.packet.ARPPacket && model == 4) {
                ARPPacket p = (ARPPacket) packet;
                //Returns the hardware address (MAC address) of the sender
                Object saa = p.getSenderHardwareAddress();
                Object taa = p.getTargetHardwareAddress();
                s = "* * * ARPPacket:| 发送硬件地址： " + saa
                        + "|目标硬件地址： " + taa
                        + " |长度: " + p.len + "\n";
                textArea.setText(s);
                System.out.println(s);

            }
            //取得链路层数据头 :如果你想局网抓包或伪造数据包，嘿嘿
            DatalinkPacket datalink = packet.datalink;
            //如果是以太网包
            if (datalink instanceof jpcap.packet.EthernetPacket) {
                EthernetPacket ep = (EthernetPacket) datalink;
                s += "  以太包: "
                        + "|目的MAC: " + ep.getDestinationAddress()
                        + "|源MAC: " + ep.getSourceAddress() + "\n";
                textArea.setText(s);
                System.out.println(s);
            }
        }
    }
}


