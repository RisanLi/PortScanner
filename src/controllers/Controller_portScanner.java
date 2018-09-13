package controllers;
import javafx.scene.control.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    public TextArea textArea_scanProcess;
    public TextArea textArea_result;

    public void startScan(){
        textArea_scanProcess.setText("");
        textArea_result.setText("");

    }


    /**
     * 根据输入的字符串提取出其中的域名字符串或者IP字符串，如：www.baidu.com或者baidu.com或者192.168.2.1
     * @param str 输入的包含域名的字符串
     * @return 域名或IP字符串
     * */
    public static String getDomainString(String str){
        //先判断是不是IP
        String reg = "^((25[0-5])|(2[0-4]\\\\d)|(1\\\\d\\\\d)|([1-9]\\\\d)|\\\\d)(\\\\.((25[0-5])|(2[0-4]\\\\d)|(1\\\\d\\\\d)|([1-9]\\\\d)|\\\\d)){3}$|^([a-zA-Z0-9]([a-zA-Z0-9\\\\-]{0,61}[a-zA-Z0-9])?\\\\.)+[a-zA-Z]{2,6}$";

        Pattern pattern = Pattern.compile(reg);
        Matcher matcher = pattern.matcher(str);
        if(matcher.find()){
            return matcher.group();
        }
        //不是则判断是不是域名
        reg="[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\\\.?";
        pattern = Pattern.compile(reg);
        matcher = pattern.matcher(str);
        if(matcher.find()){
            return matcher.group();
        }
        //都不是就返回null
        return "";
    }
}
