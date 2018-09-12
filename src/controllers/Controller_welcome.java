package controllers;

import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;


/**
 * Created with IntelliJ IDEA.
 * User: Netzhang
 * Description:
 * Date: 2018-09-12
 * Time: 16:25
 */
public class Controller_welcome {
    public Button button_portScanner;
    public Button button_sniffer;

    public void selectPortScanner(){
        Main.stage.setScene(Main.portScannerScene);
    }

    public void selectSniffer(){
        Main.stage.setScene(Main.snifferScene);
    }
}
