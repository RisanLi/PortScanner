package controllers;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;

import java.io.IOException;

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

    public void selectPortScanner(Stage stage) throws IOException {
        Parent portScanner = FXMLLoader.load(getClass().getResource("View_portScanner.fxml"));
        Scene scene1 = new Scene(portScanner);
        stage.setScene(scene1);
    }

}
