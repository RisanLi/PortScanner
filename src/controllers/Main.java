package controllers;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class Main extends Application {
    static Stage stage;
    static Scene welcomeScene;
    static Scene portScannerScene;
    static Scene snifferScene;
    static NetworkInterface[] devices;

    @Override
    public void start(Stage primaryStage) throws Exception {
        stage = primaryStage;

        FXMLLoader welcomeFxmlLoader = new FXMLLoader(getClass().getResource("../views/View_welcome.fxml"));
        Parent welcomeRoot = welcomeFxmlLoader.load();
        welcomeScene = new Scene(welcomeRoot);

        FXMLLoader portScannerFxmlLoader = new FXMLLoader(getClass().getResource("../views/View_portScanner.fxml"));
        Parent portScannerRoot = portScannerFxmlLoader.load();
        portScannerScene = new Scene(portScannerRoot);

        FXMLLoader snifferFxmlLoader = new FXMLLoader(getClass().getResource("../views/View_sniffer.fxml"));
        Parent snifferRoot = snifferFxmlLoader.load();
        snifferScene = new Scene(snifferRoot);

        stage.setTitle("网络课设-端口扫描工具");
        stage.setScene(welcomeScene);
        stage.getIcons().add(new Image("file:" + System.getProperty("user.dir") + "\\images\\title.png"));
        stage.show();
    }

    public static void main(String[] args) {
        devices = JpcapCaptor.getDeviceList();
        launch(args);
    }
}
