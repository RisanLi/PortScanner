package controllers;

import controllers.Controller_portScanner;
import controllers.Controller_welcome;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {
    static Stage stage;
    static Scene welcomeScene;
    static Scene portScannerScene;
    static Scene snifferScene;
    @Override
    public void start(Stage primaryStage) throws Exception{
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

        stage.setScene(welcomeScene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
