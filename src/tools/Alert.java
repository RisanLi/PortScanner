package tools;

import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

import static tools.Utils.getDomainString;

/**
 * Created with IntelliJ IDEA.
 * User: Netzhang
 * Description:
 * Date: 2018-09-17
 * Time: 23:03
 */
public class Alert {
    public static String res;
    /**
     * 弹出提示框
     */
    public static void alertInformation(String title, String headerText, String contentText) {
        javafx.scene.control.Alert alert = new javafx.scene.control.Alert(javafx.scene.control.Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(headerText);
        alert.setContentText(contentText);
        alert.showAndWait();
    }

    /**
     * 弹出错误提示框
     */
    public static void alertError(String title, String headerText, String contentText) {
        javafx.scene.control.Alert alert = new javafx.scene.control.Alert(javafx.scene.control.Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(headerText);
        alert.setContentText(contentText);
        alert.showAndWait();
    }

    public static String display(String title, String message) {
        res = null;
        Stage stage = new Stage();          //设置一个舞台
        stage.initModality(Modality.APPLICATION_MODAL);
        stage.setTitle(title);

        Label label = new Label();          //添加控件
        label.setText(message);
        TextField field = new TextField();
        Button button = new Button("筛选");
            button.setOnMouseClicked(event -> {
                if (field.getText()==null){
                    alertError("Error","输入错误","请输入IP！");
                }else{
                    res =  getDomainString(field.getText());
                    if (res==null){
                        alertError("Error","输入错误","请输入符合规范的IP！");
                    }else{
                        stage.close();
                    }
                }
            });
        VBox vBox = new VBox();             //添加布局
        vBox.getChildren().addAll(label, field, button);
//        vBox.setAlignment(Pos.BASELINE_LEFT);
        stage.centerOnScreen();
        Scene scene = new Scene(vBox, 150, 200);      //添加场景
        stage.setScene(scene);      //舞台设置场景
        stage.showAndWait();        //展示并只能使用该窗体
        return res;
    }
}
