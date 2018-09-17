package tools;

import javafx.scene.control.DialogPane;
import javafx.scene.control.TextField;

import javax.xml.soap.Text;
import java.beans.EventHandler;

/**
 * Created with IntelliJ IDEA.
 * User: Netzhang
 * Description:
 * Date: 2018-09-17
 * Time: 23:03
 */
public class Alert {
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
}
