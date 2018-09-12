package controllers;

import javafx.scene.control.*;

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
            public MenuItem menuItem_contect;
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
}
