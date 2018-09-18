package tools;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with IntelliJ IDEA.
 * User: Netzhang
 * Description:
 * Date: 2018-09-18
 * Time: 10:53
 */
public class Utils {
    /**
     * 根据输入的字符串提取出其中的域名字符串或者IP字符串，如：www.baidu.com或者baidu.com或者192.168.2.1
     *
     * @param str 输入的包含域名的字符串
     * @return 域名或IP字符串
     */
    public static String getDomainString(String str) {
        //先判断是不是IP
        String reg = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
        Pattern pattern = Pattern.compile(reg);
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            return matcher.group();
        }
        //不是则判断是不是域名
        reg = "[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+";
        pattern = Pattern.compile(reg);
        matcher = pattern.matcher(str);
        if (matcher.find()) {
            return matcher.group();
        }
        //都不是就返回null
        return null;
    }
}
