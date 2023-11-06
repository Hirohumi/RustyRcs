package com.everfrost.rusty.rcs.client.utils.log;

public interface ILogger {

    void v(String tag, String msg);

    void v(String tag, String msg, Throwable tr);

    void d(String tag, String msg);

    void d(String tag, String msg, Throwable tr);

    void i(String tag, String msg);

    void i(String tag, String msg, Throwable tr);

    void w(String tag, String msg);

    void w(String tag, String msg, Throwable tr);

    void w(String tag, Throwable tr);

    void e(String tag, String msg);

    void e(String tag, String msg, Throwable tr);

    /**
     * 日志打印级别控制
     * <p></p>
     * @return 日志打印级别
     */
    int getLogLevel();
}
