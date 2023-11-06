package com.everfrost.rusty.rcs.client.utils.log;

import android.util.Log;

public class Logger {

    public static void setILogger(ILogger iLogger) {

        LoggerHolder.setILogger(iLogger);
    }

    public static void v(String tag, String msg) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.VERBOSE) {
            logger.v(tag, msg);
        }
    }

    public static void v(String tag, String msg, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.VERBOSE) {
            logger.v(tag, msg, tr);
        }
    }

    public static void d(String tag, String msg) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.DEBUG) {
            logger.d(tag, msg);
        }
    }

    public static void d(String tag, String msg, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.DEBUG) {
            logger.d(tag, msg, tr);
        }
    }

    public static void i(String tag, String msg) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.INFO) {
            logger.i(tag, msg);
        }
    }

    public static void i(String tag, String msg, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.INFO) {
            logger.i(tag, msg, tr);
        }
    }

    public static void w(String tag, String msg) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.WARN) {
            logger.w(tag, msg);
        }
    }

    public static void w(String tag, String msg, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.WARN) {
            logger.w(tag, msg, tr);
        }
    }

    public static void w(String tag, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.WARN) {
            logger.w(tag, tr);
        }
    }

    public static void e(String tag, String msg) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.ERROR) {
            logger.e(tag, msg);
        }
    }

    public static void e(String tag, String msg, Throwable tr) {
        ILogger logger = LoggerHolder.getLogger();
        if (logger.getLogLevel() <= Log.ERROR) {
            logger.e(tag, msg, tr);
        }
    }

    public static int getLogLevel() {
        ILogger logger = LoggerHolder.getLogger();
        return logger.getLogLevel();
    }
}
