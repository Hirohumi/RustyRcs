package com.everfrost.rusty.rcs.client.utils.log;

import android.util.Log;

class LoggerHolder {

    private static class DefaultLogger implements ILogger {

        private DefaultLogger() {

        }

        @Override
        public void v(String tag, String msg) {
            Log.v(tag, msg);
        }

        @Override
        public void v(String tag, String msg, Throwable tr) {
            Log.v(tag, msg, tr);
        }

        @Override
        public void d(String tag, String msg) {
            Log.d(tag, msg);
        }

        @Override
        public void d(String tag, String msg, Throwable tr) {
            Log.d(tag, msg, tr);
        }

        @Override
        public void i(String tag, String msg) {
            Log.i(tag, msg);
        }

        @Override
        public void i(String tag, String msg, Throwable tr) {
            Log.i(tag, msg, tr);
        }

        @Override
        public void w(String tag, String msg) {
            Log.w(tag, msg);
        }

        @Override
        public void w(String tag, String msg, Throwable tr) {
            Log.w(tag, msg, tr);
        }

        @Override
        public void w(String tag, Throwable tr) {
            Log.w(tag, tr);
        }

        @Override
        public void e(String tag, String msg) {
            Log.e(tag, msg);
        }

        @Override
        public void e(String tag, String msg, Throwable tr) {
            Log.e(tag, msg, tr);
        }

        @Override
        public int getLogLevel() {
            return Log.VERBOSE;
        }
    }

    private static volatile ILogger logger = new DefaultLogger();

    static void setILogger(ILogger iLogger) {

        logger = iLogger;
    }

    static ILogger getLogger() {

        return logger;
    }
}
