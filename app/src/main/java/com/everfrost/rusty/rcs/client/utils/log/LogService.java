package com.everfrost.rusty.rcs.client.utils.log;

import android.content.Context;
import android.os.Environment;

import androidx.annotation.NonNull;

import android.util.Log;

import com.everfrost.rusty.rcs.client.BuildConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class LogService {

    private static final String TAG = "LogService";
    private static final String ROOT_DIR = "Rusty";
    private static final String LOG_DIRECTORY_TYPE = "log";
    private static final String LEVEL_V = "V";
    private static final String LEVEL_D = "D";
    private static final String LEVEL_I = "I";
    private static final String LEVEL_W = "W";
    private static final String LEVEL_E = "E";

    private static final ThreadFactory threadFactory = r -> {

        Thread thread = new Thread(r);

        thread.setPriority(Thread.MIN_PRIORITY);

        return thread;
    };

    private static final ThreadPoolExecutor mExecutor = new ThreadPoolExecutor(0, 1, 5, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), threadFactory, (r, executor) -> {
        if (r instanceof FutureTask<?>) {
            ((FutureTask<?>) r).cancel(true);
        }
    });

    public static void init(Context context) {
        init(context, null);
    }

    public static void init(Context context, ILogger iLogger) {
        mExecutor.execute(() -> {
            try {
                String externalStorageState = Environment.getExternalStorageState();
                if (Environment.MEDIA_MOUNTED.equals(externalStorageState)) {
                    File externalFilesDir = context.getExternalFilesDir(ROOT_DIR);
                    if (externalFilesDir != null) {
                        LOG_DIR = new File(externalFilesDir, LOG_DIRECTORY_TYPE);
                        Log.v(TAG, "external log dir:" + LOG_DIR);
                    } else {
                        File filesDir = context.getFilesDir();
                        LOG_DIR = new File(filesDir, ROOT_DIR + File.separator + LOG_DIRECTORY_TYPE);
                        Log.v(TAG, "internal log dir:" + LOG_DIR);
                    }
                } else {
                    File filesDir = context.getFilesDir();
                    LOG_DIR = new File(filesDir, ROOT_DIR + File.separator + LOG_DIRECTORY_TYPE);
                    Log.v(TAG, "internal log dir:" + LOG_DIR);
                }

                if (LOG_DIR != null) {
                    LOG_DIR.mkdirs();
                }
            } catch (SecurityException e) {
                Log.w(TAG, "init SecurityException: ", e);
            }
        });

        if (iLogger == null) {
            iLogger = new LoggerImpl();
        }

        Logger.setILogger(iLogger);

        Thread.setDefaultUncaughtExceptionHandler(new CrashExceptionHandler());

        deleteExpiredLogFile();
    }

    private static class Format {
        private static final String LOG_MSG_DATE_FORMAT = "MM-dd HH:mm:ss.SSS";
        private static final String LOG_FILE_NAME_FORMAT_LONG = "yyyyMMdd'T'HHmmss";
        private static final String LOG_FILE_NAME_FORMAT_SHORT = "yyyyMMdd";
    }

    private static Date getDate(String dateString, String pattern) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
        return sdf.parse(dateString);
    }

    private static void deleteExpiredLogFile() {
        mExecutor.execute(() -> {
            try {
                if (LOG_DIR != null) {
                    if (LOG_DIR.exists() && LOG_DIR.isDirectory()) {
                        File[] files = LOG_DIR.listFiles();
                        if (files != null) {
                            for (File file : files) {
                                String name = file.getName();
                                if (!name.isEmpty()) {
                                    try {
                                        Date date = getDate(name, Format.LOG_FILE_NAME_FORMAT_SHORT);
                                        long timeDiff = System.currentTimeMillis() - date.getTime();
                                        Log.i(TAG, "deleteExpiredLogFile timeDiff: " + timeDiff);
                                        if (timeDiff >= 30 * 24 * 60 * 60 * 1000L) {
                                            removeFile(file);
                                        }
                                    } catch (ParseException e) {
                                        Log.w(TAG, "deleteExpiredLogFile ParseException: ", e);
                                        removeFile(file);
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (SecurityException e) {
                Log.w(TAG, "deleteExpiredLogFile SecurityException: ", e);
            }
        });
    }

    private static void removeFile(File file) {
        // 如果是文件直接删除
        if (file.isFile()) {
            file.delete();
            return;
        }
        // 如果是目录，递归判断，如果是空目录，直接删除，如果是文件，遍历删除
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files) {
                    removeFile(f);
                }
            }
            file.delete();
        }
    }

    public static void v(String tag, String msg) {
        if (getLogLevel() <= Log.VERBOSE) {
            Log.v(tag, msg);
            writeLogMsg(LEVEL_V, tag, msg, null);
        }
    }

    public static void v(String tag, String msg, Throwable tr) {
        if (getLogLevel() <= Log.VERBOSE) {
            Log.v(tag, msg, tr);
            writeLogMsg(LEVEL_V, tag, msg, tr);
        }
    }

    public static void d(String tag, String msg) {
        if (getLogLevel() <= Log.DEBUG) {
            Log.d(tag, msg);
            writeLogMsg(LEVEL_D, tag, msg, null);
        }
    }

    public static void d(String tag, String msg, Throwable tr) {
        if (getLogLevel() <= Log.DEBUG) {
            Log.d(tag, msg, tr);
            writeLogMsg(LEVEL_D, tag, msg, tr);
        }
    }

    public static void i(String tag, String msg) {
        if (getLogLevel() <= Log.INFO) {
            Log.i(tag, msg);
            writeLogMsg(LEVEL_I, tag, msg, null);
        }
    }

    public static void i(String tag, String msg, Throwable tr) {
        if (getLogLevel() <= Log.INFO) {
            Log.i(tag, msg, tr);
            writeLogMsg(LEVEL_I, tag, msg, tr);
        }
    }

    public static void w(String tag, String msg) {
        if (getLogLevel() <= Log.WARN) {
            Log.w(tag, msg);
            writeLogMsg(LEVEL_W, tag, msg, null);
        }
    }

    public static void w(String tag, String msg, Throwable tr) {
        if (getLogLevel() <= Log.WARN) {
            Log.w(tag, msg, tr);
            writeLogMsg(LEVEL_W, tag, msg, tr);
        }
    }

    public static void w(String tag, Throwable tr) {
        if (getLogLevel() <= Log.WARN) {
            Log.w(tag, tr);
            writeLogMsg(LEVEL_W, tag, null, tr);
        }
    }

    public static void e(String tag, String msg) {
        if (getLogLevel() <= Log.ERROR) {
            Log.e(tag, msg);
            writeLogMsg(LEVEL_E, tag, msg, null);
        }
    }

    public static void e(String tag, String msg, Throwable tr) {
        if (getLogLevel() <= Log.ERROR) {
            Log.e(tag, msg, tr);
            writeLogMsg(LEVEL_E, tag, msg, tr);
        }
    }

    private static int getLogLevel() {
        return Logger.getLogLevel();
    }

    private static File LOG_DIR = null;

    private static File LOG_FILE = null;

    private static FileWriter LOG_WRITER = null;

    private static long CHECK_POINT = 0L;

    private static void refreshLogFile(boolean force) throws IOException {

        Date now = new Date();

        if (force || CHECK_POINT <= now.getTime()) {

            String dateTime = new SimpleDateFormat(Format.LOG_FILE_NAME_FORMAT_LONG, Locale.US).format(now);

            File logFile = new File(LOG_DIR, dateTime + ".log");

            if (logFile.exists()) {
                return;
            }

            if (LOG_WRITER != null) {
                LOG_WRITER.close();
            }

            LOG_WRITER = new FileWriter(logFile, true);

            LOG_FILE = logFile;

            Calendar calendar = Calendar.getInstance();

            int dayOfMonth = calendar.get(Calendar.DAY_OF_MONTH);

            calendar.set(Calendar.DAY_OF_MONTH, dayOfMonth + 1);

            calendar.set(Calendar.HOUR_OF_DAY, 0);
            calendar.set(Calendar.MINUTE, 0);
            calendar.set(Calendar.SECOND, 0);
            calendar.set(Calendar.MILLISECOND, 0);

            CHECK_POINT = calendar.getTimeInMillis();
        }
    }

    public interface OnZipFileCreatedListener {

        void onCreated(File file);
    }

    public static void createZip(OnZipFileCreatedListener listener) {

        mExecutor.execute(() -> {

            try {

                if (LOG_DIR == null) {
                    return;
                }

                try {
                    refreshLogFile(true);
                } catch (IOException e) {
                    Log.w(TAG, "createZip IOException: ", e);
                }

                Date now = new Date();

                String dateTime = new SimpleDateFormat(Format.LOG_FILE_NAME_FORMAT_SHORT, Locale.US).format(now);

                File zipFile;

                int idx = 1;

                do {

                    zipFile = new File(LOG_DIR, dateTime + "." + idx + ".zip");

                    idx ++;

                } while (zipFile.exists());

                try (FileOutputStream fileOutputStream = new FileOutputStream(zipFile)) {

                    try (ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream)) {

                        if (LOG_DIR.exists() && LOG_DIR.isDirectory()) {

                            File[] files = LOG_DIR.listFiles();

                            if (files != null) {

                                for (File file : files) {

                                    if (file.equals(LOG_FILE)) {
                                        continue;
                                    }

                                    String fileName = file.getName();

                                    if (fileName.endsWith(".zip")) {
                                        continue;
                                    }

                                    try (FileInputStream fileInputStream = new FileInputStream(file)) {

                                        ZipEntry zipEntry = new ZipEntry(fileName);

                                        zipOutputStream.putNextEntry(zipEntry);

                                        byte[] bytes = new byte[4096];

                                        int result;

                                        do {

                                            result = fileInputStream.read(bytes);

                                            if (result > 0) {

                                                zipOutputStream.write(bytes, 0, result);
                                            }

                                        } while (result > 0);

                                        zipOutputStream.closeEntry();

                                    } catch (IOException e) {
                                        Log.w(TAG, "createZip IOException: ", e);
                                    }
                                }
                            }
                        }
                    }

                } catch (IOException e) {
                    Log.w(TAG, "createZip IOException: ", e);
                }

                listener.onCreated(zipFile);

                return;

            } catch (SecurityException e) {
                Log.w(TAG, "createZip SecurityException: ", e);
            }

            listener.onCreated(null);
        });
    }

    /**
     * 日志写入文件
     * @param tag TAG
     * @param msg 内容
     */
    private static void writeLogMsg(String level, String tag, String msg, Throwable tr) {
        if (BuildConfig.VERBOSE_LOG) {
            writeToFile(level, tag, msg, tr);
        }
    }

    private static void writeToFile(final String level, final String tag, final String msg, final Throwable tr) {

        mExecutor.execute(() -> {

            try {

                String externalStorageState = Environment.getExternalStorageState();
                if (!Environment.MEDIA_MOUNTED.equals(externalStorageState)) {
                    return;
                }

                if (LOG_DIR == null) {
                    return;
                }

                try {
                    refreshLogFile(false);
                } catch (IOException e) {
                    Log.w(TAG, "writeToFile IOException: ", e);
                }

                if (LOG_WRITER == null) {
                    return;
                }

                try {
                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(Format.LOG_MSG_DATE_FORMAT, Locale.US);
                    StringBuilder sb = new StringBuilder();
                    sb.append(level).append(" ").append(simpleDateFormat.format(new Date())).append(": ").
                            append(android.os.Process.myPid()).append(" ")
                            .append(android.os.Process.myTid()).append(" ").append(tag).append(" ").append(msg);
                    if (tr != null) {
                        sb.append(System.lineSeparator()).append(Log.getStackTraceString(tr));
                    }
                    sb.append(System.lineSeparator());

                    String str = sb.toString();

                    LOG_WRITER.write(str);

                    LOG_WRITER.flush();

                } catch (NullPointerException | IllegalArgumentException | IOException e) {
                    Log.w(TAG, "writeToFile NullPointerException: IllegalArgumentException: IOException: ", e);
                }

            } catch (SecurityException e) {
                Log.w(TAG, "writeToFile SecurityException: ", e);
            }
        });
    }

    public static class LoggerImpl implements ILogger {

        @Override
        public void v(String tag, String msg) {
            LogService.v(tag, msg);
        }

        @Override
        public void v(String tag, String msg, Throwable tr) {
            LogService.v(tag, msg, tr);
        }

        @Override
        public void d(String tag, String msg) {
            LogService.d(tag, msg);
        }

        @Override
        public void d(String tag, String msg, Throwable tr) {
            LogService.d(tag, msg, tr);
        }

        @Override
        public void i(String tag, String msg) {
            LogService.i(tag, msg);
        }

        @Override
        public void i(String tag, String msg, Throwable tr) {
            LogService.i(tag, msg, tr);
        }

        @Override
        public void w(String tag, String msg) {
            LogService.w(tag, msg);
        }

        @Override
        public void w(String tag, String msg, Throwable tr) {
            LogService.w(tag, msg, tr);
        }

        @Override
        public void w(String tag, Throwable tr) {
            LogService.w(tag, tr);
        }

        @Override
        public void e(String tag, String msg) {
            LogService.e(tag, msg);
        }

        @Override
        public void e(String tag, String msg, Throwable tr) {
            LogService.e(tag, msg, tr);
        }

        @Override
        public int getLogLevel() {
            return BuildConfig.VERBOSE_LOG ? Log.VERBOSE : Log.INFO;
        }
    }

    private static class CrashExceptionHandler implements Thread.UncaughtExceptionHandler {

        private static final String TAG = "CrashExceptionHandler";

        @Override
        public void uncaughtException(@NonNull Thread t, @NonNull Throwable e) {
            LogService.e(TAG, "uncaughtException: ", e);
        }
    }
}
