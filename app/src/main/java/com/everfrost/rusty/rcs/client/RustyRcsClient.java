package com.everfrost.rusty.rcs.client;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class RustyRcsClient {

    // Used to load the 'nativelib' library on application startup.
    static  {
        System.loadLibrary("native-lib");
    }

    public static final int STATE_NONE = 0;

    public static final int STATE_IN_PROCESS = 1;

    public static final int STATE_CONNECTED = 2;

    public static final int SERVICE_TYPE_ONE_TO_ONE_CHAT = 0;

    public static final int SERVICE_TYPE_STANDALONE = 1; // this is what you'll see most of the time

    public static final int SERVICE_TYPE_DEFERRED_ONE_TO_ONE_CHAT = 2;

    public static class MessagingSession {

        static native void destroy(long nativeHandle);
    }

    public interface MultiConferenceV1EventListener {
        void onUserJoined(String userId);
        void onUserLeft(String userId);
        void onConferenceEnded();
    }

    public static class MultiConferenceV1 {

        static native void destroy(long nativeHandle);
    }

    public static class MultiConferenceV1InviteResponseReceiver {

        static native void sendOkResponse(long nativeHandle, int statusCode, String answerSdp, MultiConferenceV1EventListener listener);

        static native void cancel(long nativeHandle);

        static native void free(long nativeHandle);
    }

    public interface Listener {
        void onStateChange(int state);
        void onMessage(int serviceType, long nativeHandle /* MessagingSession */, String contactUri, String contentType, String contentBody, String messageId, String date, String from);
        void onMultiConferenceV1Invite(long nativeHandle /* MultiConferenceV1 */, byte[] offerSdp, long responseReceiverHandle /* MultiConferenceV1InviteResponseReceiver */);
    }

    public static native long createRcsClient(int subId, int mcc, int mnc, String imsi, String imei, String msisdn, String dir, Listener listener);

    public interface ConfigListener {
        void onProgress(int statusCode);
        void onResult(int statusCode, String imsConfig, String rcsConfig, String extra);
    }

    public static native void startConfig(long nativeHandle, ConfigListener listener);

    public static native void inputOtp(long nativeHandle, String otp);

    public static native void setup(long nativeHandle, String imsConfig, String rcsConfig);

    public static native void connect(long nativeHandle);

    public static native void disconnect(long nativeHandle);

    public interface SendMessageListener {
        void onResult(int statusCode, String reasonPhrase);
    }

    public static final int RECIPIENT_TYPE_CONTACT = 0;

    public static final int RECIPIENT_TYPE_CHATBOT = 1;

    public static final int RECIPIENT_TYPE_GROUP = 2;

    public static final int RECIPIENT_TYPE_RESOURCE_LIST = 3;

    public static native void sendMessage(long nativeHandle, String messageType, String messageContent, String recipient, int recipientType, SendMessageListener listener);

    public interface SendImdnReportCallback {
        void onResult(int statusCode, String reasonPhrase);
    }

    public static native void sendImdnReport(long nativeHandle, String imdnContent, String senderUri, int senderServiceType, long senderSessionNativeHandle, SendImdnReportCallback callback);

    public interface UploadFileResultCallback {
        void onResult(int statusCode, String reasonPhrase, String resultXml);
    }

    public static native void uploadFile(long nativeHandle, @NonNull String tid, @NonNull String filePath, @NonNull String fileName, @NonNull String fileMime, @Nullable String fileHash, @Nullable String thumbnailPath, @Nullable String thumbnailName, @Nullable String thumbnailMime, @Nullable String thumbnailHash, UploadFileResultCallback callback);

    public interface DownloadFileResultCallback {
        void onResult(int statusCode, String reasonPhrase);
    }

    public static native void downloadFile(long nativeHandle, String dataUrl, String destinationPath, int start, int total, DownloadFileResultCallback callback);

    public interface CreateMultiConferenceV1ResultCallback {
        void onResult(long nativeHandle /* MultiConferenceV1 */, byte[] answerSdp);
    }

    static native void createMultiConferenceV1(long nativeHandle, String recipients, String offerSdp, MultiConferenceV1EventListener eventListener, CreateMultiConferenceV1ResultCallback callback);

    public interface RetrieveSpecificChatbotsResultCallback {
        void onResult(int statusCode, String reasonPhrase, String specificChatbots, String responseETag, int expiry);
    }

    static native void retrieveSpecificChatbots(long nativeHandle, String localETag, RetrieveSpecificChatbotsResultCallback callback);

    public interface SearchChatbotResultCallback {
        void onResult(int statusCode, String reasonPhrase, String chatbotSearchResultList);
    }

    static native void searchChatbot(long nativeHandle, String query, SearchChatbotResultCallback callback);

    public interface RetrieveChatbotInfoResultCallback {
        void onResult(int statusCode, String reasonPhrase, String chatbotInfo, String responseETag, int expiry);
    }

    static native void retrieveChatbotInfo(long nativeHandle, String chatbotSipUri, String localETag, RetrieveChatbotInfoResultCallback callback);

    public static native void destroy(long nativeHandle);

    public static class AsyncLatchHandle {

        public static native void wakeUp(long nativeHandle);

        public static native void destroy(long nativeHandle);
    }
}