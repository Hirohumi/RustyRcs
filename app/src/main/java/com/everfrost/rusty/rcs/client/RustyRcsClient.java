/*
 *    Copyright 2023 宋昊文
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.everfrost.rusty.rcs.client;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class RustyRcsClient {
    static  {
        System.loadLibrary("native-lib");
    }

    public static final int STATE_NONE = 0;

    public static final int STATE_CONFIGURED = 1;

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

    static native long createRcsClient(int subId, int mcc, int mnc, String imsi, String imei, String msisdn, String dir, Listener listener);

    public interface ConfigListener {
        void onProgress(int statusCode);
        void onResult(int statusCode, String imsConfig, String rcsConfig, String extra);
    }

    static native void startConfig(long nativeHandle, ConfigListener listener);

    static native void inputOtp(long nativeHandle, String otp);

    static native void setup(long nativeHandle, String imsConfig, String rcsConfig);

    static native void connect(long nativeHandle);

    static native void disconnect(long nativeHandle);

    public interface SendMessageListener {
        void onResult(int statusCode, String reasonPhrase);
    }

    static native void sendMessage(long nativeHandle, String messageType, String messageContent, String recipient, boolean recipientIsChatbot, SendMessageListener listener);

    public interface SendImdnReportCallback {
        void onResult(int statusCode, String reasonPhrase);
    }

    static native void sendImdnReport(long nativeHandle, String imdnContent, String senderUri, int senderServiceType, long senderSessionNativeHandle, SendImdnReportCallback callback);

    public interface UploadFileResultCallback {
        void onResult(int statusCode, String reasonPhrase, String resultXml);
    }

    static native void uploadFile(long nativeHandle, @NonNull String tid, @NonNull String filePath, @NonNull String fileMime, @Nullable String fileHash, @Nullable String thumbnailPath, @Nullable String thumbnailMime, @Nullable String thumbnailHash, UploadFileResultCallback callback);

    public interface DownloadFileResultCallback {
        void onResult(int statusCode, String reasonPhrase);
    }

    static native void downloadFile(long nativeHandle, String dataUrl, String destinationPath, int start, int total, DownloadFileResultCallback callback);

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

    static native void destroy(long nativeHandle);
}
