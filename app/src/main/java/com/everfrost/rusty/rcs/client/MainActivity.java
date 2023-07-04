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

import android.Manifest;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Bundle;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.everfrost.rusty.rcs.client.model.ChatbotSearchResultJson;
import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private long nativeClient;

    private String fileUploadTid;

    private int uploadFailureCount;

    private static MessageDigest getMessageDigestInstance() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "MessageDigest.init.Exception : ", e);
        }
        return null;
    }

    public static String bytesToHexString(byte[] bytes) {
        if (bytes != null) {
            StringBuilder stringBuilder = new StringBuilder();
            for (byte aByte : bytes) {
                int v = aByte & 0xFF;
                String hv = Integer.toHexString(v);
                if (hv.length() < 2) {
                    stringBuilder.append(0);
                }
                stringBuilder.append(hv);
            }
            return stringBuilder.toString();
        }
        return null;
    }

    public static String getMD5(byte[] bytes) {
        MessageDigest messageDigest = getMessageDigestInstance();
        if (messageDigest != null && bytes != null) {
            messageDigest.update(bytes);
            return bytesToHexString(messageDigest.digest());
        }
        return null;
    }

    private final ActivityResultLauncher<String[]> requestPermissionLauncher = registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> {
        if (result.containsValue(false)) {
            Log.w(TAG, "permission not granted");
        } else {
            initRustyRcs();
        }
    });

    private void initRustyRcs() {
        Log.d(TAG, "initRustyRcs");

        IntentFilter intentFilter = new IntentFilter("android.intent.action.DATA_SMS_RECEIVED");
        intentFilter.addDataScheme("sms");
        intentFilter.addDataAuthority("localhost", String.valueOf(SmsReceiver.DEFAULT_APPLICATION_PORT));
        intentFilter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY - 1);
        String broadcastPermission = "android.permission.BROADCAST_SMS";
        getApplicationContext().registerReceiver(new SmsReceiver(new SmsReceiver.Listener() {
            @Override
            public void onReceivedRcsConfigSms(int subId, String userId) {

                Log.i(TAG, "onReceivedRcsConfigSms on subscription" + subId);
            }

            @Override
            public void onReceivedOtp(int subId, String otp) {

                Log.i(TAG, "onReceivedOtp on subscription " + subId);

                RustyRcsClient.inputOtp(nativeClient, otp);
            }
        }), intentFilter, broadcastPermission, null);

        new Thread() {
            @Override
            public void run() {

                File temporaryDirectory;

                if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {

                    temporaryDirectory = new File(getExternalFilesDir("Rusty/Rcs"), "");

                } else {

                    temporaryDirectory = new File(getFilesDir(), "Rusty/Rcs" + File.separator + "");
                }

                temporaryDirectory.mkdirs();

                File certificateDirectory = new File(temporaryDirectory, "certs");

                certificateDirectory.mkdir();

                File certificatePath = new File(certificateDirectory, "cert.pem");

                certificatePath.delete();

                try (FileOutputStream fileOutputStream = new FileOutputStream(certificatePath)) {

                    try {

                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");

                        trustManagerFactory.init((KeyStore) null);

                        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

                        for (TrustManager trustManager :
                                trustManagers)
                        {
                            X509TrustManager x509TrustManager = (X509TrustManager) trustManager;

                            X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();

                            for (X509Certificate x509Certificate :
                                    acceptedIssuers) {

                                fileOutputStream.write("-----BEGIN CERTIFICATE-----\r\n".getBytes(StandardCharsets.US_ASCII));

//                                byte[] tbsCertificate = x509Certificate.getTBSCertificate();

                                byte[] encoded = x509Certificate.getEncoded();

                                byte[] bytes = Base64.encode(encoded, 0);

                                fileOutputStream.write(bytes);

                                fileOutputStream.write("-----END CERTIFICATE-----\r\n".getBytes(StandardCharsets.US_ASCII));
                            }
                        }

                    } catch (NoSuchAlgorithmException | KeyStoreException | CertificateEncodingException e) {

                        Log.w(TAG, "e:", e);
                    }

                } catch (IOException e) {

                }

                int mcc = getResources().getInteger(R.integer.mcc);
                int mnc = getResources().getInteger(R.integer.mnc);
                String imsi = getResources().getString(R.string.imsi);
                String imei = getResources().getString(R.string.imei);
                String msisdn = getResources().getString(R.string.msisdn);

                ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

                nativeClient = RustyRcsClient.createRcsClient(-1, mcc, mnc, imsi, imei, msisdn, temporaryDirectory.toString(), new RustyRcsClient.Listener() {
                    @Override
                    public void onStateChange(int state) {
                        Log.d(TAG, "onStateChange:" + state);
                    }

                    @Override
                    public void onMessage(int serviceType, long nativeHandle, String contactUri, String contentType, String contentBody, String messageId, String date, String from) {
                        Log.d(TAG, "onMessage from service:" + serviceType);
                        Log.d(TAG, "contactUri:" + contactUri);
                        Log.d(TAG, "contentType:" + contentType);
                        Log.d(TAG, "contentBody:" + contentBody);
                        Log.d(TAG, "imdn messageId:" + messageId);
                        Log.d(TAG, "cpim date:" + date);
                        Log.d(TAG, "cpim from:" + from);

                        lastReceivedMessageSessionHandle = nativeHandle;
                        lastReceivedMessageImdnId = messageId;
                        lastReceivedMessageDateTime = date;
                    }


                    @Override
                    public void onMultiConferenceV1Invite(long nativeHandle, byte[] offerSdp, long responseReceiverHandle) {
                        Log.d(TAG, "onMultiConferenceV1Invite");

                        Log.d(TAG, "offerSdp:" + new String(offerSdp, StandardCharsets.UTF_8));
                    }
                });
            }
        }.start();
    }

    private EditText editText;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editText = findViewById(R.id.search_text);

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED
            && ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
            && ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED) {
            initRustyRcs();
        } else {
            requestPermissionLauncher.launch(new String[] {Manifest.permission.INTERNET, Manifest.permission.READ_PHONE_STATE, Manifest.permission.RECEIVE_SMS});
        }
    }

    public void onClickedInit(View view) {

        RustyRcsClient.startConfig(nativeClient, new RustyRcsClient.ConfigListener() {
            @Override
            public void onProgress(int statusCode) {
                Log.d(TAG, "onConfigProgress:" + statusCode);
                if (statusCode == 1) {
                    // TODO: 2023/6/14 ready the UI for user to input ZeroPortSMS
                }
            }

            @Override
            public void onResult(int statusCode, String imsConfig, String rcsConfig, String extra) {
                Log.d(TAG, "onConfigResult:" + statusCode);
                if (statusCode == 0) {
                    RustyRcsClient.setup(nativeClient, imsConfig, rcsConfig);
                }
            }
        });
    }

    public void onClickedConnect(View view) {
        RustyRcsClient.connect(nativeClient);
    }

    public void onClickedDisconnect(View view) {
        RustyRcsClient.disconnect(nativeClient);
    }

    public void onClickedSendMessage(View view) {

        String toMsisdn = getResources().getString(R.string.to_msisdn);

        RustyRcsClient.sendMessage(nativeClient, "text/plain", "Hello, World!", "tel:" + toMsisdn, false, (statusCode, reasonPhrase) -> Log.d(TAG, "RustyRcsClient.sendMessage()->onResult: " + statusCode + " " + reasonPhrase));
    }

    private String lastReceivedMessageImdnId;

    private String lastReceivedMessageDateTime;

    private long lastReceivedMessageSessionHandle;

    public void onClickedSendIMDN(View view) {
        String imdnContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<imdn xmlns=\"urn:ietf:params:xml:ns:resource-lists\">" +
                "<message-id>" + lastReceivedMessageImdnId + "</message-id>" +
                "<datetime>" + lastReceivedMessageDateTime + "</datetime>" +
                "<delivery-notification>" +
                "<status>" + "<delivered />" + "</status>" +
                "</delivery-notification>" +
                "</imdn>";

        String toMsisdn = getResources().getString(R.string.to_msisdn);

        RustyRcsClient.sendImdnReport(nativeClient, imdnContent, "tel:" + toMsisdn, 1, lastReceivedMessageSessionHandle, (statusCode, reasonPhrase) -> Log.d(TAG, "RustyRcsClient.sendImdnReport()->onResult: " + statusCode + " " + reasonPhrase));
    }

    public void onClickedUploadFile(View view) {

        new Thread() {
            @Override
            public void run() {

                File temporaryDirectory;

                if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {

                    temporaryDirectory = new File(getExternalFilesDir("Rusty/Rcs"), "");

                } else {

                    temporaryDirectory = new File(getFilesDir(), "Rusty/Rcs" + File.separator + "");
                }

                temporaryDirectory.mkdirs();

                File file = new File(temporaryDirectory, "test_image.png");

                try (InputStream inputStream = getResources().openRawResource(R.raw.test_image)) {

                    try (FileOutputStream outputStream = new FileOutputStream(file)) {

                        byte[] bytes = new byte[4096];

                        do {

                            int r = inputStream.read(bytes);

                            if (r > 0)
                            {
                                outputStream.write(bytes, 0, r);
                            }
                            else
                            {
                                break;
                            }

                        } while(true);
                    }

                } catch (IOException e) {

                }

                File thumb = new File(temporaryDirectory, "test_thumbnail.png");

                try (InputStream inputStream = getResources().openRawResource(R.raw.test_thumbnail)) {

                    try (FileOutputStream outputStream = new FileOutputStream(thumb)) {

                        byte[] bytes = new byte[4096];

                        do {

                            int r = inputStream.read(bytes);

                            if (r > 0)
                            {
                                outputStream.write(bytes, 0, r);
                            }
                            else
                            {
                                break;
                            }

                        } while(true);
                    }

                } catch (IOException e) {

                }

                String filePath = file.toString();
                String thumbPath = thumb.toString();

                runOnUiThread(() -> {
                    if (fileUploadTid == null) {
                        fileUploadTid = UUID.randomUUID().toString();
                    }
                    RustyRcsClient.uploadFile(nativeClient, fileUploadTid, filePath, "image/png", null, thumbPath, "image/png", null, (statusCode, reasonPhrase, resultXml) -> {
                        Log.i(TAG, "RustyRcsClient.uploadFile()->onResult: " + statusCode + " " + reasonPhrase);
                        Log.i(TAG, "resultXml: " + resultXml);
                        runOnUiThread(() -> {
                            XmlPullParserFactory factory;
                            try {
                                factory = XmlPullParserFactory.newInstance();
                                factory.setNamespaceAware(true);
                                XmlPullParser xpp = factory.newPullParser();
                                xpp.setInput( new StringReader( resultXml ) );
                                int eventType = xpp.getEventType();
                                boolean readingFileInfo = false;
                                boolean readingThumbnailInfo = false;
                                while (eventType != XmlPullParser.END_DOCUMENT) {
                                    if (eventType == XmlPullParser.START_TAG) {
                                        if (xpp.getName().equals("file-info")) {
                                            readingFileInfo = false;
                                            readingThumbnailInfo = false;
                                            int count = xpp.getAttributeCount();
                                            for (int i = 0; i < count; i ++) {
                                                if (xpp.getAttributeName(i).equals("type")) {
                                                    if (xpp.getAttributeValue(i).equals("file")) {
                                                        readingFileInfo = true;
                                                    } else if (xpp.getAttributeValue(i).equals("thumbnail")) {
                                                        readingThumbnailInfo = true;
                                                    }
                                                }
                                            }
                                        } else if (xpp.getName().equals("data")) {
                                            int count = xpp.getAttributeCount();
                                            for (int i = 0; i < count; i ++) {
                                                if (xpp.getAttributeName(i).equals("url")) {
                                                    if (readingFileInfo) {
                                                        lastUploadedFileUrl = xpp.getAttributeValue(i);
                                                    }
                                                    if (readingThumbnailInfo) {
                                                        lastUploadedThumbnailUrl = xpp.getAttributeValue(i);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    eventType = xpp.next();
                                }
                            } catch (XmlPullParserException | IOException e) {
                                throw new RuntimeException(e);
                            }

                            if (statusCode == 200) {
                                fileUploadTid = null;
                            } else {
                                uploadFailureCount ++;
                                if (uploadFailureCount > 3) {
                                    fileUploadTid = null;
                                }
                            }
                        });
                    });
                });
            }
        }.start();
    }

    private String lastUploadedFileUrl;

    private String lastUploadedThumbnailUrl;

    public void onClickedDownloadFile(View view) {
        new Thread() {
            @Override
            public void run() {
                File temporaryDirectory;

                if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {

                    temporaryDirectory = new File(getExternalFilesDir("Rusty/Rcs"), "");

                } else {

                    temporaryDirectory = new File(getFilesDir(), "Rusty/Rcs" + File.separator + "");
                }

                temporaryDirectory.mkdirs();

                File file = new File(temporaryDirectory, "download_image.png");

                String filePath = file.toString();

                runOnUiThread(() -> RustyRcsClient.downloadFile(nativeClient, lastUploadedFileUrl, filePath, 0, 70117, (statusCode, reasonPhrase) -> Log.i(TAG, "RustyRcsClient.downloadFile()->onResult: " + statusCode + " " + reasonPhrase)));
            }
        }.start();
    }

    public void onClickedRetrieveSpecificChatbots(View view) {
        RustyRcsClient.retrieveSpecificChatbots(nativeClient, null, (statusCode, reasonPhrase, specificChatbots, responseETag, expiry) -> {
            Log.d(TAG, "RustyRcsClient.retrieveSpecificChatbots()->onResult: " + statusCode + " " + reasonPhrase);
            Log.d(TAG, "specificChatbots: " + specificChatbots);
            Log.d(TAG, "responseETag: " + responseETag);
            Log.d(TAG, "expiry: " + expiry);
        });
    }

    private ChatbotSearchResultJson.BotsJson bot;

    public void onClickedSearch(View view) {
        String query = editText.getText().toString();

        RustyRcsClient.searchChatbot(nativeClient, query, (statusCode, reasonPhrase, chatbotSearchResultList) -> {
            Log.d(TAG, "RustyRcsClient.searchChatbot()->onResult: " + statusCode + " " + reasonPhrase);

            byte[] jsonData = chatbotSearchResultList.getBytes(StandardCharsets.UTF_8);

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(jsonData);

            InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream, StandardCharsets.UTF_8);

            try {

                Gson gson = new Gson();

                JsonReader jsonReader = gson.newJsonReader(inputStreamReader);

                ChatbotSearchResultJson json = gson.fromJson(jsonReader, ChatbotSearchResultJson.class);

                ChatbotSearchResultJson.BotsJson[] bots = json.getBots();

                if (bots != null) {

                    for (ChatbotSearchResultJson.BotsJson bot : bots) {

                        Log.i(TAG, "bot: " + bot);
                    }

                    if (bots.length > 0) {
                        this.bot = bots[0];
                    }
                }

            } catch (JsonIOException | JsonSyntaxException e) {

                Log.w(TAG, "e:", e);
            }
        });
    }

    public void onClickedRetrieveChatbotInfo(View view) {
        RustyRcsClient.retrieveChatbotInfo(nativeClient, bot.id, null, (statusCode, reasonPhrase, chatbotInfo, responseETag, expiry) -> {
            Log.d(TAG, "RustyRcsClient.retrieveChatbotInfo()->onResult: " + statusCode + " " + reasonPhrase);
            Log.d(TAG, "chatbotInfo: " + chatbotInfo);
            Log.d(TAG, "responseETag: " + responseETag);
            Log.d(TAG, "expiry: " + expiry);
        });
    }

    public void onClickedDestroy(View view) {
        RustyRcsClient.disconnect(nativeClient);
        RustyRcsClient.destroy(nativeClient);
    }
}
