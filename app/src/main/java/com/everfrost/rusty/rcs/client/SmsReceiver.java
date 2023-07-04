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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import androidx.annotation.NonNull;

import java.lang.reflect.InvocationTargetException;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG = "SmsReceiver";

    public static final int DEFAULT_APPLICATION_PORT = 37273;

    public interface Listener {
        void onReceivedRcsConfigSms(int subId, String userId);
        void onReceivedOtp(int subId, String otp);
    }

    @NonNull
    private final Listener listener;

    public SmsReceiver(@NonNull Listener listener) {
        super();
        this.listener = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {

        String action = intent.getAction();

        Log.i(TAG, "onReceive:" + action);

        if (Telephony.Sms.Intents.DATA_SMS_RECEIVED_ACTION.equals(action)) {

            SmsMessage[] smsMessages = Telephony.Sms.Intents.getMessagesFromIntent(intent);

            if (smsMessages != null) {

                for (SmsMessage smsMessage :
                        smsMessages) {

                    int subscriptionId = - 1;

                    try {

                        Integer i = (Integer) SmsMessage.class.getDeclaredMethod("getSubId").invoke(smsMessage);

                        if (i != null) {
                            subscriptionId = i;
                        }

                    } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {

                        Log.e(TAG, "e:", e);
                    }

                    Log.v(TAG, "subscriptionId:" + subscriptionId);

                    String messageBody = smsMessage.getMessageBody();

                    Log.v(TAG, "messageBody:" + messageBody);

                    if (messageBody != null && !messageBody.isEmpty()) {

                        // TODO: 2020/4/10 Support FQDN

                        if (messageBody.endsWith("-rcscfg")) {

                            String USER_ID = messageBody.substring(0, messageBody.length() - 7);

                            listener.onReceivedRcsConfigSms(subscriptionId, USER_ID);

                        } else {

                            listener.onReceivedOtp(subscriptionId, messageBody);
                        }
                    }
                }
            }
        }
    }
}
