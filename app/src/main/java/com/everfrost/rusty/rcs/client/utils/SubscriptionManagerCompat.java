package com.everfrost.rusty.rcs.client.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresPermission;

import com.everfrost.rusty.rcs.client.utils.log.LogService;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

public class SubscriptionManagerCompat {

    private static final String TAG = "SubscriptionManagerCompat";

    private static final boolean FIX_MNC_MCC_FOR_CHINA_TELECOM = true;

    public static final class SubscriptionInfoCompat {

        private static final String TAG = "SubscriptionInfoCompat";

        public final int slotId;

        public final int subscriptionId;

        public final String MSISDN;

        public final String IMSI;

        public final String IMEI;

        private final String MCC;

        public String getMcc() {
            return MCC;
        }

        private final String MNC;

        public String getMnc() {
            if (MNC.length() == 2) {
                return "0" + MNC;
            }
            return MNC;
        }

        public final boolean validated;

        public SubscriptionInfoCompat(int slotId, int subscriptionId, String MSISDN, String IMSI, String IMEI, String MCC, String MNC) {

            LogService.d(TAG, "create SubscriptionInfoCompat for slotId:" + slotId + " subscriptionId:" + subscriptionId + " with IMSI:" + IMSI + " IMEI:" + IMEI + " MCC:" + MCC + " MNC:" + MNC);

            boolean validated = false;

            if (IMSI != null && !IMSI.isEmpty() && IMEI != null && !IMEI.isEmpty() && MCC != null && MNC != null) {

                if (!"000".equals(MCC)) {

                    if (MNC.length() == 2) {

                        if (!IMSI.startsWith(MCC + MNC) && !IMSI.startsWith(MCC + "0" + MNC)) {

                            if ("460".equals(MCC) && "03".equals(MNC)) {

                                if (FIX_MNC_MCC_FOR_CHINA_TELECOM) {

                                    if (IMSI.length() >= 5) {

                                        MNC = IMSI.substring(3, 5);

                                        validated = true;

                                        LogService.w(TAG, "SIM card validated, resetting MNC to " + MNC);
                                    }
                                }
                            }

                        } else {

                            validated = true;

                            LogService.i(TAG, "SIM card validated");
                        }

                    } else if (MNC.length() == 3) {

                        if (IMSI.startsWith(MCC + MNC)) {

                            validated = true;

                            LogService.i(TAG, "SIM card validated");

                        } else {

                            if (FIX_MNC_MCC_FOR_CHINA_TELECOM) {

                                if ("460".equals(MCC) && "003".equals(MNC)) {

                                    if (FIX_MNC_MCC_FOR_CHINA_TELECOM) {

                                        if (IMSI.length() >= 6) {

                                            MNC = IMSI.substring(3, 6);

                                            validated = true;

                                            LogService.w(TAG, "SIM card validated, resetting MNC to " + MNC);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            this.slotId = slotId;

            this.subscriptionId = subscriptionId;

            this.MSISDN = MSISDN;

            this.IMSI = IMSI;
            this.IMEI = IMEI;

            this.MCC = MCC;
            this.MNC = MNC;

            this.validated = validated;
        }

        @NonNull
        @Override
        public String toString() {
            return "SubscriptionInfoCompat{" +
                    "slotId=" + slotId +
                    ", subscriptionId=" + subscriptionId +
                    ", MSISDN='" + MSISDN + '\'' +
                    ", IMSI='" + IMSI + '\'' +
                    ", IMEI='" + IMEI + '\'' +
                    ", MCC='" + MCC + '\'' +
                    ", MNC='" + MNC + '\'' +
                    ", validated=" + validated +
                    '}';
        }
    }

    private static String getMcc(SubscriptionInfo subscriptionInfo) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {

            String mccString = subscriptionInfo.getMccString();

            LogService.d(TAG, "getMccString:" + mccString);

            if (!TextUtils.isEmpty(mccString) && TextUtils.isDigitsOnly(mccString)) {

                if (mccString.length() == 3) {

                    return mccString;
                }
            }
        }

        int mcc = subscriptionInfo.getMcc();

        LogService.d(TAG, "Mcc:" + mcc);

        return String.format(Locale.ENGLISH, "%03d", mcc);
    }

    private static String getMnc(SubscriptionInfo subscriptionInfo) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {

            String mncString = subscriptionInfo.getMncString();

            LogService.d(TAG, "getMncString:" + mncString);

            if (!TextUtils.isEmpty(mncString) && TextUtils.isDigitsOnly(mncString)) {

                if (mncString.length() == 2 || mncString.length() == 3) {

                    return mncString;
                }
            }
        }

        int mnc = subscriptionInfo.getMnc();

        LogService.d(TAG, "Mnc:" + mnc);

        String mncString = String.format(Locale.ENGLISH, "%d", mnc);

        if (mncString.length() == 1) {

            return "0" + mncString;
        }

        return mncString;
    }

    @RequiresPermission(allOf = {"android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"})
    @SuppressLint({"DiscouragedPrivateApi", "HardwareIds"})
    private SubscriptionInfoCompat createSubscriptionInfoForSubscriptionInfo(SubscriptionInfo subscriptionInfo, TelephonyManager telephonyManager) {

        int slotId = subscriptionInfo.getSimSlotIndex();

        int subscriptionId = subscriptionInfo.getSubscriptionId();

        TelephonyManager telephonyManagerForSubscription;

        if (subscriptionId > 0) {

            telephonyManagerForSubscription = telephonyManager.createForSubscriptionId(subscriptionId);

        } else {

            telephonyManagerForSubscription = telephonyManager;
        }

        @SuppressLint("MissingPermission") String MSISDN = telephonyManagerForSubscription.getLine1Number();

        if (MSISDN == null) {

            try {

                MSISDN = (String) TelephonyManager.class.getDeclaredMethod("getMsisdn").invoke(telephonyManagerForSubscription);

            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {

                LogService.w(TAG, "getMsisdn e:", e);
            }
        }

        String IMSI = telephonyManagerForSubscription.getSubscriberId();

        @SuppressLint("MissingPermission") String IMEI = telephonyManagerForSubscription.getDeviceId();

        String MCC = getMcc(subscriptionInfo);

        String MNC = getMnc(subscriptionInfo);

        return new SubscriptionInfoCompat(slotId, subscriptionId, MSISDN, IMSI, IMEI, MCC, MNC);
    }

    private final List<SubscriptionInfoCompat> activeSubscriptions = Collections.synchronizedList(new LinkedList<>());

    private final TelephonyManager telephonyManager;

    private final SubscriptionManager subscriptionManager;

    @RequiresPermission(allOf = {"android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"})
    public SubscriptionManagerCompat(Context context) {

        telephonyManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

        subscriptionManager = (SubscriptionManager) context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
    }

    public interface OnSubscriptionsChangedListener {

        void onSubscriptionsChanged(List<SubscriptionInfoCompat> subscriptionInfoCompatList);
    }

    private final List<OnSubscriptionsChangedListener> listeners = new LinkedList<>();

    @RequiresPermission(allOf = {"android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"})
    public void register(OnSubscriptionsChangedListener onSubscriptionsChangedListener) {

        subscriptionManager.addOnSubscriptionsChangedListener(new SubscriptionManager.OnSubscriptionsChangedListener() {

            @Override
            public void onSubscriptionsChanged() {

                @SuppressLint("MissingPermission") List<SubscriptionInfo> activeSubscriptionInfoList = subscriptionManager.getActiveSubscriptionInfoList();

                if (activeSubscriptionInfoList != null) {

                    List<SubscriptionInfoCompat> subscriptionInfoCompatList = new LinkedList<>();

                    for (SubscriptionInfo subscriptionInfo : activeSubscriptionInfoList) {

                        @SuppressLint("MissingPermission") SubscriptionInfoCompat subscriptionInfoCompat = createSubscriptionInfoForSubscriptionInfo(subscriptionInfo, telephonyManager);

                        subscriptionInfoCompatList.add(subscriptionInfoCompat);
                    }

                    synchronized (activeSubscriptions) {

                        activeSubscriptions.clear();

                        activeSubscriptions.addAll(subscriptionInfoCompatList);

                        for (OnSubscriptionsChangedListener onSubscriptionsChangedListener : listeners) {

                            onSubscriptionsChangedListener.onSubscriptionsChanged(subscriptionInfoCompatList);
                        }
                    }
                }
            }
        });

        synchronized (activeSubscriptions) {

            listeners.add(onSubscriptionsChangedListener);

            List<SubscriptionInfoCompat> subscriptionInfoCompatList = new ArrayList<>(activeSubscriptions);

            onSubscriptionsChangedListener.onSubscriptionsChanged(subscriptionInfoCompatList);
        }
    }

    public static int getDefaultSubscriptionId(Context context) {
        int defaultSubscriptionId = SubscriptionManager.getDefaultDataSubscriptionId();
        if (defaultSubscriptionId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
            defaultSubscriptionId = SubscriptionManager.getDefaultSubscriptionId();
        }
        return defaultSubscriptionId;
    }
}
