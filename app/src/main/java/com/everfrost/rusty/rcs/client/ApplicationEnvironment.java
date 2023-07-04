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

import android.annotation.SuppressLint;
import android.app.Application;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import java.net.InetAddress;
import java.util.List;

public class ApplicationEnvironment extends Application {
    static  {
        System.loadLibrary("native-lib");
    }

    private static final String TAG = "ApplicationEnvironment";

    private static native void registerHostEnvironment(ApplicationEnvironment factory);

    @Override
    public void onCreate() {
        super.onCreate();

        registerHostEnvironment(this);
    }

    public static class CellularNetworkRequestListener {
        public static native void onResult(long nativeHandle, boolean activated);
        private long nativeHandle;
        private CellularNetworkRequestListener(long nativeHandle) {
            this.nativeHandle = nativeHandle;
        }
    }

    public static class CellularNetworkRequest {
        private final ConnectivityManager connectivityManager;
        private final ConnectivityManager.NetworkCallback networkCallback;
        private final CellularNetworkRequestListener listener;
        private CellularNetworkRequest(ConnectivityManager connectivityManager, ConnectivityManager.NetworkCallback networkCallback, CellularNetworkRequestListener listener) {
            this.connectivityManager = connectivityManager;
            this.networkCallback = networkCallback;
            this.listener = listener;
        }
        public void release() {
            synchronized (listener) {
                if (listener.nativeHandle > 0L) {
                    CellularNetworkRequestListener.onResult(listener.nativeHandle, false);
                    listener.nativeHandle = 0L;
                }
            }
            connectivityManager.unregisterNetworkCallback(networkCallback);
        }
    }

    @SuppressLint("MissingPermission")
    public CellularNetworkRequest createNetworkRequest(long listenerHandle) {

        SubscriptionManager subscriptionManager = (SubscriptionManager) getSystemService(TELEPHONY_SUBSCRIPTION_SERVICE);

        SubscriptionInfo subscriptionInfo = subscriptionManager.getActiveSubscriptionInfoForSimSlotIndex(0);

        if (subscriptionInfo != null) {

            TelephonyManager telephonyManager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);

            int subId = subscriptionInfo.getSubscriptionId();

            telephonyManager = telephonyManager.createForSubscriptionId(subId);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

                String networkSpecifier = telephonyManager.getNetworkSpecifier();

                ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

                NetworkRequest request = new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR).setNetworkSpecifier(networkSpecifier).build();

                CellularNetworkRequestListener listener = new CellularNetworkRequestListener(listenerHandle);

                ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(@NonNull Network network) {
                        synchronized (listener) {
                            if (listener.nativeHandle > 0L) {
                                CellularNetworkRequestListener.onResult(listener.nativeHandle, true);
                                listener.nativeHandle = 0L;
                            }
                        }
                    }
                };

                connectivityManager.requestNetwork(request, networkCallback);

                return new CellularNetworkRequest(connectivityManager, networkCallback, listener);
            }
        }

        return null;
    }

    public Network getCurrentActiveNetwork() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            return connectivityManager.getActiveNetwork();
        }
        return null;
    }

    public static class DnsInfo {
        private int n = 0;
        private final List<InetAddress> dnsServers;
        public DnsInfo(List<InetAddress> dnsServers) {
            this.dnsServers = dnsServers;
        }
        public String getNextServerAddress() {
            if (n < dnsServers.size()) {
                InetAddress address = dnsServers.get(n);
                n ++;
                return address.getHostAddress() + ":53";
            }
            return null;
        }
    }

    public DnsInfo getDnsInfoFromNetwork(@NonNull Network network) {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
            List<InetAddress> dnsServers = linkProperties.getDnsServers();
            return new DnsInfo(dnsServers);
        }

        return null;
    }

    public int getNetworkType(@NonNull Network network) {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(network);
            if (networkCapabilities != null) {
                if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)) {
                            return 2; // PS
                        } else {
                            return 3; // PS Roaming
                        }
                    } else {
                        return 1; // Wi-Fi
                    }
                }
            }
        }

        return 0;
    }

    public byte[] getIccAuthentication(byte[] data, int subId) {

        String challenge = Base64.encodeToString(data, Base64.NO_WRAP);

        TelephonyManager telephonyManager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);

        if (subId > 0) {
            telephonyManager = telephonyManager.createForSubscriptionId(subId);
        }

        try {

            String authenticationRes = telephonyManager.getIccAuthentication(TelephonyManager.APPTYPE_USIM, TelephonyManager.AUTHTYPE_EAP_AKA, challenge);

            if (authenticationRes != null) {

                return Base64.decode(authenticationRes, Base64.DEFAULT);

            } else {

                Log.w(TAG, "getIccAuthentication not successful");
            }

        } catch (SecurityException e) {

            Log.w(TAG, "e:", e);
        }

        return null;
    }
}
