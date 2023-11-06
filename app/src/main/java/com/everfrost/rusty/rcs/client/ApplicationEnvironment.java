package com.everfrost.rusty.rcs.client;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
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

import androidx.annotation.NonNull;

import com.everfrost.rusty.rcs.client.utils.log.LogService;
import com.everfrost.rusty.rcs.client.RustyRcsClient;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

public class ApplicationEnvironment {

    static {
        System.loadLibrary("nativelib");
    }

    private static final String LOG_TAG = "ApplicationEnvironment";

    public static native void registerHostEnvironment(ApplicationEnvironment factory);

    private final Application application;

    private Selector socketSelector;

    private static final Executor executor = Executors.newSingleThreadExecutor();

    public ApplicationEnvironment(Application application) {
        this.application = application;

        try {
            socketSelector = Selector.open();
        } catch (IOException e) {
            LogService.w(LOG_TAG, "failed to open socket channel selector", e);
        }

        new Thread() {
            @Override
            public void run() {
                while (true) {
                    try {
                        socketSelector.select();
                        Set<SelectionKey> selectedKeys = socketSelector.selectedKeys();
                        Iterator<SelectionKey> iterator = selectedKeys.iterator();
                        while (iterator.hasNext()) {
                            SelectionKey key = iterator.next();
                            Object attachment = key.attachment();
                            if (attachment instanceof Long) {
                                long nativeHandle = (Long) attachment;
                                if (key.isConnectable()) {
                                    RustyRcsClient.SocketEventReceiver.onConnectAvailable(nativeHandle);
                                }
                                if (key.isReadable()) {
                                    RustyRcsClient.SocketEventReceiver.onReadAvailable(nativeHandle);
                                }
                                if (key.isWritable()) {
                                    RustyRcsClient.SocketEventReceiver.onWriteAvailable(nativeHandle);
                                }
                            }

                            if (attachment instanceof SocketSSLEngine) {
                                SocketSSLEngine socketSSLEngine = (SocketSSLEngine) attachment;
                                if (key.isConnectable()) {
                                    RustyRcsClient.SocketEventReceiver.onConnectAvailable(socketSSLEngine.asyncHandle);
                                }
                                if (key.isReadable()) {
                                    socketSSLEngine.onReadAvailable(key);
                                }
                                if (key.isWritable()) {
                                    socketSSLEngine.onWriteAvailable(key);
                                }
                            }

                            iterator.remove();
                        }
                    } catch (IOException e) {
                        LogService.w(LOG_TAG, "error processing sockets:", e);
                    }
                }
            }
        }.start();
    }

    public static void debugLog(String tag, String msg) {
        LogService.d(tag, msg);
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

        SubscriptionManager subscriptionManager = (SubscriptionManager) application.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);

        SubscriptionInfo subscriptionInfo = subscriptionManager.getActiveSubscriptionInfoForSimSlotIndex(0);

        if (subscriptionInfo != null) {

            TelephonyManager telephonyManager = (TelephonyManager) application.getSystemService(Context.TELEPHONY_SERVICE);

            int subId = subscriptionInfo.getSubscriptionId();

            telephonyManager = telephonyManager.createForSubscriptionId(subId);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

                String networkSpecifier = telephonyManager.getNetworkSpecifier();

                ConnectivityManager connectivityManager = (ConnectivityManager) application.getSystemService(Context.CONNECTIVITY_SERVICE);

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
        ConnectivityManager connectivityManager = (ConnectivityManager) application.getSystemService(Context.CONNECTIVITY_SERVICE);
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
        ConnectivityManager connectivityManager = (ConnectivityManager) application.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
            if (linkProperties != null) {
                List<InetAddress> dnsServers = linkProperties.getDnsServers();
                return new DnsInfo(dnsServers);
            }
        }

        return null;
    }

    public int getNetworkType(@NonNull Network network) {
        ConnectivityManager connectivityManager = (ConnectivityManager) application.getSystemService(Context.CONNECTIVITY_SERVICE);
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

    public static class SocketSSLEngine {

        private final SSLEngine engine;

        private final ByteBuffer readBuffer;

        private final Object decryptionLock = new Object();

        private final ByteBuffer decrypted;

        private boolean readFailed = false;

        private final ByteBuffer writeBuffer;

        private final Object encryptionLock = new Object();

        private final ByteBuffer encrypted;

        private boolean writeFailed = false;

        private final Object statusLock = new Object();

        private final long asyncHandle;

        private SocketSSLEngine(SSLEngine engine, long asyncHandle) {
            this.engine = engine;
            this.asyncHandle = asyncHandle;

            final int ioBufferSize = 32 * 1024;

            readBuffer = ByteBuffer.allocate(ioBufferSize);

            decrypted = ByteBuffer.allocate(ioBufferSize);

            writeBuffer = ByteBuffer.allocate(ioBufferSize);

            encrypted = ByteBuffer.allocate(ioBufferSize);
        }

        public void onReadAvailable(SelectionKey key) {

            try (Channel channel = key.channel()) {

                if (channel instanceof ReadableByteChannel) {

                    ReadableByteChannel readableByteChannel = (ReadableByteChannel) channel;

                    readableByteChannel.read(readBuffer);

                    readBuffer.flip();

                    SSLEngineResult.HandshakeStatus handshakeStatus;

                    synchronized (statusLock) {
                        handshakeStatus = engine.getHandshakeStatus();
                    }

                    boolean handshakeIsNotFinishedBefore = handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED;

                    int r;

                    synchronized (decryptionLock) {

                        r = decrypt();
                    }

                    if (handshakeIsNotFinishedBefore) {

                        synchronized (statusLock) {
                            handshakeStatus = engine.getHandshakeStatus();
                        }

                        boolean handshakeIsFinishedAfter = handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED;

                        if (handshakeIsFinishedAfter) {

                            RustyRcsClient.SocketEventReceiver.onHandshakeAvailable(asyncHandle);
                        }
                    }

                    if (r > 0) {

                        RustyRcsClient.SocketEventReceiver.onReadAvailable(asyncHandle);
                    }
                }

            } catch (IOException e) {
                LogService.w(LOG_TAG, "cannot retrieve a readable channel");
            }
        }

        public void onWriteAvailable(SelectionKey key) {

            try (Channel channel = key.channel()) {

                if (channel instanceof WritableByteChannel) {

                    WritableByteChannel writableByteChannel = (WritableByteChannel) channel;

                    synchronized (encryptionLock) {

                        encrypted.flip();

                        int r = writableByteChannel.write(encrypted);

                        if (r > 0) {
                            encrypted.compact();

                            RustyRcsClient.SocketEventReceiver.onWriteAvailable(asyncHandle);
                        }
                    }
                }

            } catch (IOException e) {
                LogService.w(LOG_TAG, "cannot retrieve a writeable channel");
            }
        }

        public int decrypt() {

            try {
                SSLEngineResult result = engine.unwrap(readBuffer, decrypted);
                SSLEngineResult.Status status = result.getStatus();
                if (status == SSLEngineResult.Status.OK) {
                    readBuffer.compact();
                    return result.bytesProduced();
                } else if (status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    return -1;
                } else if (status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    return 0;
                } else if (status == SSLEngineResult.Status.CLOSED) {
                    return -1;
                }
            } catch (SSLException e) {
                LogService.w(LOG_TAG, "error decrypting ssl packets");
            }

            return -1;
        }

        public int encrypt() {

            try {
                SSLEngineResult result = engine.wrap(writeBuffer, encrypted);
                SSLEngineResult.Status status = result.getStatus();
                if (status == SSLEngineResult.Status.OK) {
                    writeBuffer.compact();
                    return result.bytesConsumed();
                } else if (status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    return 0;
                } else if (status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    return -1;
                } else if (status == SSLEngineResult.Status.CLOSED) {
                    return -1;
                }
            } catch (SSLException e) {
                LogService.w(LOG_TAG, "error encrypting ssl packets");
            }

            return -1;
        }
    }

    public static class AsyncSocket {

        private final SocketChannel socketChannel;

        private final SocketSSLEngine socketSSLEngine;

        private AsyncSocket(SocketChannel socketChannel, SocketSSLEngine socketSSLEngine) {

            this.socketChannel = socketChannel;

            this.socketSSLEngine = socketSSLEngine;
        }

        public int connect(String remoteHost, int remotePort) {

            InetSocketAddress inetSocketAddress = new InetSocketAddress(remoteHost, remotePort);

            try {
                socketChannel.connect(inetSocketAddress);
                return 0;
            } catch (IOException e) {
                LogService.w(LOG_TAG, "error attempting to connect to address " + inetSocketAddress);
            }

            return -1;
        }

        public int finishConnect() {

            try {
                if (socketChannel.finishConnect()) {
                    return 0;
                } else {
                    return 114; // EALREADY
                }
            } catch (IOException e) {
                LogService.w(LOG_TAG, "error attempting to finish connection");
            }

            return -1;
        }

        public int startHandshake() {

            if (socketSSLEngine != null) {

                try {
                    socketSSLEngine.engine.beginHandshake();
                    return 0;
                } catch (SSLException e) {
                    LogService.w(LOG_TAG, "error attempting handshake", e);
                }

                return -1;

            } else {

                return 0;
            }
        }

        public int finishHandshake() {

            if (socketSSLEngine != null) {

                SSLEngineResult.HandshakeStatus handshakeStatus;

                synchronized (socketSSLEngine.statusLock) {
                    handshakeStatus = socketSSLEngine.engine.getHandshakeStatus();
                }

                if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                    return 0;
                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {

                    LogService.i(LOG_TAG, "need to perform some task");

                    Runnable task = socketSSLEngine.engine.getDelegatedTask();

                    executor.execute(() -> {

                        task.run();

                        LogService.i(LOG_TAG, "task complete");

                        RustyRcsClient.SocketEventReceiver.onHandshakeAvailable(socketSSLEngine.asyncHandle);
                    });

                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {

                    synchronized (socketSSLEngine.encryptionLock) {

                        int r = socketSSLEngine.encrypt();

                        if (r >= 0) {

                            if (socketSSLEngine.encrypted.position() != 0) {

                                socketSSLEngine.encrypted.flip();

                                try {
                                    socketChannel.write(socketSSLEngine.encrypted);
                                    socketSSLEngine.encrypted.compact();

                                    synchronized (socketSSLEngine.statusLock) {
                                        handshakeStatus = socketSSLEngine.engine.getHandshakeStatus();
                                        if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                                            return 0;
                                        }
                                    }

                                    return 114;
                                } catch (IOException e) {
                                    LogService.w(LOG_TAG, "error writing tls socket:", e);
                                }
                            }
                        }
                    }

                    return - 1;

                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {

                    return 114;

                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                    try {
                        socketSSLEngine.engine.beginHandshake();
                    } catch (SSLException e) {
                        LogService.w(LOG_TAG, "error attempting handshake", e);
                    }

                    return 114; // EALREADY
                }

                return -1;

            } else {

                return 0;
            }
        }

        public int read(byte[] bytes) {

            if (socketSSLEngine != null) {

                synchronized (socketSSLEngine.decryptionLock) {

                    int remaining = socketSSLEngine.decrypted.remaining();

                    if (remaining > 0) {

                        socketSSLEngine.decrypted.flip();

                        socketSSLEngine.decrypted.get(bytes);

                        int after = socketSSLEngine.decrypted.remaining();

                        if (after < remaining) {
                            socketSSLEngine.decrypted.compact();
                            return remaining - after;
                        } else {
                            return 0;
                        }
                    } else {
                        return 0;
                    }
                }

            } else {

                ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

                try {

                    return socketChannel.read(byteBuffer);

                } catch (NotYetConnectedException e) {

                    return 0;

                } catch (IOException e) {

                    LogService.w(LOG_TAG, "error reading socket:", e);
                }
            }

            return - 1;
        }

        public int write(byte[] bytes) {

            if (socketSSLEngine != null) {

                socketSSLEngine.writeBuffer.put(bytes);

                socketSSLEngine.writeBuffer.flip();

                synchronized (socketSSLEngine.encryptionLock) {

                    int r = socketSSLEngine.encrypt();

                    if (r > 0) {

                        socketSSLEngine.encrypted.flip();

                        try {
                            socketChannel.write(socketSSLEngine.encrypted);
                            socketSSLEngine.encrypted.compact();
                            return r;
                        } catch (IOException e) {
                            LogService.w(LOG_TAG, "error writing tls socket:", e);
                        }

                    } else {

                        return r;
                    }
                }

            } else {

                try {

                    ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

                    return socketChannel.write(byteBuffer);

                } catch (NotYetConnectedException e) {

                    return 0;

                } catch (IOException e) {

                    LogService.w(LOG_TAG, "error writing socket:", e);
                }
            }

            return - 1;
        }

        public int close() {

            try {

                socketChannel.close();

                return 0;

            } catch (IOException e) {

                LogService.w(LOG_TAG, "error closing socket:", e);
            }

            return - 1;
        }

        public static class SocketInfo {
            public final int af;
            public final String lAddr;
            public final int lPort;

            private SocketInfo(int af, String lAddr, int lPort) {
                this.af = af;
                this.lAddr = lAddr;
                this.lPort = lPort;
            }
        }

        public SocketInfo getSocketInfo() {

            try {
                SocketAddress localSocketAddress = socketChannel.getLocalAddress();

                if (localSocketAddress instanceof InetSocketAddress) {

                    InetSocketAddress localInetSocketAddress = (InetSocketAddress) localSocketAddress;

                    InetAddress inetAddress = localInetSocketAddress.getAddress();

                    String localAddress = inetAddress.getHostAddress();

                    int localPort = localInetSocketAddress.getPort();

                    if (inetAddress instanceof Inet4Address) {
                        return new SocketInfo(2, localAddress, localPort);
                    } else if (inetAddress instanceof Inet6Address) {
                        return new SocketInfo(10, localAddress, localPort);
                    }
                }
            } catch (IOException e) {
                LogService.w(LOG_TAG, "cannot get socket info, maybe not bound:", e);
            }

            return null;
        }

        private CipherSuiteCoding getSessionCipherSuite() {
            if (socketSSLEngine != null) {
                synchronized (socketSSLEngine.statusLock) {
                    SSLSession sslSession = socketSSLEngine.engine.getHandshakeSession();
                    String cipherSuite = sslSession.getCipherSuite();
                    return CipherSuiteCoding.get(cipherSuite);
                }
            }
            return null;
        }
    }

    public AsyncSocket createSocket(long asyncHandle, boolean useTLS, String hostName) {

        try {

            SocketChannel socketChannel = SocketChannel.open();

            if (socketChannel != null) {

                socketChannel.configureBlocking(false);

                if (useTLS) {

                    SSLEngine engine = SSLContext.getDefault().createSSLEngine();
                    engine.setUseClientMode(true);
                    SSLParameters sslParameters = new SSLParameters();
                    SNIServerName sniServerName = new SNIHostName(hostName);
                    sslParameters.setServerNames(Collections.singletonList(sniServerName));
                    engine.setSSLParameters(sslParameters);

                    SocketSSLEngine socketSSLEngine = new SocketSSLEngine(engine, asyncHandle);

                    socketChannel.register(socketSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE | SelectionKey.OP_CONNECT, socketSSLEngine);

                    return new AsyncSocket(socketChannel, socketSSLEngine);

                } else {

                    socketChannel.register(socketSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE | SelectionKey.OP_CONNECT, asyncHandle);

                    return new AsyncSocket(socketChannel, null);
                }
            }

        } catch (IOException | NoSuchAlgorithmException e) {

            LogService.w(LOG_TAG, "error creating socket:", e);
        }

        return null;
    }

    public byte[] getIccAuthentication(byte[] data, int subId) {

        String challenge = Base64.encodeToString(data, Base64.NO_WRAP);

        TelephonyManager telephonyManager = (TelephonyManager) application.getSystemService(Context.TELEPHONY_SERVICE);

        if (subId > 0) {
            telephonyManager = telephonyManager.createForSubscriptionId(subId);
        }

        try {

            String authenticationRes = telephonyManager.getIccAuthentication(TelephonyManager.APPTYPE_USIM, TelephonyManager.AUTHTYPE_EAP_AKA, challenge);

            if (authenticationRes != null) {

                return Base64.decode(authenticationRes, Base64.DEFAULT);

            } else {

                LogService.w(LOG_TAG, "getIccAuthentication not successful");
            }

        } catch (SecurityException e) {

            LogService.w(LOG_TAG, "e:", e);
        }

        return null;
    }

    public enum CipherSuiteCoding {

        SSL_NULL_WITH_NULL_NULL ("SSL_NULL_WITH_NULL_NULL", 0x00, 0x00),
        TLS_NULL_WITH_NULL_NULL ("TLS_NULL_WITH_NULL_NULL", 0x00, 0x00),

        SSL_RSA_WITH_NULL_MD5 ("SSL_RSA_WITH_NULL_MD5", 0x00, 0x01),
        TLS_RSA_WITH_NULL_MD5 ("TLS_RSA_WITH_NULL_MD5", 0x00, 0x01),

        SSL_RSA_WITH_NULL_SHA ("SSL_RSA_WITH_NULL_SHA", 0x00, 0x02),
        TLS_RSA_WITH_NULL_SHA ("TLS_RSA_WITH_NULL_SHA", 0x00, 0x02),

        SSL_RSA_EXPORT_WITH_RC4_40_MD5 ("SSL_RSA_EXPORT_WITH_RC4_40_MD5", 0x00, 0x03),
        TLS_RSA_EXPORT_WITH_RC4_MD5 ("TLS_RSA_EXPORT_WITH_RC4_MD5", 0x00, 0x03),

        SSL_RSA_WITH_RC4_128_MD5 ("SSL_RSA_WITH_RC4_128_MD5", 0x00, 0x04),
        TLS_RSA_WITH_RC4_128_MD5 ("TLS_RSA_WITH_RC4_128_MD5", 0x00, 0x04),

        SSL_RSA_WITH_RC4_128_SHA ("SSL_RSA_WITH_RC4_128_SHA", 0x00, 0x05),
        TLS_RSA_WITH_RC4_128_SHA ("TLS_RSA_WITH_RC4_128_SHA", 0x00, 0x05),

        SSL_RSA_EXPORT_WTIH_RC2_CBC_40_MD5 ("SSL_RSA_EXPORT_WTIH_RC2_CBC_40_MD5", 0x00, 0x06),
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0x00, 0x06),

        SSL_RSA_WITH_IDEA_CBC_SHA ("SSL_RSA_WITH_IDEA_CBC_SHA", 0x00, 0x07),
        TLS_RSA_WITH_IDEA_CBC_SHA ("TLS_RSA_WITH_IDEA_CBC_SHA", 0x00, 0x07),

        SSL_RSA_EXPORT_WITH_DES40_CBC_SHA ("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x08),
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x08),

        SSL_RSA_WITH_DES_CBC_SHA ("SSL_RSA_WITH_DES_CBC_SHA", 0x00, 0x09),
        TLS_RSA_WITH_DES_CBC_SHA ("TLS_RSA_WITH_DES_CBC_SHA", 0x00, 0x09),

        SSL_RSA_WITH_3DES_EDE_CBC_SHA ("SSL_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x0A),
        TLS_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x0A),

        SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA ("SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x0B),
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA ("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x0B),

        SSL_DH_DSS_WITH_DES_CBC_SHA ("SSL_DH_DSS_WITH_DES_CBC_SHA", 0x00, 0x0C),
        TLS_DH_DSS_WITH_DES_CBC_SHA ("TLS_DH_DSS_WITH_DES_CBC_SHA", 0x00, 0x0C),

        SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA ("SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA", 0x00, 0x0D),
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA ("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA ", 0x00, 0x0D),

        SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA ("SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x0E),
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA ("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x0E),

        SSL_DH_RSA_WITH_DES_CBC_SHA ("SSL_DH_RSA_WITH_DES_CBC_SHA", 0x00, 0x0F),
        TLS_DH_RSA_WITH_DES_CBC_SHA ("TLS_DH_RSA_WITH_DES_CBC_SHA", 0x00, 0x0F),

        SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA ("SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x10),
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x10),

        SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA ("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x11),
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA ("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x11),

        SSL_DHE_DSS_WITH_DES_CBC_SHA ("SSL_DHE_DSS_WITH_DES_CBC_SHA", 0x00, 0x12),
        TLS_DHE_DSS_WITH_DES_CBC_SHA ("TLS_DHE_DSS_WITH_DES_CBC_SHA", 0x00, 0x12),

        SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA ("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 0x00, 0x13),
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA ("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 0x00, 0x13),

        SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA ("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x14),
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA ("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x14),

        SSL_DHE_RSA_WITH_DES_CBC_SHA ("SSL_DHE_RSA_WITH_DES_CBC_SHA", 0x00, 0x15),
        TLS_DHE_RSA_WITH_DES_CBC_SHA ("TLS_DHE_RSA_WITH_DES_CBC_SHA", 0x00, 0x15),

        SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA ("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x16),
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x00, 0x16),

        SSL_DH_anon_EXPORT_WITH_RC4_40_MD5 ("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", 0x00, 0x17),
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 ("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", 0x00, 0x17),

        SSL_DH_anon_WITH_RC4_128_MD5 ("SSL_DH_anon_WITH_RC4_128_MD5", 0x00, 0x18),
        TLS_DH_anon_WITH_RC4_128_MD5 ("TLS_DH_anon_WITH_RC4_128_MD5", 0x00, 0x18),

        SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA ("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x19),
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA ("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 0x00, 0x19),

        SSL_DH_anon_WITH_DES_CBC_SHA ("SSL_DH_anon_WITH_DES_CBC_SHA", 0x00, 0x1A),
        TLS_DH_anon_WITH_DES_CBC_SHA ("TLS_DH_anon_WITH_DES_CBC_SHA", 0x00, 0x1A),

        SSL_DH_anon_WITH_3DES_EDE_CBC_SHA ("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x00, 0x1B),
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x00, 0x1B),

        TLS_KRB5_WITH_DES_CBC_SHA ("TLS_KRB5_WITH_DES_CBC_SHA", 0x00, 0x1E),
        TLS_KRB5_WITH_3DES_EDE_CBC_SHA ("TLS_KRB5_WITH_3DES_EDE_CBC_SHA", 0x00, 0x1F),
        TLS_KRB5_WITH_RC4_128_SHA ("TLS_KRB5_WITH_RC4_128_SHA", 0x00, 0x20),
        TLS_KRB5_WITH_IDEA_CBC_SHA ("TLS_KRB5_WITH_IDEA_CBC_SHA", 0x00, 0x21),
        TLS_KRB5_WITH_DES_CBC_MD5 ("TLS_KRB5_WITH_DES_CBC_MD5", 0x00, 0x22),
        TLS_KRB5_WITH_3DES_EDE_CBC_MD5 ("TLS_KRB5_WITH_3DES_EDE_CBC_MD5", 0x00, 0x23),
        TLS_KRB5_WITH_RC4_128_MD5 ("TLS_KRB5_WITH_RC4_128_MD5", 0x00, 0x24),
        TLS_KRB5_WITH_IDEA_CBC_MD5 ("TLS_KRB5_WITH_IDEA_CBC_MD5", 0x00, 0x25),
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA ("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", 0x00, 0x26),
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA ("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", 0x00, 0x27),
        TLS_KRB5_EXPORT_WITH_RC4_40_SHA ("TLS_KRB5_EXPORT_WITH_RC4_40_SHA", 0x00, 0x28),
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 ("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", 0x00, 0x29),
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 ("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", 0x00, 0x2A),
        TLS_KRB5_EXPORT_WITH_RC4_40_MD5 ("TLS_KRB5_EXPORT_WITH_RC4_40_MD5", 0x00, 0x2B),
        TLS_PSK_WITH_NULL_SHA ("TLS_PSK_WITH_NULL_SHA", 0x00, 0x2C),
        TLS_DHE_PSK_WITH_NULL_SHA ("TLS_DHE_PSK_WITH_NULL_SHA", 0x00, 0x2D),
        TLS_RSA_PSK_WITH_NULL_SHA ("TLS_RSA_PSK_WITH_NULL_SHA", 0x00, 0x2E),
        TLS_RSA_WITH_AES_128_CBC_SHA ("TLS_RSA_WITH_AES_128_CBC_SHA", 0x00, 0x2F),
        TLS_DH_DSS_WITH_AES_128_CBC_SHA ("TLS_DH_DSS_WITH_AES_128_CBC_SHA", 0x00, 0x30),
        TLS_DH_RSA_WITH_AES_128_CBC_SHA ("TLS_DH_RSA_WITH_AES_128_CBC_SHA", 0x00, 0x31),
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA ("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x00, 0x32),
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x00, 0x33),
        TLS_DH_anon_WITH_AES_128_CBC_SHA ("TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x00, 0x34),
        TLS_RSA_WITH_AES_256_CBC_SHA ("TLS_RSA_WITH_AES_256_CBC_SHA", 0x00, 0x35),
        TLS_DH_DSS_WITH_AES_256_CBC_SHA ("TLS_DH_DSS_WITH_AES_256_CBC_SHA", 0x00, 0x36),
        TLS_DH_RSA_WITH_AES_256_CBC_SHA ("TLS_DH_RSA_WITH_AES_256_CBC_SHA", 0x00, 0x37),
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA ("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0x00, 0x38),
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x00, 0x39),
        TLS_DH_anon_WITH_AES_256_CBC_SHA ("TLS_DH_anon_WITH_AES_256_CBC_SHA", 0x00, 0x3A),
        TLS_RSA_WITH_NULL_SHA256 ("TLS_RSA_WITH_NULL_SHA256", 0x00, 0x3B),
        TLS_RSA_WITH_AES_128_CBC_SHA256 ("TLS_RSA_WITH_AES_128_CBC_SHA256", 0x00, 0x3C),
        TLS_RSA_WITH_AES_256_CBC_SHA256 ("TLS_RSA_WITH_AES_256_CBC_SHA256", 0x00, 0x3D),
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 ("TLS_DH_DSS_WITH_AES_128_CBC_SHA256", 0x00, 0x3E),
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 ("TLS_DH_RSA_WITH_AES_128_CBC_SHA256", 0x00, 0x3F),
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 ("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 0x00, 0x40),
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA ("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x41),
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA ("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x42),
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA ("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x43),
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA ("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x44),
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA ("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x45),
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA ("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", 0x00, 0x46),

        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x00, 0x67),
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 ("TLS_DH_DSS_WITH_AES_256_CBC_SHA256", 0x00, 0x68),
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 ("TLS_DH_RSA_WITH_AES_256_CBC_SHA256", 0x00, 0x69),
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 ("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 0x00, 0x6A),
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x00, 0x6B),
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 ("TLS_DH_anon_WITH_AES_128_CBC_SHA256", 0x00, 0x6C),
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 ("TLS_DH_anon_WITH_AES_256_CBC_SHA256", 0x00, 0x6D),

        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA ("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x84),
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA ("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x85),
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA ("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x86),
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA ("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x87),
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA ("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x88),
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA ("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", 0x00, 0x89),
        TLS_PSK_WITH_RC4_128_SHA ("TLS_PSK_WITH_RC4_128_SHA", 0x00, 0x8A),
        TLS_PSK_WITH_3DES_EDE_CBC_SHA ("TLS_PSK_WITH_3DES_EDE_CBC_SHA", 0x00, 0x8B),
        TLS_PSK_WITH_AES_128_CBC_SHA ("TLS_PSK_WITH_AES_128_CBC_SHA", 0x00, 0x8C),
        TLS_PSK_WITH_AES_256_CBC_SHA ("TLS_PSK_WITH_AES_256_CBC_SHA", 0x00, 0x8D),
        TLS_DHE_PSK_WITH_RC4_128_SHA ("TLS_DHE_PSK_WITH_RC4_128_SHA", 0x00, 0x8E),
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA ("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", 0x00, 0x8F),
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA ("TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 0x00, 0x90),
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA ("TLS_DHE_PSK_WITH_AES_256_CBC_SHA", 0x00, 0x91),
        TLS_RSA_PSK_WITH_RC4_128_SHA ("TLS_RSA_PSK_WITH_RC4_128_SHA", 0x00, 0x92),
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA ("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", 0x00, 0x93),
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA ("TLS_RSA_PSK_WITH_AES_128_CBC_SHA", 0x00, 0x94),
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA ("TLS_RSA_PSK_WITH_AES_256_CBC_SHA", 0x00, 0x95),
        TLS_RSA_WITH_SEED_CBC_SHA ("TLS_RSA_WITH_SEED_CBC_SHA", 0x00, 0x96),
        TLS_DH_DSS_WITH_SEED_CBC_SHA ("TLS_DH_DSS_WITH_SEED_CBC_SHA", 0x00, 0x97),
        TLS_DH_RSA_WITH_SEED_CBC_SHA ("TLS_DH_RSA_WITH_SEED_CBC_SHA", 0x00, 0x98),
        TLS_DHE_DSS_WITH_SEED_CBC_SHA ("TLS_DHE_DSS_WITH_SEED_CBC_SHA", 0x00, 0x99),
        TLS_DHE_RSA_WITH_SEED_CBC_SHA ("TLS_DHE_RSA_WITH_SEED_CBC_SHA", 0x00, 0x9A),
        TLS_DH_anon_WITH_SEED_CBC_SHA ("TLS_DH_anon_WITH_SEED_CBC_SHA", 0x00, 0x9B),
        TLS_RSA_WITH_AES_128_GCM_SHA256 ("TLS_RSA_WITH_AES_128_GCM_SHA256", 0x00, 0x9C),
        TLS_RSA_WITH_AES_256_GCM_SHA384 ("TLS_RSA_WITH_AES_256_GCM_SHA384", 0x00, 0x9D),
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x00, 0x9E),
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x00, 0x9F),
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256 ("TLS_DH_RSA_WITH_AES_128_GCM_SHA256", 0x00, 0xA0),
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384 ("TLS_DH_RSA_WITH_AES_256_GCM_SHA384", 0x00, 0xA1),
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 ("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00, 0xA2),
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 ("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 0x00, 0xA3),
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256 ("TLS_DH_DSS_WITH_AES_128_GCM_SHA256", 0x00, 0xA4),
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384 ("TLS_DH_DSS_WITH_AES_256_GCM_SHA384", 0x00, 0xA5),
        TLS_DH_anon_WITH_AES_128_GCM_SHA256 ("TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0x00, 0xA6),
        TLS_DH_anon_WITH_AES_256_GCM_SHA384 ("TLS_DH_anon_WITH_AES_256_GCM_SHA384", 0x00, 0xA7),
        TLS_PSK_WITH_AES_128_GCM_SHA256 ("TLS_PSK_WITH_AES_128_GCM_SHA256", 0x00, 0xA8),
        TLS_PSK_WITH_AES_256_GCM_SHA384 ("TLS_PSK_WITH_AES_256_GCM_SHA384", 0x00, 0xA9),
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 ("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 0x00, 0xAA),
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 ("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", 0x00, 0xAB),
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 ("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", 0x00, 0xAC),
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 ("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", 0x00, 0xAD),
        TLS_PSK_WITH_AES_128_CBC_SHA256 ("TLS_PSK_WITH_AES_128_CBC_SHA256", 0x00, 0xAE),
        TLS_PSK_WITH_AES_256_CBC_SHA384 ("TLS_PSK_WITH_AES_256_CBC_SHA384", 0x00, 0xAF),
        TLS_PSK_WITH_NULL_SHA256 ("TLS_PSK_WITH_NULL_SHA256", 0x00, 0xB0),
        TLS_PSK_WITH_NULL_SHA384 ("TLS_PSK_WITH_NULL_SHA384", 0x00, 0xB1),
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 ("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", 0x00, 0xB2),
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 ("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", 0x00, 0xB3),
        TLS_DHE_PSK_WITH_NULL_SHA256 ("TLS_DHE_PSK_WITH_NULL_SHA256", 0x00, 0xB4),
        TLS_DHE_PSK_WITH_NULL_SHA384 ("TLS_DHE_PSK_WITH_NULL_SHA384", 0x00, 0xB5),
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 ("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", 0x00, 0xB6),
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 ("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", 0x00, 0xB7),
        TLS_RSA_PSK_WITH_NULL_SHA256 ("TLS_RSA_PSK_WITH_NULL_SHA256", 0x00, 0xB8),
        TLS_RSA_PSK_WITH_NULL_SHA384 ("TLS_RSA_PSK_WITH_NULL_SHA384", 0x00, 0xB9),
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBA),
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBB),
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBC),
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBD),
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBE),
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", 0x00, 0xBF),
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC0),
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC1),
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC2),
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC3),
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC4),
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 ("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", 0x00, 0xC5),
        TLS_SM4_GCM_SM3 ("TLS_SM4_GCM_SM3", 0x00, 0xC6),
        TLS_SM4_CCM_SM3 ("TLS_SM4_CCM_SM3", 0x00, 0xC7),

        TLS_EMPTY_RENEGOTIATION_INFO_SCSV ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x00, 0xFF),

        TLS_FALLBACK_SCSV ("TLS_FALLBACK_SCSV", 0x56, 0x00),

        TLS_AES_128_GCM_SHA256 ("TLS_AES_128_GCM_SHA256", 0x13, 0x01),
        TLS_AES_256_GCM_SHA384 ("TLS_AES_256_GCM_SHA384", 0x13, 0x02),

        /* Not in JSSE Cipher Suite Names */
        TLS_CHACHA20_POLY1305_SHA256 ("TLS_CHACHA20_POLY1305_SHA256", 0x13, 0x03),
        TLS_AES_128_CCM_SHA256 ("TLS_AES_128_CCM_SHA256", 0x13, 0x04),
        TLS_AES_128_CCM_8_SHA256 ("TLS_AES_128_CCM_8_SHA256", 0x13, 0x05),

        TLS_ECDH_ECDSA_WITH_NULL_SHA ("TLS_ECDH_ECDSA_WITH_NULL_SHA", 0xC0, 0x01),
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA ("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 0xC0, 0x02),
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA ("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x03),
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA ("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0xC0, 0x04),
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA ("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", 0xC0, 0x05),
        TLS_ECDHE_ECDSA_WITH_NULL_SHA ("TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xC0, 0x06),
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC0, 0x07),
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x08),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC0, 0x09),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0xC0, 0x0A),
        TLS_ECDH_RSA_WITH_NULL_SHA ("TLS_ECDH_RSA_WITH_NULL_SHA", 0xC0, 0x0B),
        TLS_ECDH_RSA_WITH_RC4_128_SHA ("TLS_ECDH_RSA_WITH_RC4_128_SHA", 0xC0, 0x0C),
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x0D),
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 0xC0, 0x0E),
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA ("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", 0xC0, 0x0F),
        TLS_ECDHE_RSA_WITH_NULL_SHA ("TLS_ECDHE_RSA_WITH_NULL_SHA", 0xC0, 0x10),
        TLS_ECDHE_RSA_WITH_RC4_128_SHA ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC0, 0x11),
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x12),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC0, 0x13),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xC0, 0x14),
        TLS_ECDH_anon_WITH_NULL_SHA ("TLS_ECDH_anon_WITH_NULL_SHA", 0xC0, 0x15),
        TLS_ECDH_anon_WITH_RC4_128_SHA ("TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC0, 0x16),
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA ("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x17),
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA ("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xC0, 0x18),
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA ("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 0xC0, 0x19),
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA ("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x1A),
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA ("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x1B),
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA ("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x1C),
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA ("TLS_SRP_SHA_WITH_AES_128_CBC_SHA", 0xC0, 0x1D),
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA ("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", 0xC0, 0x1E),
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA ("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", 0xC0, 0x1F),
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA ("TLS_SRP_SHA_WITH_AES_256_CBC_SHA", 0xC0, 0x20),
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA ("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", 0xC0, 0x21),
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA ("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", 0xC0, 0x22),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC0, 0x23),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0xC0, 0x24),
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 ("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0xC0, 0x25),
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 ("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", 0xC0, 0x26),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC0, 0x27),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xC0, 0x28),
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 0xC0, 0x29),
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 ("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", 0xC0, 0x2A),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC0, 0x2B),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC0, 0x2C),
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 ("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xC0, 0x2D),
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 ("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", 0xC0, 0x2E),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC0, 0x2F),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC0, 0x30),
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 ("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 0xC0, 0x31),
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 ("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", 0xC0, 0x32),
        TLS_ECDHE_PSK_WITH_RC4_128_SHA ("TLS_ECDHE_PSK_WITH_RC4_128_SHA", 0xC0, 0x33),
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA ("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", 0xC0, 0x34),
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA ("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xC0, 0x35),
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA ("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", 0xC0, 0x36),
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 ("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", 0xC0, 0x37),
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 ("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", 0xC0, 0x38),
        TLS_ECDHE_PSK_WITH_NULL_SHA ("TLS_ECDHE_PSK_WITH_NULL_SHA", 0xC0, 0x39),
        TLS_ECDHE_PSK_WITH_NULL_SHA256 ("TLS_ECDHE_PSK_WITH_NULL_SHA256", 0xC0, 0x3A),
        TLS_ECDHE_PSK_WITH_NULL_SHA384 ("TLS_ECDHE_PSK_WITH_NULL_SHA384", 0xC0, 0x3B),
        TLS_RSA_WITH_ARIA_128_CBC_SHA256 ("TLS_RSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x3C),
        TLS_RSA_WITH_ARIA_256_CBC_SHA384 ("TLS_RSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x3D),
        TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 ("TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x3E),
        TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 ("TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x3F),
        TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 ("TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x40),
        TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 ("TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x41),
        TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 ("TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x42),
        TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 ("TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x43),
        TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ("TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x44),
        TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 ("TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x45),
        TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 ("TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x46),
        TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 ("TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x47),
        TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 ("TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x48),
        TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 ("TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x49),
        TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 ("TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x4A),
        TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 ("TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x4B),
        TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 ("TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x4C),
        TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 ("TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x4D),
        TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 ("TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x4E),
        TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 ("TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x4F),
        TLS_RSA_WITH_ARIA_128_GCM_SHA256 ("TLS_RSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x50),
        TLS_RSA_WITH_ARIA_256_GCM_SHA384 ("TLS_RSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x51),
        TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 ("TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x52),
        TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 ("TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x53),
        TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 ("TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x54),
        TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 ("TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x55),
        TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 ("TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x56),
        TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 ("TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x57),
        TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 ("TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x58),
        TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 ("TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x59),
        TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 ("TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x5A),
        TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 ("TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x5B),
        TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 ("TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x5C),
        TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 ("TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x5D),
        TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 ("TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x5E),
        TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 ("TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x5F),
        TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 ("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x60),
        TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 ("TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x61),
        TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 ("TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x62),
        TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 ("TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x63),
        TLS_PSK_WITH_ARIA_128_CBC_SHA256 ("TLS_PSK_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x64),
        TLS_PSK_WITH_ARIA_256_CBC_SHA384 ("TLS_PSK_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x65),
        TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 ("TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x66),
        TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 ("TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x67),
        TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 ("TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x68),
        TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 ("TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x69),
        TLS_PSK_WITH_ARIA_128_GCM_SHA256 ("TLS_PSK_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x6A),
        TLS_PSK_WITH_ARIA_256_GCM_SHA384 ("TLS_PSK_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x6B),
        TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 ("TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x6C),
        TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 ("TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x6D),
        TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 ("TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", 0xC0, 0x6E),
        TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 ("TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", 0xC0, 0x6F),
        TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 ("TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", 0xC0, 0x70),
        TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 ("TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", 0xC0, 0x71),
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x72),
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x73),
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x74),
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x75),
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x76),
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x77),
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x78),
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x79),
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x7A),
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x7B),
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x7C),
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x7D),
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x7E),
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x7F),
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x80),
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x81),
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x82),
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x83),
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x84),
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x85),
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x86),
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x87),
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x88),
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x89),
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x8A),
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x8B),
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x8C),
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x8D),
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x8E),
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x8F),
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x90),
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x91),
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 ("TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", 0xC0, 0x92),
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 ("TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", 0xC0, 0x93),
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x94),
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x95),
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x96),
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x97),
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x98),
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x99),
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 ("TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", 0xC0, 0x9A),
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 ("TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", 0xC0, 0x9B),
        TLS_RSA_WITH_AES_128_CCM ("TLS_RSA_WITH_AES_128_CCM", 0xC0, 0x9C),
        TLS_RSA_WITH_AES_256_CCM ("TLS_RSA_WITH_AES_256_CCM", 0xC0, 0x9D),
        TLS_DHE_RSA_WITH_AES_128_CCM ("TLS_DHE_RSA_WITH_AES_128_CCM", 0xC0, 0x9E),
        TLS_DHE_RSA_WITH_AES_256_CCM ("TLS_DHE_RSA_WITH_AES_256_CCM", 0xC0, 0x9F),
        TLS_RSA_WITH_AES_128_CCM_8 ("TLS_RSA_WITH_AES_128_CCM_8", 0xC0, 0xA0),
        TLS_RSA_WITH_AES_256_CCM_8 ("TLS_RSA_WITH_AES_256_CCM_8", 0xC0, 0xA1),
        TLS_DHE_RSA_WITH_AES_128_CCM_8 ("TLS_DHE_RSA_WITH_AES_128_CCM_8", 0xC0, 0xA2),
        TLS_DHE_RSA_WITH_AES_256_CCM_8 ("TLS_DHE_RSA_WITH_AES_256_CCM_8", 0xC0, 0xA3),
        TLS_PSK_WITH_AES_128_CCM ("TLS_PSK_WITH_AES_128_CCM", 0xC0, 0xA4),
        TLS_PSK_WITH_AES_256_CCM ("TLS_PSK_WITH_AES_256_CCM", 0xC0, 0xA5),
        TLS_DHE_PSK_WITH_AES_128_CCM ("TLS_DHE_PSK_WITH_AES_128_CCM", 0xC0, 0xA6),
        TLS_DHE_PSK_WITH_AES_256_CCM ("TLS_DHE_PSK_WITH_AES_256_CCM", 0xC0, 0xA7),
        TLS_PSK_WITH_AES_128_CCM_8 ("TLS_PSK_WITH_AES_128_CCM_8", 0xC0, 0xA8),
        TLS_PSK_WITH_AES_256_CCM_8 ("TLS_PSK_WITH_AES_256_CCM_8", 0xC0, 0xA9),
        TLS_DHE_PSK_WITH_AES_128_CCM_8 ("TLS_DHE_PSK_WITH_AES_128_CCM_8", 0xC0, 0xAA),
        TLS_DHE_PSK_WITH_AES_256_CCM_8 ("TLS_DHE_PSK_WITH_AES_256_CCM_8", 0xC0, 0xAB),
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM ("TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 0xC0, 0xAC),
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM ("TLS_ECDHE_ECDSA_WITH_AES_256_CCM", 0xC0, 0xAD),
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 0xC0, 0xAE),
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 ("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", 0xC0, 0xAF),

        /* Not in JSSE Cipher Suite Names */
        TLS_ECCPWD_WITH_AES_128_GCM_SHA256 ("TLS_ECCPWD_WITH_AES_128_GCM_SHA256", 0xC0, 0xB0),
        TLS_ECCPWD_WITH_AES_256_GCM_SHA384 ("TLS_ECCPWD_WITH_AES_256_GCM_SHA384", 0xC0, 0xB1),
        TLS_ECCPWD_WITH_AES_128_CCM_SHA256 ("TLS_ECCPWD_WITH_AES_128_CCM_SHA256", 0xC0, 0xB2),
        TLS_ECCPWD_WITH_AES_256_CCM_SHA384 ("TLS_ECCPWD_WITH_AES_256_CCM_SHA384", 0xC0, 0xB3),
        TLS_SHA256_SHA256 ("TLS_SHA256_SHA256", 0xC0, 0xB4),
        TLS_SHA384_SHA384 ("TLS_SHA384_SHA384", 0xC0, 0xB5),

        /* Not in JSSE Cipher Suite Names */
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", 0xC1, 0x00),
        TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", 0xC1, 0x01),
        TLS_GOSTR341112_256_WITH_28147_CNT_IMIT ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", 0xC1, 0x02),
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", 0xC1, 0x03),
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_L ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", 0xC1, 0x04),
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", 0xC1, 0x05),
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_S ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", 0xC1, 0x06),

        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xA8),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xA9),
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xAA),
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 ("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xAB),
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 ("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xAC),
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 ("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xAD),
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 ("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCC, 0xAE),

        /* Not in JSSE Cipher Suite Names */
        TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 ("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xD0, 0x01),
        TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 ("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", 0xD0, 0x02),
        TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 ("TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", 0xD0, 0x03),

        /* Not in JSSE Cipher Suite Names */
        TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 ("TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256", 0xD0, 0x05);

        private final String name;

        public final byte yy;

        public final byte zz;

        CipherSuiteCoding(String name, int yy, int zz) {

            this.name = name;

            this.yy = (byte) yy;
            this.zz = (byte) zz;
        }

        public static CipherSuiteCoding get(String cipherSuite) {

            CipherSuiteCoding[] cipherSuiteCodings = CipherSuiteCoding.values();

            for (CipherSuiteCoding cipherSuiteCoding :
                    cipherSuiteCodings) {

                if (cipherSuiteCoding.name.equals(cipherSuite)) {

                    return cipherSuiteCoding;
                }
            }

            return null;
        }
    }
}
