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

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.ConnectionPendingException;
import java.nio.channels.NoConnectionPendingException;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnresolvedAddressException;
import java.nio.channels.UnsupportedAddressTypeException;
import java.nio.channels.WritableByteChannel;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

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
        System.loadLibrary("native-lib");
    }

    private static final String LOG_TAG = "ApplicationEnvironment";

    public static native void registerHostEnvironment(ApplicationEnvironment factory);

    private final Application application;

    private Selector socketSelector;

    private static final Object registerLock = new Object();

    private static final Executor executor = Executors.newSingleThreadExecutor();

    public ApplicationEnvironment(Application application) {
        this.application = application;

        try {
            socketSelector = Selector.open();
        } catch (IOException e) {
            LogService.w(LOG_TAG, "failed to open socket channel selector", e);
        }

        java.lang.System.setProperty("java.net.preferIPv4Stack", "true");
        java.lang.System.setProperty("java.net.preferIPv6Addresses", "false");

        new Thread() {
            @Override
            public void run() {
                while (true) {
                    try {
                        synchronized (registerLock) {
                            LogService.v(LOG_TAG, "synchronizing selector registration");
                        }
                        LogService.i(LOG_TAG, "socketSelector.select()");
                        int r = socketSelector.select();
                        LogService.i(LOG_TAG, "socketSelector.select() returns " + r);
                        Set<SelectionKey> selectedKeys = socketSelector.selectedKeys();
                        Iterator<SelectionKey> iterator = selectedKeys.iterator();
                        while (iterator.hasNext()) {
                            SelectionKey key = iterator.next();
                            LogService.i(LOG_TAG, "on SelectionKey " + key + " ready ops=" + key.readyOps() + ", interest ops=" + key.interestOps());
                            if (key.isValid()) {
                                Object attachment = key.attachment();
                                if (attachment instanceof AsyncLatch) {
                                    AsyncLatch asyncLatch = (AsyncLatch) attachment;
                                    try {
                                        if (key.isConnectable()) {
                                            LogService.i(LOG_TAG, "key isConnectable");
                                            asyncLatch.wakeUp();
                                        }
                                    } catch (CancelledKeyException e) {
                                        LogService.w(LOG_TAG, "key is cancelled:", e);
                                    }
                                }

                                if (attachment instanceof AsyncSocket) {
                                    AsyncSocket asyncSocket = (AsyncSocket) attachment;

                                    try {

                                        int ops = key.interestOps();
                                        int newOps = ops;

                                        if (key.isReadable()) {
                                            LogService.i(LOG_TAG, "key isReadable");

                                            Channel channel = key.channel();

                                            LogService.i(LOG_TAG, "onReadAvailable for channel " + channel);

                                            if (channel instanceof ReadableByteChannel) {

                                                ReadableByteChannel readableByteChannel = (ReadableByteChannel) channel;

                                                boolean closed = false;
                                                boolean full;
                                                boolean haveData;

                                                int read;

                                                synchronized (asyncSocket.readLock) {

                                                    try {
                                                        read = readableByteChannel.read(asyncSocket.readBuffer);
                                                    } catch (NonReadableChannelException |
                                                             IOException e) {
                                                        LogService.w(LOG_TAG, "error reading plain socket:", e);
                                                        asyncSocket.readClosed = true;
                                                        read = -1;
                                                    }

                                                    full = !asyncSocket.readBuffer.hasRemaining();
                                                    haveData = asyncSocket.readBuffer.position() > 0;
                                                }

                                                LogService.i(LOG_TAG, "read " + read + " bytes from channel");

                                                if (read == -1) {
                                                    closed = true;
                                                }

                                                if (closed || full) {
                                                    if (full) {
                                                        LogService.i(LOG_TAG, "cannot read further into the buffer");
                                                    } else {
                                                        LogService.i(LOG_TAG, "no more data remaining to read");
                                                    }

                                                    LogService.i(LOG_TAG, "cancelling OP_READ in " + newOps);
                                                    newOps = newOps & (~SelectionKey.OP_READ);
                                                    LogService.i(LOG_TAG, "ops is now " + newOps);
                                                }

                                                if (haveData) {
                                                    synchronized (asyncSocket.readLatches) {
                                                        Iterator<AsyncLatch> it = asyncSocket.readLatches.iterator();
                                                        while (it.hasNext()) {
                                                            AsyncLatch asyncLatch = it.next();
                                                            asyncLatch.wakeUp();
                                                            it.remove();
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if (key.isWritable()) {
                                            LogService.i(LOG_TAG, "key isWritable");

                                            Channel channel = key.channel();

                                            LogService.i(LOG_TAG, "onWriteAvailable for ssl channel " + channel);

                                            if (channel instanceof WritableByteChannel) {

                                                WritableByteChannel writableByteChannel = (WritableByteChannel) channel;

                                                boolean allWritten = false;

                                                int consumed = 0;

                                                boolean writeFailed;

                                                synchronized (asyncSocket.writeLock) {

                                                    while (asyncSocket.writeBuffer.position() > 0) {

                                                        int written = 0;

                                                        asyncSocket.writeBuffer.flip();
                                                        try {
                                                            written = writableByteChannel.write(asyncSocket.writeBuffer);
                                                        } catch (NonWritableChannelException | IOException e) {
                                                            LogService.w(LOG_TAG, "error writing plain socket:", e);
                                                            asyncSocket.writeFailed = true;
                                                        } finally {
                                                            asyncSocket.writeBuffer.compact();
                                                        }

                                                        if (written <= 0) {
                                                            break;
                                                        } else {
                                                            consumed += written;
                                                        }
                                                    }

                                                    writeFailed = asyncSocket.writeFailed;

                                                    if (asyncSocket.writeBuffer.position() == 0) {
                                                        allWritten = true;
                                                    }
                                                }

                                                if (allWritten || writeFailed) {
                                                    if (allWritten) {
                                                        LogService.i(LOG_TAG, "all pending write finished");
                                                    } else {
                                                        LogService.i(LOG_TAG, "cannot write further into the channel");
                                                    }
                                                    LogService.i(LOG_TAG, "cancelling OP_WRITE in " + newOps);
                                                    newOps = newOps & (~SelectionKey.OP_WRITE);
                                                    LogService.i(LOG_TAG, "ops is now " + newOps);
                                                }

                                                if (consumed > 0) {
                                                    synchronized (asyncSocket.writeLatches) {
                                                        Iterator<AsyncLatch> it = asyncSocket.writeLatches.iterator();
                                                        while (it.hasNext()) {
                                                            AsyncLatch asyncLatch = it.next();
                                                            asyncLatch.wakeUp();
                                                            it.remove();
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        synchronized (registerLock) {
                                            if (ops != newOps) {
                                                LogService.i(LOG_TAG, "changing interestOps " + newOps);
                                                key.interestOps(newOps);
                                            }
                                        }

                                    } catch (CancelledKeyException e) {
                                        LogService.w(LOG_TAG, "key is cancelled:", e);
                                    }
                                }

                                if (attachment instanceof SocketSSLEngine) {
                                    SocketSSLEngine socketSSLEngine = (SocketSSLEngine) attachment;

                                    try {

                                        int ops = key.interestOps();
                                        int newOps = ops;

                                        SocketSSLEngine.ReadResult readResult = null;
                                        SocketSSLEngine.WriteResult writeResult = null;

                                        if (key.isReadable()) {
                                            LogService.i(LOG_TAG, "key isReadable");
                                            readResult = socketSSLEngine.onReadAvailable(key);
                                            if (readResult.bufferFull) {
                                                LogService.i(LOG_TAG, "no more data remaining to read or to decrypt, cancelling OP_READ in " + newOps);
                                                newOps = newOps & (~SelectionKey.OP_READ);
                                                LogService.i(LOG_TAG, "ops is now " + newOps);
                                            }
                                        }

                                        if (key.isWritable()) {
                                            LogService.i(LOG_TAG, "key isWritable");
                                            writeResult = socketSSLEngine.onWriteAvailable(key);
                                            if (writeResult.bufferEmpty) {
                                                LogService.i(LOG_TAG, "all pending write finished, cancelling OP_WRITE in " + newOps);
                                                newOps = newOps & (~SelectionKey.OP_WRITE);
                                                LogService.i(LOG_TAG, "ops is now " + newOps);
                                            }
                                        }

                                        synchronized (registerLock) {
                                            if (ops != newOps) {
                                                LogService.i(LOG_TAG, "changing interestOps " + newOps);
                                                key.interestOps(newOps);
                                            }
                                        }

                                        if (readResult != null && readResult.producedSome) {
                                            synchronized (socketSSLEngine.sslReadLatches) {
                                                Iterator<AsyncLatch> sslReadIterator = socketSSLEngine.sslReadLatches.iterator();
                                                while (sslReadIterator.hasNext()) {
                                                    AsyncLatch asyncLatch = sslReadIterator.next();
                                                    asyncLatch.wakeUp();
                                                    sslReadIterator.remove();
                                                }
                                            }
                                        }

                                        if (writeResult != null && writeResult.consumedSome) {
                                            synchronized (socketSSLEngine.sslWriteLatches) {
                                                Iterator<AsyncLatch> sslWriteIterator = socketSSLEngine.sslWriteLatches.iterator();
                                                while (sslWriteIterator.hasNext()) {
                                                    AsyncLatch asyncLatch = sslWriteIterator.next();
                                                    asyncLatch.wakeUp();
                                                    sslWriteIterator.remove();
                                                }
                                            }
                                        }

                                    } catch (CancelledKeyException e) {
                                        LogService.w(LOG_TAG, "key is cancelled:", e);
                                    }
                                }
                            }

                            iterator.remove();
                        }
                    } catch (IOException | ClosedSelectorException | IllegalArgumentException e) {
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

    private static class AsyncLatch {
        private final AtomicLong nativeHandle;
        private AsyncLatch(long nativeHandle) {
            this.nativeHandle = new AtomicLong(nativeHandle);
        }

        private void wakeUp() {
            while (true) {
                long handle = nativeHandle.get();
                if (handle == 0) {
                    break;
                }

                if (nativeHandle.compareAndSet(handle, 0)) {
                    RustyRcsClient.AsyncLatchHandle.wakeUp(handle);
                    RustyRcsClient.AsyncLatchHandle.destroy(handle);
                    break;
                }
            }
        }

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            while (true) {
                long handle = nativeHandle.get();
                if (handle == 0) {
                    break;
                }

                if (nativeHandle.compareAndSet(handle, 0)) {
                    RustyRcsClient.AsyncLatchHandle.destroy(handle);
                    break;
                }
            }
        }
    }

    public static class SocketSSLEngine {

        private final SSLEngine engine;

        private final ByteBuffer readBuffer;

        private final ByteBuffer decrypted;

        private final Object readLock;

        private int readTotal = 0;

        private final List<AsyncLatch> sslReadLatches = Collections.synchronizedList(new LinkedList<>());

        private boolean readClosed = false;

        private final Object writeLock;

        private final ByteBuffer writeBuffer;

        private final ByteBuffer encrypted;

        private int writeTotal = 0;

        private final List<AsyncLatch> sslWriteLatches = Collections.synchronizedList(new LinkedList<>());

        private boolean writeFailed = false;

        private boolean shutDownWrite = false;

        private boolean writeCompleted = false;

        private boolean readCompleted = false;

        private final Object shutDownLock = new Object();

        private final List<AsyncLatch> sslShutDownLatches = new LinkedList<>();

        private final Object statusLock = new Object();

        private SSLSession sslSession;

        private final List<AsyncLatch> sslHandshakeLatches = new LinkedList<>();

        private SocketSSLEngine(SSLEngine engine, ByteBuffer readBuffer, ByteBuffer writeBuffer, Object readLock, Object writeLock) {
            this.engine = engine;

            final int ioBufferSize = 64 * 1024;

            this.readLock = readLock;
            this.readBuffer = readBuffer;

            decrypted = ByteBuffer.allocate(ioBufferSize);

            this.writeLock = writeLock;
            this.writeBuffer = writeBuffer;

            encrypted = ByteBuffer.allocate(ioBufferSize);
        }

        public static class ReadResult {
            private final boolean bufferFull;
            private final boolean producedSome;
            private ReadResult(boolean bufferFull, boolean producedSome) {
                this.bufferFull = bufferFull;
                this.producedSome = producedSome;
            }
        }

        public ReadResult onReadAvailable(SelectionKey key) {

            boolean bufferFull = false;
            boolean producedResult = false;

            Channel channel = key.channel();

            LogService.i(LOG_TAG, "onReadAvailable for ssl channel " + channel);

            if (channel instanceof ReadableByteChannel) {

                ReadableByteChannel readableByteChannel = (ReadableByteChannel) channel;

                boolean closed = false;

                int read;

                try {
                    read = readableByteChannel.read(readBuffer);
                } catch (NonReadableChannelException | IOException e) {
                    LogService.w(LOG_TAG, "error reading tls socket:", e);
                    read = -1;
                }

                if (read > 0) {
                    readTotal += read;
                }

                LogService.d(LOG_TAG, "read " + read + " bytes from channel, totalling " + readTotal + " bytes");

                LogService.d(LOG_TAG, "position=" + readBuffer.position() + ", limit=" + readBuffer.limit() + " after read");

                if (read == -1) {
                    closed = true;
                }

                boolean completed = false;

                int produced = 0;

                synchronized (readLock) {

                    if (closed) {
                        readClosed = true;
                    }

                    while (readBuffer.position() > 0) {

                        SSLEngineResult result = decrypt();
                        SSLEngineResult.Status status = result.getStatus();
                        LogService.i(LOG_TAG, "engine->unwrap() result:" + status);
                        if (status == SSLEngineResult.Status.OK) {
                            SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                            if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                                synchronized (statusLock) {
                                    sslSession = engine.getSession();
                                    if (sslSession != null) {
                                        Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                        while (iterator.hasNext()) {
                                            AsyncLatch asyncLatch = iterator.next();
                                            asyncLatch.wakeUp();
                                            iterator.remove();
                                        }
                                    } else {
                                        LogService.w(LOG_TAG, "ssl handshake finished but cannot retrieve sslSession");
                                    }
                                }
                            }
                            int bytesConsumed = result.bytesConsumed();
                            int bytesProduced = result.bytesProduced();
                            LogService.i(LOG_TAG, "bytesConsumed=" + bytesConsumed + ", bytesProduced=" + bytesProduced);
                            produced += bytesProduced;
                            if (bytesConsumed > 0 || bytesProduced > 0) {
                                continue;
                            } else if (readClosed) {
                                try {
                                    LogService.i(LOG_TAG, "closing ssl in-bound");
                                    engine.closeInbound();
                                } catch (SSLException e) {
                                    LogService.w(LOG_TAG, "ssl socket has not received the proper SSL/TLS close notification message:", e);
                                } finally {
                                    completed = true;
                                }
                            }
                        } else if (status == SSLEngineResult.Status.CLOSED) {
                            completed = true;
                            int bytesConsumed = result.bytesConsumed();
                            int bytesProduced = result.bytesProduced();
                            LogService.i(LOG_TAG, "bytesConsumed=" + bytesConsumed + ", bytesProduced=" + bytesProduced);
                            produced += bytesProduced;
                        }

                        break;
                    }

                    LogService.i(LOG_TAG, "ssl engine produced " + produced + " bytes");

                    if (produced > 0 || readClosed) {
                        producedResult = true;
                    }
                }

                LogService.d(LOG_TAG, "position=" + readBuffer.position() + ", limit=" + readBuffer.limit() + " after decryption");

                if (!readBuffer.hasRemaining() || (closed && produced == 0)) {
                    bufferFull = true;
                }

                if (completed) {
                    synchronized (shutDownLock) {
                        readCompleted = true;
                        if (closed) {
                            writeCompleted = true;
                        }
                        Iterator<AsyncLatch> iterator = sslShutDownLatches.iterator();
                        while (iterator.hasNext()) {
                            AsyncLatch asyncLatch = iterator.next();
                            asyncLatch.wakeUp();
                            iterator.remove();
                        }
                    }
                }

                synchronized (statusLock) {
                    if (sslSession == null) {
                        SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
                        LogService.i(LOG_TAG, "ssl engine handshake status now is " + handshakeStatus);
                        if (handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                            sslSession = engine.getSession();
                            if (sslSession != null) {
                                Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                while (iterator.hasNext()) {
                                    AsyncLatch asyncLatch = iterator.next();
                                    asyncLatch.wakeUp();
                                    iterator.remove();
                                }
                            } else {
                                LogService.w(LOG_TAG, "ssl handshake finished but cannot retrieve sslSession");
                            }
                        } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            LogService.i(LOG_TAG, "ssl need to perform some task");

                            Runnable task = engine.getDelegatedTask();

                            executor.execute(() -> {

                                task.run();

                                LogService.i(LOG_TAG, "ssl task complete");

                                synchronized (statusLock) {
                                    Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                    while (iterator.hasNext()) {
                                        AsyncLatch asyncLatch = iterator.next();
                                        asyncLatch.wakeUp();
                                        iterator.remove();
                                    }
                                }
                            });

                        } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                            LogService.i(LOG_TAG, "need more input data to perform ssl-engine wrap");
                            int ops = key.interestOps();
                            LogService.i(LOG_TAG, "re-adding OP_WRITE in " + ops);
                            ops = ops ^ SelectionKey.OP_WRITE;
                            LogService.i(LOG_TAG, "ops is now " + ops);
                            key.interestOps(ops);
                        } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                            if (closed) {
                                LogService.w(LOG_TAG, "ssl requires remote data but is already closed");
                                synchronized (statusLock) {
                                    Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                    while (iterator.hasNext()) {
                                        AsyncLatch asyncLatch = iterator.next();
                                        asyncLatch.wakeUp();
                                        iterator.remove();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return new ReadResult(bufferFull, producedResult);
        }

        public static final class WriteResult {
            private final boolean bufferEmpty;
            private final boolean consumedSome;
            private WriteResult(boolean bufferEmpty, boolean consumedSome) {
                this.bufferEmpty = bufferEmpty;
                this.consumedSome = consumedSome;
            }
        }

        public WriteResult onWriteAvailable(SelectionKey key) {

            boolean bufferEmpty = false;
            boolean consumedSome = false;

            Channel channel = key.channel();

            LogService.i(LOG_TAG, "onWriteAvailable for ssl channel " + channel);

            if (channel instanceof WritableByteChannel) {

                WritableByteChannel writableByteChannel = (WritableByteChannel) channel;

                int consumed = 0;

                boolean cryptroClosed = false;

                synchronized (writeLock) {

                    do {

                        SSLEngineResult result = encrypt();
                        SSLEngineResult.Status status = result.getStatus();
                        LogService.i(LOG_TAG, "engine->wrap() result:" + status);
                        if (status == SSLEngineResult.Status.OK) {
                            SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                            if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                                synchronized (statusLock) {
                                    sslSession = engine.getSession();
                                    if (sslSession != null) {
                                        Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                        while (iterator.hasNext()) {
                                            AsyncLatch asyncLatch = iterator.next();
                                            asyncLatch.wakeUp();
                                            iterator.remove();
                                        }
                                    } else {
                                        LogService.w(LOG_TAG, "ssl handshake finished but cannot retrieve sslSession");
                                    }
                                }
                            }
                            int bytesConsumed = result.bytesConsumed();
                            int bytesProduced = result.bytesProduced();
                            LogService.i(LOG_TAG, "bytesConsumed=" + bytesConsumed + ", bytesProduced=" + bytesProduced);
                            consumed += bytesConsumed;
                            if (bytesConsumed > 0 || bytesProduced > 0) {
                                continue;
                            } else {
                                if (writeBuffer.position() == 0 && shutDownWrite) {
                                    engine.closeOutbound();
                                    continue;
                                }
                            }
                        } else if (status == SSLEngineResult.Status.CLOSED) {
                            cryptroClosed = true;
                            int bytesConsumed = result.bytesConsumed();
                            int bytesProduced = result.bytesProduced();
                            LogService.i(LOG_TAG, "bytesConsumed=" + bytesConsumed + ", bytesProduced=" + bytesProduced);
                            consumed += bytesConsumed;
                        }

                        break;

                    } while (true);

                    while (encrypted.position() > 0) {

                        int written = 0;

                        try {
                            encrypted.flip();
                            written = writableByteChannel.write(encrypted);
                        } catch (NonWritableChannelException | IOException e) {
                            LogService.w(LOG_TAG, "error writing tls socket:", e);
                            writeFailed = true;
                        } finally {
                            encrypted.compact();
                        }

                        if (written > 0) {
                            writeTotal += written;
                        }

                        LogService.i(LOG_TAG, "write " + written + " bytes to channel, totalling " + writeTotal + " bytes");

                        if (written <= 0) {
                            break;
                        }
                    }

                    boolean allConsumed = false;

                    if (encrypted.position() == 0 && writeBuffer.position() == 0) {
                        allConsumed = true;
                        bufferEmpty = true;
                        LogService.i(LOG_TAG, "ssl data all encrypted and written");
                    }

                    if (!allConsumed && cryptroClosed) {
                        writeFailed = true;
                        LogService.i(LOG_TAG, "write failed, crypto closed early");
                    }

                    if (consumed > 0 || writeFailed) {
                        consumedSome = true;
                    }
                }

                if (cryptroClosed) {
                    bufferEmpty = true;
                    synchronized (shutDownLock) {
                        writeCompleted = true;
                        Iterator<AsyncLatch> iterator = sslShutDownLatches.iterator();
                        while (iterator.hasNext()) {
                            AsyncLatch asyncLatch = iterator.next();
                            asyncLatch.wakeUp();
                            iterator.remove();
                        }
                    }
                }

                synchronized (statusLock) {
                    if (sslSession == null) {
                        SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
                        LogService.i(LOG_TAG, "ssl engine handshake status now is " + handshakeStatus);
                        if (handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                            sslSession = engine.getSession();
                            if (sslSession != null) {
                                Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                while (iterator.hasNext()) {
                                    AsyncLatch asyncLatch = iterator.next();
                                    asyncLatch.wakeUp();
                                    iterator.remove();
                                }
                            } else {
                                LogService.w(LOG_TAG, "ssl handshake finished but cannot retrieve sslSession");
                            }
                        } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            LogService.i(LOG_TAG, "ssl need to perform some task");

                            Runnable task = engine.getDelegatedTask();

                            executor.execute(() -> {

                                task.run();

                                LogService.i(LOG_TAG, "ssl task complete");

                                synchronized (statusLock) {
                                    Iterator<AsyncLatch> iterator = sslHandshakeLatches.iterator();
                                    while (iterator.hasNext()) {
                                        AsyncLatch asyncLatch = iterator.next();
                                        asyncLatch.wakeUp();
                                        iterator.remove();
                                    }
                                }
                            });
                        }
                    }
                }
            }

            return new WriteResult(bufferEmpty, consumedSome);
        }

        public SSLEngineResult decrypt() {
            try {
                readBuffer.flip();
                return engine.unwrap(readBuffer, decrypted);
            } catch (SSLException e) {
                LogService.w(LOG_TAG, "error decrypting ssl packets");
            } finally {
                readBuffer.compact();
            }

            return null;
        }

        public SSLEngineResult encrypt() {
            try {
                writeBuffer.flip();
                return engine.wrap(writeBuffer, encrypted);
            } catch (SSLException e) {
                LogService.w(LOG_TAG, "error encrypting ssl packets");
            } finally {
                writeBuffer.compact();
            }

            return null;
        }

        public int finishHandshake(SelectableChannel selectableChannel, Selector socketSelector, long asyncHandle) {

            synchronized (statusLock) {

                if (sslSession != null) {
                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                    return 0;
                }

                SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();

                LogService.i(LOG_TAG, "ssl engine handshake status is " + handshakeStatus);

                if (handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    sslSession = engine.getSession();

                    if (sslSession != null) {
                        RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                        return 0;
                    } else {
                        LogService.w(LOG_TAG, "handshake might not have started");
                    }

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    sslHandshakeLatches.add(asyncLatch);

                    try {
                        engine.beginHandshake();
                    } catch (SSLException | IllegalStateException e) {
                        LogService.w(LOG_TAG, "error attempting handshake", e);
                    }

                    return 114; // EALREADY
                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                    sslSession = engine.getSession();

                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                    return 0;
                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    LogService.i(LOG_TAG, "ssl need to perform some task");

                    Runnable task = engine.getDelegatedTask();

                    executor.execute(() -> {

                        task.run();

                        LogService.i(LOG_TAG, "ssl task complete");

                        asyncLatch.wakeUp();
                    });

                    return 114; // EALREADY

                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    sslHandshakeLatches.add(asyncLatch);

                    LogService.i(LOG_TAG, "platform_socket_finish_handshake will block, setting up channel selector");

                    synchronized (registerLock) {
                        socketSelector.wakeup();
                        try {
                            SelectionKey selectionKey = selectableChannel.register(socketSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, this);
                            LogService.i(LOG_TAG, "selectableChannel event registered with:" + selectionKey);
                        } catch (ClosedChannelException | IllegalStateException | IllegalArgumentException e) {
                            LogService.w(LOG_TAG, "failed to register selectable channel:", e);
                            return -1;
                        }
                    }

                    return 114;

                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    sslHandshakeLatches.add(asyncLatch);

                    return 114; // EALREADY
                }
            }

            RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

            return -1;
        }

        public CipherSuiteCoding getSessionCipherSuite() {
            synchronized (statusLock) {
                if (sslSession == null) {
                    sslSession = engine.getSession();
                }

                if (sslSession != null) {
                    String cipherSuite = sslSession.getCipherSuite();
                    return CipherSuiteCoding.get(cipherSuite);
                } else {
                    return null;
                }
            }
        }
    }

    public static class AsyncSocket {

        private final Selector socketSelector;

        private final SocketChannel socketChannel;

        private final SelectableChannel selectableChannel;

        private final List<AsyncLatch> readLatches = Collections.synchronizedList(new LinkedList<>());

        private final List<AsyncLatch> writeLatches = Collections.synchronizedList(new LinkedList<>());

        private final Object readLock = new Object();

        private final ByteBuffer readBuffer;

        private boolean readClosed = false;

        private int readTotal = 0;

        private final Object writeLock = new Object();

        private final ByteBuffer writeBuffer;

        private boolean writeFailed = false;

        private int writeTotal = 0;

        private SocketSSLEngine socketSSLEngine;

        private AsyncSocket(Selector socketSelector, SocketChannel socketChannel, SelectableChannel selectableChannel) {

            final int ioBufferSize = 64 * 1024;

            this.readBuffer = ByteBuffer.allocate(ioBufferSize);

            this.writeBuffer = ByteBuffer.allocate(ioBufferSize);

            this.socketSelector = socketSelector;

            this.socketChannel = socketChannel;

            this.selectableChannel = selectableChannel;
        }

        public int bind(String localAddress, int localPort) {

            try {

                InetSocketAddress socketAddress;

                if ("0.0.0.0".equals(localAddress) || "::".equals(localAddress) || "localhost".equals(localAddress)) {
                    socketAddress = new InetSocketAddress(localPort);
                } else {
                    InetAddress inetAddress = InetAddress.getByName(localAddress);
                    socketAddress = new InetSocketAddress(inetAddress, localPort);
                }

                this.socketChannel.bind(socketAddress);

                return 0;

            } catch (IOException e) {
                LogService.w(LOG_TAG, "failed to bind socket address:", e);
            }

            return -1;
        }

        public int setupTls(String hostName) {

            SSLEngine engine;

            try {
                engine = SSLContext.getDefault().createSSLEngine();
                engine.setUseClientMode(true);
                SSLParameters sslParameters = new SSLParameters();
                SNIServerName sniServerName = new SNIHostName(hostName);
                sslParameters.setServerNames(Collections.singletonList(sniServerName));
                engine.setSSLParameters(sslParameters);
            } catch (IllegalStateException | IllegalArgumentException | NoSuchAlgorithmException e) {
                LogService.w(LOG_TAG, "failed to configure ssl engine:", e);
                return -1;
            }

            LogService.i(LOG_TAG, "configured ssl engine");

            this.socketSSLEngine = new SocketSSLEngine(engine, readBuffer, writeBuffer, readLock, writeLock);

            return 0;
        }

        public int connect(String remoteHost, int remotePort) {

            InetSocketAddress inetSocketAddress = new InetSocketAddress(remoteHost, remotePort);

            try {
                socketChannel.connect(inetSocketAddress);
                return 0;
            } catch (IOException
                     | AlreadyConnectedException
                     | ConnectionPendingException
                     | UnresolvedAddressException
                     | UnsupportedAddressTypeException
                     | SecurityException e) {
                LogService.w(LOG_TAG, "error attempting to connect to address " + inetSocketAddress);
            }

            return -1;
        }

        public int finishConnect(long asyncHandle) {

            try {
                if (socketChannel.finishConnect()) {

                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                    if (socketSSLEngine != null) {
                        LogService.i(LOG_TAG, "ssl socket connected, setting up channel selector");
                        int registerResult = registerSelectionKey(SelectionKey.OP_READ, socketSSLEngine, true);
                        if (registerResult < 0) {
                            return -1;
                        }
                    } else {
                        LogService.i(LOG_TAG, "socket connected, setting up channel selector");
                        int registerResult = registerSelectionKey(SelectionKey.OP_READ, this, true);
                        if (registerResult < 0) {
                            return -1;
                        }
                    }

                    return 0;
                } else {

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    LogService.i(LOG_TAG, "platform_socket_finish_connect will block, setting up channel selector");

                    int registerResult = registerSelectionKey(SelectionKey.OP_CONNECT, asyncLatch, false);
                    if (registerResult < 0) {
                        return -1;
                    }

                    return 114; // EALREADY
                }
            } catch (NoConnectionPendingException | IOException e) {
                LogService.w(LOG_TAG, "error attempting to finish connection:", e);
            }

            RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

            return -1;
        }

        public int startHandshake() {

            if (socketSSLEngine != null) {

                try {
                    socketSSLEngine.engine.beginHandshake();
                    return 0;
                } catch (SSLException | IllegalStateException e) {
                    LogService.w(LOG_TAG, "error attempting handshake", e);
                }

                return -1;

            } else {

                return 0;
            }
        }

        public int finishHandshake(long asyncHandle) {

            if (socketSSLEngine != null) {

                return socketSSLEngine.finishHandshake(selectableChannel, socketSelector, asyncHandle);

            } else {

                RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                return 0;
            }
        }

        public int read(byte[] bytes, long asyncHandle) {

            if (socketSSLEngine != null) {

                LogService.i(LOG_TAG, "read ssl max " + bytes.length + " bytes");

                int read;

                synchronized (socketSSLEngine.readLock) {

                    socketSSLEngine.decrypted.flip();

                    int remaining = socketSSLEngine.decrypted.remaining();

                    LogService.i(LOG_TAG, "decrypted remaining:" + remaining);

                    if (remaining > 0) {
                        if (remaining > bytes.length) {
                            socketSSLEngine.decrypted.get(bytes);
                        } else {
                            socketSSLEngine.decrypted.get(bytes, 0, remaining);
                        }

                        int after = socketSSLEngine.decrypted.remaining();

                        if (after < remaining) {
                            read = remaining - after;
                        } else {
                            read = 0;
                        }
                    } else {
                        read = 0;
                    }

                    socketSSLEngine.decrypted.compact();

                    LogService.i(LOG_TAG, "decrypted read:" + read);

                    if (read == 0) {
                        if (socketSSLEngine.readClosed) {
                            RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                            return -1;
                        }
                    }
                }

                if (read == 0) {
                    LogService.i(LOG_TAG, "platform_read_socket will block, setting up channel selector");

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    socketSSLEngine.sslReadLatches.add(asyncLatch);

                    int registerResult = registerSelectionKey(SelectionKey.OP_READ | SelectionKey.OP_WRITE, socketSSLEngine, true);
                    if (registerResult < 0) {
                        return -1;
                    }
                } else {
                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);
                }

                readTotal += read;

                LogService.i(LOG_TAG, "we have read " + readTotal + " bytes from decrypted ssl in total");

                return read;

            } else {

                LogService.i(LOG_TAG, "read max " + bytes.length + " bytes");

                int read;

                synchronized (readLock) {
                    readBuffer.flip();
                    int remainingBefore = readBuffer.remaining();
                    readBuffer.get(bytes, 0, Math.min(remainingBefore, bytes.length));
                    int remainingAfter = readBuffer.remaining();
                    readBuffer.compact();
                    read = remainingBefore - remainingAfter;

                    if (read == 0 && readClosed) {
                        read = -1;
                    }
                }

                if (read == 0) {
                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    readLatches.add(asyncLatch);

                    LogService.i(LOG_TAG, "platform_read_socket will block, setting up channel selector");

                    int registerResult = registerSelectionKey(SelectionKey.OP_READ, this, false);
                    if (registerResult < 0) {
                        return -1;
                    } else if (registerResult == 11) {
                        return -11; // will be treated as Poll::Ready(Ok(())) with 0 bytes advanced
                    }
                } else {
                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);
                }

                LogService.i(LOG_TAG, "we have read " + readTotal + " bytes in total");

                return read;
            }
        }

        public int write(byte[] bytes, long asyncHandle) {

            if (socketSSLEngine != null) {

                LogService.i(LOG_TAG, "write ssl " + bytes.length + " bytes");

                int written = 0;

                synchronized (socketSSLEngine.writeLock) {

                    if (socketSSLEngine.writeFailed) {
                        written = -1;
                        LogService.w(LOG_TAG, "ssl socket already failed");
                    } else {
                        int remaining = socketSSLEngine.writeBuffer.remaining();

                        LogService.i(LOG_TAG, "ssl writeBuffer remaining:" + remaining);

                        if (remaining > 0) {

                            int writtenThisTime;
                            if (remaining > bytes.length - written) {
                                socketSSLEngine.writeBuffer.put(bytes, written, bytes.length - written);
                                writtenThisTime = bytes.length - written;
                            } else {
                                socketSSLEngine.writeBuffer.put(bytes, written, remaining);
                                writtenThisTime = remaining;
                            }

                            written += writtenThisTime;
                        }

                        LogService.i(LOG_TAG, "enqueued " + written + " bytes to ssl writeBuffer");
                    }
                }

                if (written == 0) {
                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    socketSSLEngine.sslWriteLatches.add(asyncLatch);
                } else {
                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);
                }

                int registerResult = registerSelectionKey(SelectionKey.OP_READ | SelectionKey.OP_WRITE, socketSSLEngine, true);
                if (registerResult < 0) {
                    return -1;
                }

                if (written > 0) {
                    writeTotal += written;
                }

                LogService.i(LOG_TAG, "we have written " + writeTotal + " bytes to ssl encryption in total");

                return written;

            } else {

                LogService.i(LOG_TAG, "write " + bytes.length + " bytes");

                int written = 0;

                synchronized (writeLock) {
                    if (writeFailed) {
                        written = -1;
                        LogService.w(LOG_TAG, "socket already failed");
                    } else {
                        int remaining = writeBuffer.remaining();
                        if (remaining > 0) {
                            int writtenThisTime;
                            if (remaining > bytes.length - written) {
                                writeBuffer.put(bytes, written, bytes.length - written);
                                writtenThisTime = bytes.length - written;
                            } else {
                                writeBuffer.put(bytes, written, remaining);
                                writtenThisTime = remaining;
                            }
                            written += writtenThisTime;
                        }
                        LogService.i(LOG_TAG, "enqueued " + written + " bytes to writeBuffer");
                    }
                }

                if (written == 0) {
                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    writeLatches.add(asyncLatch);
                } else {
                    RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);
                }

                if (written < 0) {
                    return -1;
                }

                int registerResult = registerSelectionKey(SelectionKey.OP_READ | SelectionKey.OP_WRITE, this, true);
                if (registerResult < 0) {
                    return -1;
                }

                if (written > 0) {
                    writeTotal += written;
                }

                LogService.i(LOG_TAG, "we have written " + writeTotal + " bytes in total");

                return written;
            }
        }

        public int shutDown(long asyncHandle) {

            if (socketSSLEngine != null) {

                synchronized (socketSSLEngine.shutDownLock) {

                    if (socketSSLEngine.writeCompleted && socketSSLEngine.readCompleted) {
                        RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                        return 0;
                    }
                }

                boolean writeCompleted;

                synchronized (socketSSLEngine.writeLock) {

                    socketSSLEngine.shutDownWrite = true;

                    writeCompleted = socketSSLEngine.writeCompleted;

                    AsyncLatch asyncLatch = new AsyncLatch(asyncHandle);

                    socketSSLEngine.sslShutDownLatches.add(asyncLatch);
                }

                if (!writeCompleted) {
                    LogService.i(LOG_TAG, "socket still require shutdown, setting up channel selector");

                    int registerResult = registerSelectionKey(SelectionKey.OP_READ | SelectionKey.OP_WRITE, socketSSLEngine, false);
                    if (registerResult < 0) {
                        return -1;
                    }
                }

                return 114;

            } else {
                RustyRcsClient.AsyncLatchHandle.destroy(asyncHandle);

                return 0;
            }
        }

        public void close() {

            try {

                synchronized (registerLock) {
                    socketSelector.wakeup();
                    SelectionKey key = socketChannel.keyFor(socketSelector);
                    if (key != null) {
                        key.cancel();
                    }
                }

                socketChannel.close();

            } catch (IOException e) {

                LogService.w(LOG_TAG, "error closing socket:", e);
            }
        }

        private int registerSelectionKey(int key, Object att, boolean forceReplace) {

            synchronized (registerLock) {
                socketSelector.wakeup();
                SelectionKey selectionKey = selectableChannel.keyFor(socketSelector);
                if (forceReplace || selectionKey == null) {
                    try {
                        selectionKey = selectableChannel.register(socketSelector, key, att);
                        LogService.i(LOG_TAG, "selectableChannel event registered with:" + selectionKey + " on event " + key);
                    } catch (ClosedChannelException | IllegalStateException | IllegalArgumentException e) {
                        LogService.w(LOG_TAG, "failed to register selectable channel:", e);
                        return -1;
                    }
                } else {
                    try {
                        int ops = selectionKey.interestOps();
                        LogService.i(LOG_TAG, "selectableChannel already registered with:" + selectionKey + " on event " + ops);
                        Object attachment = selectionKey.attachment();
                        if (!Objects.equals(att, attachment)) {
                            LogService.i(LOG_TAG, "resetting selectionKey attachment");
                            selectionKey.attach(att);
                        }
                        int newOps = ops | key;
                        if (ops != newOps) {
                            LogService.i(LOG_TAG, "adding key " + key + " into selection, ops is now " + newOps);
                            selectionKey.interestOps(newOps);
                        }
                    } catch (CancelledKeyException e) {
                        LogService.w(LOG_TAG, "key is already cancelled:", e);
                        return 11;
                    }
                }
            }

            return 0;
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

        public CipherSuiteCoding getSessionCipherSuite() {
            if (socketSSLEngine != null) {
                return socketSSLEngine.getSessionCipherSuite();
            }
            return null;
        }
    }

    public AsyncSocket createSocket() {

        LogService.i(LOG_TAG, "createSocket");

        try {

            SocketChannel socketChannel = SocketChannel.open();

            LogService.i(LOG_TAG, "SocketChannel opened:" + socketChannel);

            if (socketChannel != null) {

                SelectableChannel selectableChannel = socketChannel.configureBlocking(false);

                LogService.i(LOG_TAG, "configureBlocking=>false for channel:" + selectableChannel);

                return new AsyncSocket(socketSelector, socketChannel, selectableChannel);
            }

        } catch (IOException e) {

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
