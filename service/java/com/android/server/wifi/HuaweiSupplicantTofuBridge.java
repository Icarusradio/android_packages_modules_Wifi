/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.wifi;

import android.os.Handler;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceSpecificException;
import android.util.Log;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import vendor.lineage.wifi.tofu.IWifiTofuBridge;

/** Optional vendor adapter. Each acquisition gets a fresh stream and revocable session token. */
final class HuaweiSupplicantTofuBridge {
    private static final String TAG = "HuaweiSupplicantTofu";
    private static final String SERVICE = IWifiTofuBridge.DESCRIPTOR + "/default";
    private final Handler mHandler;
    private volatile Session mSession;
    private volatile IWifiTofuBridge mService;
    private CountDownLatch mServiceReady;

    interface Listener {
        void onCertificate(int depth, CertificateEventInfo certificate);
        void onFailure();
    }

    HuaweiSupplicantTofuBridge(Handler handler) {
        mHandler = handler;
        resolveService();
    }

    private synchronized CountDownLatch resolveService() {
        if (mServiceReady != null) return mServiceReady;
        CountDownLatch ready = new CountDownLatch(1);
        mServiceReady = ready;
        Thread resolver = new Thread(() -> {
            try {
                if (ServiceManager.isDeclared(SERVICE)) {
                    IBinder binder = ServiceManager.waitForDeclaredService(SERVICE);
                    if (binder != null) {
                        binder.linkToDeath(() -> {
                            synchronized (HuaweiSupplicantTofuBridge.this) {
                                if (mService != null && mService.asBinder() == binder) {
                                    mService = null;
                                    mServiceReady = null;
                                }
                            }
                        }, 0);
                        synchronized (HuaweiSupplicantTofuBridge.this) {
                            if (binder.isBinderAlive()) {
                                mService = IWifiTofuBridge.Stub.asInterface(binder);
                            } else {
                                mServiceReady = null;
                            }
                        }
                    }
                }
            } catch (RemoteException | SecurityException e) {
                Log.e(TAG, "Cannot resolve certificate adapter");
            } finally {
                ready.countDown();
            }
        }, "HuaweiWifiTofuService");
        resolver.setDaemon(true);
        resolver.start();
        return ready;
    }

    private IWifiTofuBridge getService() {
        try {
            // ServiceManager's module API can wait indefinitely. Keep that wait off the Wi-Fi
            // thread and bound our own wait; a missing adapter never enables the feature.
            resolveService().await(500, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return mService;
    }

    private synchronized void clearService() {
        mService = null;
        mServiceReady = null;
    }

    boolean isAvailable(String iface) {
        try {
            IWifiTofuBridge service = getService();
            return service != null && service.isSupported(iface);
        } catch (RemoteException | ServiceSpecificException | SecurityException e) {
            clearService();
            return false;
        }
    }

    boolean start(String iface, int nativeNetworkId, Listener listener) {
        stop(iface);
        try {
            IWifiTofuBridge service = getService();
            if (service == null) return false;
            ParcelFileDescriptor descriptor = service.openMonitor(iface, nativeNetworkId);
            if (descriptor == null) return false;
            Session session = new Session(iface, descriptor, listener);
            mSession = session;
            new Thread(session::read, "HuaweiWifiTofu").start();
            return true;
        } catch (RemoteException | ServiceSpecificException | SecurityException e) {
            clearService();
            Log.e(TAG, "Cannot open certificate monitor");
            return false;
        }
    }

    void stop(String iface) {
        Session session = mSession;
        if (session != null && session.iface.equals(iface)) {
            mSession = null;
            session.close();
        }
    }

    void stopAll() {
        Session session = mSession;
        if (session != null) stop(session.iface);
    }

    private final class Session {
        final String iface;
        final Listener listener;
        final DataInputStream input;
        volatile boolean cancelled;

        Session(String iface, ParcelFileDescriptor descriptor, Listener listener) {
            this.iface = iface;
            this.listener = listener;
            input = new DataInputStream(new ParcelFileDescriptor.AutoCloseInputStream(descriptor));
        }

        boolean isCurrent() {
            return !cancelled && mSession == this;
        }

        void close() {
            cancelled = true;
            try {
                input.close();
            } catch (IOException ignored) {
                // Closing the stream also cancels the native monitor.
            }
        }

        void read() {
            try {
                while (isCurrent()) {
                    HuaweiTofuCertificateReader.Certificate certificate =
                            HuaweiTofuCertificateReader.read(input);
                    CertificateEventInfo event = new CertificateEventInfo(certificate.cert,
                            certificate.hash, this::isCurrent);
                    mHandler.post(() -> {
                        if (isCurrent()) listener.onCertificate(certificate.depth, event);
                    });
                }
            } catch (IOException | CertificateException e) {
                mHandler.post(() -> {
                    if (isCurrent()) {
                        Log.e(TAG, "Certificate monitor failed; aborting acquisition");
                        listener.onFailure();
                    }
                });
            } finally {
                // Do not revoke queued certificates here: a normal leaf may already be queued.
                try {
                    input.close();
                } catch (IOException ignored) { }
            }
        }
    }
}
