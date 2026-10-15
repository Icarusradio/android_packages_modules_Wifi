// SPDX-License-Identifier: Apache-2.0
package vendor.lineage.wifi.tofu;

import android.os.ParcelFileDescriptor;

/** Device-specific adapter for an unmodified Huawei HIDL supplicant. */
@VintfStability
interface IWifiTofuBridge {
    /** Checks that the authenticated control endpoint accepts monitor subscriptions. */
    boolean isSupported(String ifaceName);

    /**
     * Opens a fresh subscription while the supplied native network is disabled.
     * Only system_server may call this service. The returned read-only protocol is
     * a stream of big-endian uint32 depth, uint32 length, and DER certificate bytes.
     * Depth 0xffffffff and zero length indicate an error. EOF is also an error.
     * Closing the descriptor cancels this subscription. Opening another cancels the old one.
     */
    ParcelFileDescriptor openMonitor(String ifaceName, int networkId);
}
