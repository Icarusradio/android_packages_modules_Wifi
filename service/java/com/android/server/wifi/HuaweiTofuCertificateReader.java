/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.wifi;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Bounded, binary certificate protocol shared with the Huawei vendor adapter. */
final class HuaweiTofuCertificateReader {
    static final int MAX_CERTIFICATE_SIZE = 65536;

    static final class Certificate {
        final int depth;
        final X509Certificate cert;
        final String hash;

        Certificate(int depth, X509Certificate cert, String hash) {
            this.depth = depth;
            this.cert = cert;
            this.hash = hash;
        }
    }

    static Certificate read(DataInputStream input) throws IOException, CertificateException {
        int depth = input.readInt();
        int size = input.readInt();
        if (depth < 0 || depth > 100 || size <= 0 || size > MAX_CERTIFICATE_SIZE) {
            throw new IOException("Invalid TOFU certificate frame");
        }
        byte[] encoded = new byte[size];
        input.readFully(encoded);
        ByteArrayInputStream bytes = new ByteArrayInputStream(encoded);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(bytes);
        if (bytes.available() != 0 || !MessageDigest.isEqual(encoded, cert.getEncoded())) {
            throw new CertificateException("Certificate frame is not a single DER certificate");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            StringBuilder hash = new StringBuilder(64);
            for (byte value : digest) {
                hash.append(Character.forDigit((value & 0xff) >>> 4, 16));
                hash.append(Character.forDigit(value & 0xf, 16));
            }
            return new Certificate(depth, cert, hash.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 unavailable", e);
        }
    }

    private HuaweiTofuCertificateReader() {}
}
