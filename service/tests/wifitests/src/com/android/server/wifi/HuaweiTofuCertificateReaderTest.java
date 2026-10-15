/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.wifi;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.util.Arrays;

/** Also runnable as a plain JUnit host test: this protocol decoder has no Android dependency. */
public class HuaweiTofuCertificateReaderTest {
    private byte[] frame(int depth, int length, byte[] bytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeInt(depth);
        output.writeInt(length);
        output.write(bytes);
        return buffer.toByteArray();
    }

    private HuaweiTofuCertificateReader.Certificate decode(byte[] bytes) throws Exception {
        return HuaweiTofuCertificateReader.read(new DataInputStream(new ByteArrayInputStream(bytes)));
    }

    @Test
    public void completeDerProducesMatchingHashAndDepth() throws Exception {
        byte[] der = FakeKeys.CA_CERT0.getEncoded();
        HuaweiTofuCertificateReader.Certificate cert = decode(frame(2, der.length, der));
        assertEquals(2, cert.depth);
        assertArrayEquals(der, cert.cert.getEncoded());
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(der);
        StringBuilder expected = new StringBuilder();
        for (byte value : hash) expected.append(String.format("%02x", value & 0xff));
        assertEquals(expected.toString(), cert.hash);
    }

    @Test
    public void rejectsInvalidLengthAndNativeFailure() throws Exception {
        for (int[] header : new int[][]{{-1, 0}, {101, 1}, {0, -1}, {0, 0}, {0, 65537}}) {
            try {
                decode(frame(header[0], header[1], new byte[0]));
                fail("Accepted invalid header");
            } catch (IOException expected) { }
        }
    }

    @Test
    public void rejectsTruncatedDer() throws Exception {
        byte[] der = FakeKeys.CA_CERT0.getEncoded();
        try {
            decode(frame(0, der.length, Arrays.copyOf(der, der.length - 1)));
            fail("Accepted truncated frame");
        } catch (IOException expected) { }
    }

    @Test
    public void rejectsInvalidDerAndTrailingContent() throws Exception {
        for (byte[] bytes : new byte[][]{{1, 2, 3},
                Arrays.copyOf(FakeKeys.CA_CERT0.getEncoded(), FakeKeys.CA_CERT0.getEncoded().length + 1)}) {
            try {
                decode(frame(0, bytes.length, bytes));
                fail("Accepted invalid DER");
            } catch (CertificateException expected) { }
        }
    }
}
