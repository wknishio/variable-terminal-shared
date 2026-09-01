package org.vash.vate.org.bouncycastle.tls;

import org.vash.vate.org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsPSK
{
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}
