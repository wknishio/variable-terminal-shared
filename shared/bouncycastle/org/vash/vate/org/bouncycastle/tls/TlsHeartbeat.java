package org.vash.vate.org.bouncycastle.tls;

public interface TlsHeartbeat
{
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}
