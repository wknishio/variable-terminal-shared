package org.vash.vate.org.bouncycastle.tls;

import org.vash.vate.org.bouncycastle.tls.crypto.TlsCrypto;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(TlsCrypto crypto)
    {
        super(crypto, ConnectionEnd.client);
    }

    public boolean isServer()
    {
        return false;
    }
}
