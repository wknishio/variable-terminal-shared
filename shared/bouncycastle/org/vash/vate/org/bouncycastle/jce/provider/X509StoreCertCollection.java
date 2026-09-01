package org.vash.vate.org.bouncycastle.jce.provider;

import java.util.Collection;

import org.vash.vate.org.bouncycastle.util.CollectionStore;
import org.vash.vate.org.bouncycastle.util.Selector;
import org.vash.vate.org.bouncycastle.x509.X509CollectionStoreParameters;
import org.vash.vate.org.bouncycastle.x509.X509StoreParameters;
import org.vash.vate.org.bouncycastle.x509.X509StoreSpi;

public class X509StoreCertCollection
    extends X509StoreSpi
{
    private CollectionStore _store;

    public X509StoreCertCollection()
    {
    }

    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509CollectionStoreParameters))
        {
            throw new IllegalArgumentException(params.toString());
        }

        _store = new CollectionStore(((X509CollectionStoreParameters)params).getCollection());
    }

    public Collection engineGetMatches(Selector selector)
    {
        return _store.getMatches(selector);
    }
}
