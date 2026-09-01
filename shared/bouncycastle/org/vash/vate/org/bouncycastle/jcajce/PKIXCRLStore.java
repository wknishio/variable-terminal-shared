package org.vash.vate.org.bouncycastle.jcajce;

import java.security.cert.CRL;
import java.util.Collection;

import org.vash.vate.org.bouncycastle.util.Selector;
import org.vash.vate.org.bouncycastle.util.Store;
import org.vash.vate.org.bouncycastle.util.StoreException;

public interface PKIXCRLStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
