package org.vash.vate.org.bouncycastle.jce.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.vash.vate.org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.vash.vate.org.bouncycastle.util.Selector;
import org.vash.vate.org.bouncycastle.util.StoreException;
import org.vash.vate.org.bouncycastle.x509.X509CertPairStoreSelector;
import org.vash.vate.org.bouncycastle.x509.X509StoreParameters;
import org.vash.vate.org.bouncycastle.x509.X509StoreSpi;
import org.vash.vate.org.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * A SPI implementation of Bouncy Castle  X509Store</code> for getting
 * cross certificates pairs from an LDAP directory.
 *
 * @see org.vash.vate.org.bouncycastle.x509.X509Store
 */
public class X509StoreLDAPCertPairs extends X509StoreSpi
{

    private LDAPStoreHelper helper;

    public X509StoreLDAPCertPairs()
    {
    }

    /**
     * Initializes this LDAP cross certificate pair store implementation.
     *
     * @param parameters  X509LDAPCertStoreParameters</code>.
     * @throws IllegalArgumentException if  params</code> is not an instance of
     *                                   X509LDAPCertStoreParameters</code>.
     */
    public void engineInit(X509StoreParameters parameters)
    {
        if (!(parameters instanceof X509LDAPCertStoreParameters))
        {
            throw new IllegalArgumentException(
                "Initialization parameters must be an instance of "
                    + X509LDAPCertStoreParameters.class.getName() + ".");
        }
        helper = new LDAPStoreHelper((X509LDAPCertStoreParameters)parameters);
    }

    /**
     * Returns a collection of matching cross certificate pairs from the LDAP
     * location.
     * <p>
     * The selector must be a of type  X509CertPairStoreSelector</code>.
     * If it is not an empty collection is returned.
     * </p>
     * <p>
     * The subject should be a reasonable criteria for a selector.
     * </p>
     * @param selector The selector to use for finding.
     * @return A collection with the matches.
     * @throws StoreException if an exception occurs while searching.
     */
    public Collection engineGetMatches(Selector selector) throws StoreException
    {
        if (!(selector instanceof X509CertPairStoreSelector))
        {
            return Collections.EMPTY_SET;
        }
        X509CertPairStoreSelector xselector = (X509CertPairStoreSelector)selector;
        Set set = new HashSet();
        set.addAll(helper.getCrossCertificatePairs(xselector));
        return set;
    }

}
