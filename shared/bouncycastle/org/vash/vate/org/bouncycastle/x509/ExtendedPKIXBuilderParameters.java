package org.vash.vate.org.bouncycastle.x509;

import org.vash.vate.org.bouncycastle.util.Selector;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This class contains extended parameters for PKIX certification path builders.
 * 
 * @see java.security.cert.PKIXBuilderParameters
 * @see org.vash.vate.org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi
 * @deprecated use PKIXExtendedBuilderParameters
 */
public class ExtendedPKIXBuilderParameters extends ExtendedPKIXParameters
{

    private int maxPathLength = 5;

    private Set excludedCerts = Collections.EMPTY_SET;

    /**
     * Excluded certificates are not used for building a certification path.
     * <p>
     * The returned set is immutable.
     * 
     * @return Returns the excluded certificates.
     */
    public Set getExcludedCerts()
    {
        return Collections.unmodifiableSet(excludedCerts);
    }

    /**
     * Sets the excluded certificates which are not used for building a
     * certification path. If the  Set</code> is  null</code> an
     * empty set is assumed.
     * <p>
     * The given set is cloned to protect it against subsequent modifications.
     * 
     * @param excludedCerts The excluded certificates to set.
     */
    public void setExcludedCerts(Set excludedCerts)
    {
        if (excludedCerts == null)
        {
            excludedCerts = Collections.EMPTY_SET;
        }
        else
        {
            this.excludedCerts = new HashSet(excludedCerts);
        }
    }

    /**
     * Creates an instance of  PKIXBuilderParameters</code> with the
     * specified  Set</code> of most-trusted CAs. Each element of the set
     * is a {@link TrustAnchor TrustAnchor}.
     * 
     * <p>
     * Note that the  Set</code> is copied to protect against subsequent
     * modifications.
     * 
     * @param trustAnchors a  Set</code> of  TrustAnchor</code>s
     * @param targetConstraints a  Selector</code> specifying the
     *            constraints on the target certificate or attribute
     *            certificate.
     * @throws InvalidAlgorithmParameterException if  trustAnchors</code>
     *             is empty.
     * @throws NullPointerException if  trustAnchors</code> is
     *              null</code>
     * @throws ClassCastException if any of the elements of
     *              trustAnchors</code> is not of type
     *              java.security.cert.TrustAnchor</code>
     */
    public ExtendedPKIXBuilderParameters(Set trustAnchors,
            Selector targetConstraints)
            throws InvalidAlgorithmParameterException
    {
        super(trustAnchors);
        setTargetConstraints(targetConstraints);
    }

    /**
     * Sets the maximum number of intermediate non-self-issued certificates in a
     * certification path. The PKIX  CertPathBuilder</code> must not
     * build paths longer then this length.
     * <p>
     * A value of 0 implies that the path can only contain a single certificate.
     * A value of -1 does not limit the length. The default length is 5.
     * 
     * <p>
     * 
     * The basic constraints extension of a CA certificate overrides this value
     * if smaller.
     * 
     * @param maxPathLength the maximum number of non-self-issued intermediate
     *            certificates in the certification path
     * @throws InvalidParameterException if  maxPathLength</code> is set
     *             to a value less than -1
     * 
     * @see org.vash.vate.org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi
     * @see #getMaxPathLength
     */
    public void setMaxPathLength(int maxPathLength)
    {
        if (maxPathLength < -1)
        {
            throw new InvalidParameterException("The maximum path "
                    + "length parameter can not be less than -1.");
        }
        this.maxPathLength = maxPathLength;
    }

    /**
     * Returns the value of the maximum number of intermediate non-self-issued
     * certificates in the certification path.
     * 
     * @return the maximum number of non-self-issued intermediate certificates
     *         in the certification path, or -1 if no limit exists.
     * 
     * @see #setMaxPathLength(int)
     */
    public int getMaxPathLength()
    {
        return maxPathLength;
    }

    /**
     * Can alse handle  ExtendedPKIXBuilderParameters</code> and
     *  PKIXBuilderParameters</code>.
     * 
     * @param params Parameters to set.
     * @see org.vash.vate.org.bouncycastle.x509.ExtendedPKIXParameters#setParams(java.security.cert.PKIXParameters)
     */
    protected void setParams(PKIXParameters params)
    {
        super.setParams(params);
        if (params instanceof ExtendedPKIXBuilderParameters)
        {
            ExtendedPKIXBuilderParameters _params = (ExtendedPKIXBuilderParameters) params;
            maxPathLength = _params.maxPathLength;
            excludedCerts = new HashSet(_params.excludedCerts);
        }
        if (params instanceof PKIXBuilderParameters)
        {
            PKIXBuilderParameters _params = (PKIXBuilderParameters) params;
            maxPathLength = _params.getMaxPathLength();
        }
    }

    /**
     * Makes a copy of this  PKIXParameters</code> object. Changes to the
     * copy will not affect the original and vice versa.
     * 
     * @return a copy of this  PKIXParameters</code> object
     */
    public Object clone()
    {
        ExtendedPKIXBuilderParameters params = null;
        try
        {
            params = new ExtendedPKIXBuilderParameters(getTrustAnchors(),
                    getTargetConstraints());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        params.setParams(this);
        return params;
    }

    /**
     * Returns an instance of  ExtendedPKIXParameters</code> which can be
     * safely casted to  ExtendedPKIXBuilderParameters</code>.
     * <p>
     * This method can be used to get a copy from other
     *  PKIXBuilderParameters</code>,  PKIXParameters</code>,
     * and  ExtendedPKIXParameters</code> instances.
     * 
     * @param pkixParams The PKIX parameters to create a copy of.
     * @return An  ExtendedPKIXBuilderParameters</code> instance.
     */
    public static ExtendedPKIXParameters getInstance(PKIXParameters pkixParams)
    {
        ExtendedPKIXBuilderParameters params;
        try
        {
            params = new ExtendedPKIXBuilderParameters(pkixParams
                    .getTrustAnchors(), X509CertStoreSelector
                    .getInstance((X509CertSelector) pkixParams
                            .getTargetCertConstraints()));
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        params.setParams(pkixParams);
        return params;
    }
}
