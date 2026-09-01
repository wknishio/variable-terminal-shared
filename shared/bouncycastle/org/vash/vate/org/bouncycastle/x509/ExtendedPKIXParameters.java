package org.vash.vate.org.bouncycastle.x509;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.vash.vate.org.bouncycastle.util.Selector;
import org.vash.vate.org.bouncycastle.util.Store;

/**
 * This class extends the PKIXParameters with a validity model parameter.
 *
 * @deprecated use PKIXExtendedParameters
 */
public class ExtendedPKIXParameters
    extends PKIXParameters
{

    private List stores;

    private Selector selector;

    private boolean additionalLocationsEnabled;

    private List additionalStores;

    private Set trustedACIssuers;

    private Set necessaryACAttributes;

    private Set prohibitedACAttributes;

    private Set attrCertCheckers;

    /**
     * Creates an instance of  PKIXParameters</code> with the specified
     *  Set</code> of most-trusted CAs. Each element of the set is a
     * {@link TrustAnchor TrustAnchor}.
     * <p>
     *     Note that the  Set</code>
     * is copied to protect against subsequent modifications.
     * </p>
     * 
     * @param trustAnchors a  Set</code> of  TrustAnchor</code>s
     * @throws InvalidAlgorithmParameterException if the specified
     *              Set</code> is empty.
     * @throws NullPointerException if the specified  Set</code> is
     *              null</code>
     * @throws ClassCastException if any of the elements in the  Set</code>
     *             is not of type  java.security.cert.TrustAnchor</code>
     */
    public ExtendedPKIXParameters(Set trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        super(trustAnchors);
        stores = new ArrayList();
        additionalStores = new ArrayList();
        trustedACIssuers = new HashSet();
        necessaryACAttributes = new HashSet();
        prohibitedACAttributes = new HashSet();
        attrCertCheckers = new HashSet();
    }

    /**
     * Returns an instance with the parameters of a given
     *  PKIXParameters</code> object.
     * 
     * @param pkixParams The given  PKIXParameters</code>
     * @return an extended PKIX params object
     */
    public static ExtendedPKIXParameters getInstance(PKIXParameters pkixParams)
    {
        ExtendedPKIXParameters params;
        try
        {
            params = new ExtendedPKIXParameters(pkixParams.getTrustAnchors());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        params.setParams(pkixParams);
        return params;
    }

    /**
     * Method to support  clone()</code> under J2ME.
     *  super.clone()</code> does not exist and fields are not copied.
     * 
     * @param params Parameters to set. If this are
     *             ExtendedPKIXParameters</code> they are copied to.
     */
    protected void setParams(PKIXParameters params)
    {
        setDate(params.getDate());
        setCertPathCheckers(params.getCertPathCheckers());
        setCertStores(params.getCertStores());
        setAnyPolicyInhibited(params.isAnyPolicyInhibited());
        setExplicitPolicyRequired(params.isExplicitPolicyRequired());
        setPolicyMappingInhibited(params.isPolicyMappingInhibited());
        setRevocationEnabled(params.isRevocationEnabled());
        setInitialPolicies(params.getInitialPolicies());
        setPolicyQualifiersRejected(params.getPolicyQualifiersRejected());
        setSigProvider(params.getSigProvider());
        setTargetCertConstraints(params.getTargetCertConstraints());
        try
        {
            setTrustAnchors(params.getTrustAnchors());
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(e.getMessage());
        }
        if (params instanceof ExtendedPKIXParameters)
        {
            ExtendedPKIXParameters _params = (ExtendedPKIXParameters) params;
            validityModel = _params.validityModel;
            useDeltas = _params.useDeltas;
            additionalLocationsEnabled = _params.additionalLocationsEnabled;
            selector = _params.selector == null ? null
                : (Selector) _params.selector.clone();
            stores = new ArrayList(_params.stores);
            additionalStores = new ArrayList(_params.additionalStores);
            trustedACIssuers = new HashSet(_params.trustedACIssuers);
            prohibitedACAttributes = new HashSet(_params.prohibitedACAttributes);
            necessaryACAttributes = new HashSet(_params.necessaryACAttributes);
            attrCertCheckers = new HashSet(_params.attrCertCheckers);
        }
    }

    /**
     * This is the default PKIX validity model. Actually there are two variants
     * of this: The PKIX model and the modified PKIX model. The PKIX model
     * verifies that all involved certificates must have been valid at the
     * current time. The modified PKIX model verifies that all involved
     * certificates were valid at the signing time. Both are indirectly choosen
     * with the {@link PKIXParameters#setDate(java.util.Date)} method, so this
     * methods sets the Date when  all</em> certificates must have been
     * valid.
     */
    public static final int PKIX_VALIDITY_MODEL = 0;

    /**
     * This model uses the following validity model. Each certificate must have
     * been valid at the moment where is was used. That means the end
     * certificate must have been valid at the time the signature was done. The
     * CA certificate which signed the end certificate must have been valid,
     * when the end certificate was signed. The CA (or Root CA) certificate must
     * have been valid, when the CA certificate was signed and so on. So the
     * {@link PKIXParameters#setDate(java.util.Date)} method sets the time, when
     * the  end certificate</em> must have been valid.
     * <p>
     * It is used e.g.
     * in the German signature law.
     * </p>
     */
    public static final int CHAIN_VALIDITY_MODEL = 1;

    private int validityModel = PKIX_VALIDITY_MODEL;

    private boolean useDeltas = false;

    /**
     * Defaults to  false</code>.
     * 
     * @return Returns if delta CRLs should be used.
     */
    public boolean isUseDeltasEnabled()
    {
        return useDeltas;
    }

    /**
     * Sets if delta CRLs should be used for checking the revocation status.
     * 
     * @param useDeltas  true</code> if delta CRLs should be used.
     */
    public void setUseDeltasEnabled(boolean useDeltas)
    {
        this.useDeltas = useDeltas;
    }

    /**
     * @return Returns the validity model.
     * @see #CHAIN_VALIDITY_MODEL
     * @see #PKIX_VALIDITY_MODEL
     */
    public int getValidityModel()
    {
        return validityModel;
    }

    /**
     * Sets the Java CertStore to this extended PKIX parameters.
     * 
     * @throws ClassCastException if an element of  stores</code> is not
     *             a  CertStore</code>.
     */
    public void setCertStores(List stores)
    {
        if (stores != null)
        {
            Iterator it = stores.iterator();
            while (it.hasNext())
            {
                addCertStore((CertStore)it.next());
            }
        }
    }

    /**
     * Sets the Bouncy Castle Stores for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     * <p>
     * The  List</code> is cloned.
     * 
     * @param stores A list of stores to use.
     * @see #getStores
     * @throws ClassCastException if an element of  stores</code> is not
     *             a {@link Store}.
     */
    public void setStores(List stores)
    {
        if (stores == null)
        {
            this.stores = new ArrayList();
        }
        else
        {
            for (Iterator i = stores.iterator(); i.hasNext();)
            {
                if (!(i.next() instanceof Store))
                {
                    throw new ClassCastException(
                        "All elements of list must be "
                            + "of type org.vash.vate.org.bouncycastle.util.Store.");
                }
            }
            this.stores = new ArrayList(stores);
        }
    }

    /**
     * Adds a Bouncy Castle {@link Store} to find CRLs, certificates, attribute
     * certificates or cross certificates.
     * <p>
     * This method should be used to add local stores, like collection based
     * X.509 stores, if available. Local stores should be considered first,
     * before trying to use additional (remote) locations, because they do not
     * need possible additional network traffic.
     * <p>
     * If  store</code> is  null</code> it is ignored.
     * 
     * @param store The store to add.
     * @see #getStores
     */
    public void addStore(Store store)
    {
        if (store != null)
        {
            stores.add(store);
        }
    }

    /**
     * Adds an additional Bouncy Castle {@link Store} to find CRLs, certificates,
     * attribute certificates or cross certificates.
     * <p>
     * You should not use this method. This method is used for adding additional
     * X.509 stores, which are used to add (remote) locations, e.g. LDAP, found
     * during X.509 object processing, e.g. in certificates or CRLs. This method
     * is used in PKIX certification path processing.
     * <p>
     * If  store</code> is  null</code> it is ignored.
     * 
     * @param store The store to add.
     * @see #getStores()
     * @deprecated use addStore().
     */
    public void addAdditionalStore(Store store)
    {
        if (store != null)
        {
            additionalStores.add(store);
        }
    }

    /**
     * @deprecated
     */
    public void addAddionalStore(Store store)
    {
        addAdditionalStore(store);      
    }

    /**
     * Returns an immutable  List</code> of additional Bouncy Castle
     *  Store</code>s used for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     * 
     * @return an immutable  List</code> of additional Bouncy Castle
     *          Store</code>s. Never  null</code>.
     * 
     * @see #addAdditionalStore(Store)
     */
    public List getAdditionalStores()
    {
        return Collections.unmodifiableList(additionalStores);
    }

    /**
     * Returns an immutable  List</code> of Bouncy Castle
     *  Store</code>s used for finding CRLs, certificates, attribute
     * certificates or cross certificates.
     * 
     * @return an immutable  List</code> of Bouncy Castle
     *          Store</code>s. Never  null</code>.
     * 
     * @see #setStores(List)
     */
    public List getStores()
    {
        return Collections.unmodifiableList(new ArrayList(stores));
    }

    /**
     * @param validityModel The validity model to set.
     * @see #CHAIN_VALIDITY_MODEL
     * @see #PKIX_VALIDITY_MODEL
     */
    public void setValidityModel(int validityModel)
    {
        this.validityModel = validityModel;
    }

    public Object clone()
    {
        ExtendedPKIXParameters params;
        try
        {
            params = new ExtendedPKIXParameters(getTrustAnchors());
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
     * Returns if additional {@link X509Store}s for locations like LDAP found
     * in certificates or CRLs should be used.
     * 
     * @return Returns  true</code> if additional stores are used.
     */
    public boolean isAdditionalLocationsEnabled()
    {
        return additionalLocationsEnabled;
    }

    /**
     * Sets if additional {@link X509Store}s for locations like LDAP found in
     * certificates or CRLs should be used.
     * 
     * @param enabled  true</code> if additional stores are used.
     */
    public void setAdditionalLocationsEnabled(boolean enabled)
    {
        additionalLocationsEnabled = enabled;
    }

    /**
     * Returns the required constraints on the target certificate or attribute
     * certificate. The constraints are returned as an instance of
     *  Selector</code>. If  null</code>, no constraints are
     * defined.
     * 
     * <p>
     * The target certificate in a PKIX path may be a certificate or an
     * attribute certificate.
     * <p>
     * Note that the  Selector</code> returned is cloned to protect
     * against subsequent modifications.
     * 
     * @return a  Selector</code> specifying the constraints on the
     *         target certificate or attribute certificate (or  null</code>)
     * @see #setTargetConstraints
     * @see X509CertStoreSelector
     * @see X509AttributeCertStoreSelector
     */
    public Selector getTargetConstraints()
    {
        if (selector != null)
        {
            return (Selector) selector.clone();
        }
        else
        {
            return null;
        }
    }

    /**
     * Sets the required constraints on the target certificate or attribute
     * certificate. The constraints are specified as an instance of
     *  Selector</code>. If  null</code>, no constraints are
     * defined.
     * <p>
     * The target certificate in a PKIX path may be a certificate or an
     * attribute certificate.
     * <p>
     * Note that the  Selector</code> specified is cloned to protect
     * against subsequent modifications.
     * 
     * @param selector a  Selector</code> specifying the constraints on
     *            the target certificate or attribute certificate (or
     *             null</code>)
     * @see #getTargetConstraints
     * @see X509CertStoreSelector
     * @see X509AttributeCertStoreSelector
     */
    public void setTargetConstraints(Selector selector)
    {
        if (selector != null)
        {
            this.selector = (Selector) selector.clone();
        }
        else
        {
            this.selector = null;
        }
    }

    /**
     * Sets the required constraints on the target certificate. The constraints
     * are specified as an instance of  X509CertSelector</code>. If
     *  null</code>, no constraints are defined.
     * 
     * <p>
     * This method wraps the given  X509CertSelector</code> into a
     *  X509CertStoreSelector</code>.
     * <p>
     * Note that the  X509CertSelector</code> specified is cloned to
     * protect against subsequent modifications.
     * 
     * @param selector a  X509CertSelector</code> specifying the
     *            constraints on the target certificate (or  null</code>)
     * @see #getTargetCertConstraints
     * @see X509CertStoreSelector
     */
    public void setTargetCertConstraints(CertSelector selector)
    {
        super.setTargetCertConstraints(selector);
        if (selector != null)
        {
            this.selector = X509CertStoreSelector
                .getInstance((X509CertSelector) selector);
        }
        else
        {
            this.selector = null;
        }
    }

    /**
     * Returns the trusted attribute certificate issuers. If attribute
     * certificates is verified the trusted AC issuers must be set.
     * <p>
     * The returned  Set</code> consists of  TrustAnchor</code>s.
     * <p>
     * The returned  Set</code> is immutable. Never  null</code>
     * 
     * @return Returns an immutable set of the trusted AC issuers.
     */
    public Set getTrustedACIssuers()
    {
        return Collections.unmodifiableSet(trustedACIssuers);
    }

    /**
     * Sets the trusted attribute certificate issuers. If attribute certificates
     * is verified the trusted AC issuers must be set.
     * <p>
     * The  trustedACIssuers</code> must be a  Set</code> of
     *  TrustAnchor</code>
     * <p>
     * The given set is cloned.
     * 
     * @param trustedACIssuers The trusted AC issuers to set. Is never
     *             null</code>.
     * @throws ClassCastException if an element of  stores</code> is not
     *             a  TrustAnchor</code>.
     */
    public void setTrustedACIssuers(Set trustedACIssuers)
    {
        if (trustedACIssuers == null)
        {
            this.trustedACIssuers.clear();
            return;
        }
        for (Iterator it = trustedACIssuers.iterator(); it.hasNext();)
        {
            if (!(it.next() instanceof TrustAnchor))
            {
                throw new ClassCastException("All elements of set must be "
                    + "of type " + TrustAnchor.class.getName() + ".");
            }
        }
        this.trustedACIssuers.clear();
        this.trustedACIssuers.addAll(trustedACIssuers);
    }

    /**
     * Returns the neccessary attributes which must be contained in an attribute
     * certificate.
     * <p>
     * The returned  Set</code> is immutable and contains
     *  String</code>s with the OIDs.
     * 
     * @return Returns the necessary AC attributes.
     */
    public Set getNecessaryACAttributes()
    {
        return Collections.unmodifiableSet(necessaryACAttributes);
    }

    /**
     * Sets the neccessary which must be contained in an attribute certificate.
     * <p>
     * The  Set</code> must contain  String</code>s with the
     * OIDs.
     * <p>
     * The set is cloned.
     * 
     * @param necessaryACAttributes The necessary AC attributes to set.
     * @throws ClassCastException if an element of
     *              necessaryACAttributes</code> is not a
     *              String</code>.
     */
    public void setNecessaryACAttributes(Set necessaryACAttributes)
    {
        if (necessaryACAttributes == null)
        {
            this.necessaryACAttributes.clear();
            return;
        }
        for (Iterator it = necessaryACAttributes.iterator(); it.hasNext();)
        {
            if (!(it.next() instanceof String))
            {
                throw new ClassCastException("All elements of set must be "
                    + "of type String.");
            }
        }
        this.necessaryACAttributes.clear();
        this.necessaryACAttributes.addAll(necessaryACAttributes);
    }

    /**
     * Returns the attribute certificates which are not allowed.
     * <p>
     * The returned  Set</code> is immutable and contains
     *  String</code>s with the OIDs.
     * 
     * @return Returns the prohibited AC attributes. Is never  null</code>.
     */
    public Set getProhibitedACAttributes()
    {
        return Collections.unmodifiableSet(prohibitedACAttributes);
    }

    /**
     * Sets the attribute certificates which are not allowed.
     * <p>
     * The  Set</code> must contain  String</code>s with the
     * OIDs.
     * <p>
     * The set is cloned.
     * 
     * @param prohibitedACAttributes The prohibited AC attributes to set.
     * @throws ClassCastException if an element of
     *              prohibitedACAttributes</code> is not a
     *              String</code>.
     */
    public void setProhibitedACAttributes(Set prohibitedACAttributes)
    {
        if (prohibitedACAttributes == null)
        {
            this.prohibitedACAttributes.clear();
            return;
        }
        for (Iterator it = prohibitedACAttributes.iterator(); it.hasNext();)
        {
            if (!(it.next() instanceof String))
            {
                throw new ClassCastException("All elements of set must be "
                    + "of type String.");
            }
        }
        this.prohibitedACAttributes.clear();
        this.prohibitedACAttributes.addAll(prohibitedACAttributes);
    }

    /**
     * Returns the attribute certificate checker. The returned set contains
     * {@link PKIXAttrCertChecker}s and is immutable.
     * 
     * @return Returns the attribute certificate checker. Is never
     *          null</code>.
     */
    public Set getAttrCertCheckers()
    {
        return Collections.unmodifiableSet(attrCertCheckers);
    }

    /**
     * Sets the attribute certificate checkers.
     * <p>
     * All elements in the  Set</code> must a {@link PKIXAttrCertChecker}.
     * <p>
     * The given set is cloned.
     * 
     * @param attrCertCheckers The attribute certificate checkers to set. Is
     *            never  null</code>.
     * @throws ClassCastException if an element of  attrCertCheckers</code>
     *             is not a  PKIXAttrCertChecker</code>.
     */
    public void setAttrCertCheckers(Set attrCertCheckers)
    {
        if (attrCertCheckers == null)
        {
            this.attrCertCheckers.clear();
            return;
        }
        for (Iterator it = attrCertCheckers.iterator(); it.hasNext();)
        {
            if (!(it.next() instanceof PKIXAttrCertChecker))
            {
                throw new ClassCastException("All elements of set must be "
                    + "of type " + PKIXAttrCertChecker.class.getName() + ".");
            }
        }
        this.attrCertCheckers.clear();
        this.attrCertCheckers.addAll(attrCertCheckers);
    }

}
