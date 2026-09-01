package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import org.vash.vate.org.bouncycastle.crypto.DSA;
import org.vash.vate.org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.DSASigner;
import org.vash.vate.org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw DSA signature type using the BC light-weight API.
 */
public class BcTlsDSAVerifier
    extends BcTlsDSSVerifier
{
    public BcTlsDSAVerifier(BcTlsCrypto crypto, DSAPublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    protected DSA createDSAImpl()
    {
        return new DSASigner();
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
