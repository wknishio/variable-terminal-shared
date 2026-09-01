package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import org.vash.vate.org.bouncycastle.crypto.DSA;
import org.vash.vate.org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.DSASigner;
import org.vash.vate.org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.vash.vate.org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw DSA signature type using the BC light-weight API.
 */
public class BcTlsDSASigner
    extends BcTlsDSSSigner
{
    public BcTlsDSASigner(BcTlsCrypto crypto, DSAPrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    protected DSA createDSAImpl(int cryptoHashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
