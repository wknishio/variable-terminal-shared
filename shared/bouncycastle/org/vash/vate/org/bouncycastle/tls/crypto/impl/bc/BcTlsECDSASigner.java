package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import org.vash.vate.org.bouncycastle.crypto.DSA;
import org.vash.vate.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.ECDSASigner;
import org.vash.vate.org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.vash.vate.org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw ECDSA signature type using the BC light-weight API.
 */
public class BcTlsECDSASigner
    extends BcTlsDSSSigner
{
    public BcTlsECDSASigner(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    protected DSA createDSAImpl(int cryptoHashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
