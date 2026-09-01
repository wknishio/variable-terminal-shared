package org.vash.vate.org.bouncycastle.operator.bc;

import org.vash.vate.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.vash.vate.org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcRSAAsymmetricKeyUnwrapper
    extends BcAsymmetricKeyUnwrapper
{
    public BcRSAAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId, privateKey);
    }

    protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
