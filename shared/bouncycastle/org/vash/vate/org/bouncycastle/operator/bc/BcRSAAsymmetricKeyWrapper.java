package org.vash.vate.org.bouncycastle.operator.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.vash.vate.org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.crypto.util.PublicKeyFactory;

public class BcRSAAsymmetricKeyWrapper
    extends BcAsymmetricKeyWrapper
{
    public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(encAlgId, publicKey);
    }

    public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        super(encAlgId, PublicKeyFactory.createKey(publicKeyInfo));
    }

    protected AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
