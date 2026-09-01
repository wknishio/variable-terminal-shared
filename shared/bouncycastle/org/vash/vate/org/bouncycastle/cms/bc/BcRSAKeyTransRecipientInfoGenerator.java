package org.vash.vate.org.bouncycastle.cms.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.cert.X509CertificateHolder;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.operator.bc.BcRSAAsymmetricKeyWrapper;

public class BcRSAKeyTransRecipientInfoGenerator
    extends BcKeyTransRecipientInfoGenerator
{
    public BcRSAKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(subjectKeyIdentifier, new BcRSAAsymmetricKeyWrapper(encAlgId, publicKey));
    }

    public BcRSAKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert)
        throws IOException
    {
        super(recipientCert, new BcRSAAsymmetricKeyWrapper(recipientCert.getSubjectPublicKeyInfo().getAlgorithm(), recipientCert.getSubjectPublicKeyInfo()));
    }
}
