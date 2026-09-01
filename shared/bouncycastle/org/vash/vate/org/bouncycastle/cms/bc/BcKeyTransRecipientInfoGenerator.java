package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.vash.vate.org.bouncycastle.cert.X509CertificateHolder;
import org.vash.vate.org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.vash.vate.org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(new IssuerAndSerialNumber(recipientCert.toASN1Structure()), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}