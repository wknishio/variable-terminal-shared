package org.vash.vate.org.bouncycastle.cms;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KEKRecipient
    extends Recipient
{
    RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        throws CMSException;
}
