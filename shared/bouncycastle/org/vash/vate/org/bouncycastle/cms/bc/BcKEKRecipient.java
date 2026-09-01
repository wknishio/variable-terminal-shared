package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.cms.CMSException;
import org.vash.vate.org.bouncycastle.cms.KEKRecipient;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.operator.OperatorException;
import org.vash.vate.org.bouncycastle.operator.SymmetricKeyUnwrapper;
import org.vash.vate.org.bouncycastle.operator.bc.BcSymmetricKeyUnwrapper;

public abstract class BcKEKRecipient
    implements KEKRecipient
{
    private SymmetricKeyUnwrapper unwrapper;

    public BcKEKRecipient(BcSymmetricKeyUnwrapper unwrapper)
    {
        this.unwrapper = unwrapper;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(contentEncryptionAlgorithm, encryptedContentEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
