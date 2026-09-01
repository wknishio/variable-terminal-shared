package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.cms.CMSException;
import org.vash.vate.org.bouncycastle.cms.KeyTransRecipient;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.vash.vate.org.bouncycastle.operator.OperatorException;
import org.vash.vate.org.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;

public abstract class BcKeyTransRecipient
    implements KeyTransRecipient
{
    private AsymmetricKeyParameter recipientKey;

    public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);

        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
