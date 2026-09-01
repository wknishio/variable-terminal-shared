package org.vash.vate.org.bouncycastle.cms.bc;

import java.io.InputStream;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.cms.CMSException;
import org.vash.vate.org.bouncycastle.cms.RecipientOperator;
import org.vash.vate.org.bouncycastle.crypto.BufferedBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.StreamCipher;
import org.vash.vate.org.bouncycastle.crypto.params.KeyParameter;
import org.vash.vate.org.bouncycastle.operator.InputDecryptor;
import org.vash.vate.org.bouncycastle.operator.bc.BcSymmetricKeyUnwrapper;

public class BcKEKEnvelopedRecipient
    extends BcKEKRecipient
{
    public BcKEKEnvelopedRecipient(BcSymmetricKeyUnwrapper unwrapper)
    {
        super(unwrapper);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        KeyParameter secretKey = (KeyParameter)extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                if (dataCipher instanceof BufferedBlockCipher)
                {
                    return new org.vash.vate.org.bouncycastle.crypto.io.CipherInputStream(dataOut, (BufferedBlockCipher)dataCipher);
                }
                else
                {
                    return new org.vash.vate.org.bouncycastle.crypto.io.CipherInputStream(dataOut, (StreamCipher)dataCipher);
                }
            }
        });
    }
}
