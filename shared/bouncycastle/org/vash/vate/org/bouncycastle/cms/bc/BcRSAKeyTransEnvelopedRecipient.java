package org.vash.vate.org.bouncycastle.cms.bc;

import java.io.InputStream;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.cms.CMSException;
import org.vash.vate.org.bouncycastle.cms.RecipientOperator;
import org.vash.vate.org.bouncycastle.crypto.BufferedBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.StreamCipher;
import org.vash.vate.org.bouncycastle.crypto.io.CipherInputStream;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.operator.InputDecryptor;

public class BcRSAKeyTransEnvelopedRecipient
    extends BcKeyTransRecipient
{
    public BcRSAKeyTransEnvelopedRecipient(AsymmetricKeyParameter key)
    {
        super(key);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        CipherParameters secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataIn)
            {
                if (dataCipher instanceof BufferedBlockCipher)
                {
                    return new CipherInputStream(dataIn, (BufferedBlockCipher)dataCipher);
                }
                else
                {
                    return new CipherInputStream(dataIn, (StreamCipher)dataCipher);
                }
            }
        });
    }
}
