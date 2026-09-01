package org.vash.vate.org.bouncycastle.operator.bc;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.InvalidCipherTextException;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.crypto.params.ParametersWithRandom;
import org.vash.vate.org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.vash.vate.org.bouncycastle.operator.GenericKey;
import org.vash.vate.org.bouncycastle.operator.OperatorException;

public abstract class BcAsymmetricKeyWrapper
    extends AsymmetricKeyWrapper
{
    private AsymmetricKeyParameter publicKey;
    private SecureRandom random;

    public BcAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(encAlgId);

        this.publicKey = publicKey;
    }

    public BcAsymmetricKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        AsymmetricBlockCipher keyEncryptionCipher = createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm());
        
        CipherParameters params = publicKey;
        if (random != null)
        {
            params = new ParametersWithRandom(params, random);
        }

        try
        {
            byte[] keyEnc = OperatorUtils.getKeyBytes(encryptionKey);
            keyEncryptionCipher.init(true, params);
            return keyEncryptionCipher.processBlock(keyEnc, 0, keyEnc.length);
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to encrypt contents key", e);
        }
    }

    protected abstract AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm);
}
