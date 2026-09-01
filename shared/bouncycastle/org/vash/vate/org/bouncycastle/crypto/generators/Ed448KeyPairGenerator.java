package org.vash.vate.org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.Ed448PublicKeyParameters;

public class Ed448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("Ed448KeyGen", 224, null, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(random);
        Ed448PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
