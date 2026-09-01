package org.vash.vate.org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class X25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("X25519KeyGen", 128, null, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
