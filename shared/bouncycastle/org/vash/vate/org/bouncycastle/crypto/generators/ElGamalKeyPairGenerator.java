package org.vash.vate.org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.DHParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ElGamalParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ElGamalKeyGen", ConstraintUtils.bitsOfSecurityFor(this.param.getParameters().getP()), this.param.getParameters(), CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        ElGamalParameters egp = param.getParameters();
        DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());  

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new ElGamalPublicKeyParameters(y, egp),
            new ElGamalPrivateKeyParameters(x, egp));
    }
}
