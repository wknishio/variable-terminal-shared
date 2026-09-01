package org.vash.vate.org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.ECDomainParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.vash.vate.org.bouncycastle.math.ec.ECConstants;
import org.vash.vate.org.bouncycastle.math.ec.ECMultiplier;
import org.vash.vate.org.bouncycastle.math.ec.ECPoint;
import org.vash.vate.org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.vash.vate.org.bouncycastle.math.ec.WNafUtil;
import org.vash.vate.org.bouncycastle.util.BigIntegers;

public class SM2KeyPairGenerator
    extends ECKeyPairGenerator
{
    public SM2KeyPairGenerator()
    {
        super("SM2KeyGen");
    }

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n.subtract(BigIntegers.ONE)) >= 0);
    }
}
