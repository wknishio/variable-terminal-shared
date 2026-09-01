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

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    private final String name;
    ECDomainParameters  params;
    SecureRandom        random;

    public ECKeyPairGenerator()
    {
        this("ECKeyGen");
    }

    protected ECKeyPairGenerator(String name)
    {
        this.name = name;
    }

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(name, ConstraintUtils.bitsOfSecurityFor(this.params.getCurve()), ecP.getDomainParameters(), CryptoServicePurpose.KEYGEN));
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = BigIntegers.createRandomBigInteger(nBitLength, random);

            if (isOutOfRangeD(d, n))
            {
                continue;
            }

            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n) >= 0);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
