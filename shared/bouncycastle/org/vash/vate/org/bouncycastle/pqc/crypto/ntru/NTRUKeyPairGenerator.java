package org.vash.vate.org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.vash.vate.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;
import org.vash.vate.org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.vash.vate.org.bouncycastle.util.Arrays;

/**
 * Key generator for NTRU.
 * <p>
 * Note: the {@link #init(KeyGenerationParameters)} method only accepts {@link NTRUKeyParameters}. Otherwise, a
 * {@link ClassCastException} may occur.
 */
public class NTRUKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRUKeyGenerationParameters params;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.params = (NTRUKeyGenerationParameters)param;
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        NTRUParameters parameters = params.getParameters();
        NTRUParameterSet parameterSet = parameters.getParameterSet();

        byte[] seed = new byte[parameterSet.sampleFgBytes()];
        random.nextBytes(seed);

        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        OWCPAKeyPair owcpaKeys = owcpa.keypair(seed);

        byte[] publicKey = owcpaKeys.publicKey;

        byte[] prfBytes = new byte[parameterSet.prfKeyBytes()];
        random.nextBytes(prfBytes);
        byte[] privateKey = Arrays.concatenate(owcpaKeys.privateKey, prfBytes);

        return new AsymmetricCipherKeyPair(
            new NTRUPublicKeyParameters(parameters, publicKey),
            new NTRUPrivateKeyParameters(parameters, privateKey));
    }
}
