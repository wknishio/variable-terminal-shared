package org.vash.vate.org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;

public class MLKEMKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MLKEMParameters params;

    public MLKEMKeyGenerationParameters(
        SecureRandom random,
        MLKEMParameters mlkemParameters)
    {
        super(random, 256);
        this.params = mlkemParameters;
    }

    public MLKEMParameters getParameters()
    {
        return params;
    }
}
