package org.vash.vate.org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.crypto.KeyGenerationParameters;

public class XWingKeyGenerationParameters
    extends KeyGenerationParameters
{
    public XWingKeyGenerationParameters(SecureRandom random)
    {
        super(random, 128);
    }
}
