package org.vash.vate.org.bouncycastle.crypto.ec;

import org.vash.vate.org.bouncycastle.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
