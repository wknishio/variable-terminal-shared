package org.vash.vate.org.bouncycastle.jcajce.provider.symmetric.util;

import org.vash.vate.org.bouncycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
