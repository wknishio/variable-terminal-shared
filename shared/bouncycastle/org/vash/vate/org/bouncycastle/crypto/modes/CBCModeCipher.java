package org.vash.vate.org.bouncycastle.crypto.modes;

import org.vash.vate.org.bouncycastle.crypto.BlockCipher;
import org.vash.vate.org.bouncycastle.crypto.MultiBlockCipher;

public interface CBCModeCipher
    extends MultiBlockCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
