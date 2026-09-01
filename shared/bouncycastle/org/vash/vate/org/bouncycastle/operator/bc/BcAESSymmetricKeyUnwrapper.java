package org.vash.vate.org.bouncycastle.operator.bc;

import org.vash.vate.org.bouncycastle.crypto.engines.AESWrapEngine;
import org.vash.vate.org.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyUnwrapper
    extends BcSymmetricKeyUnwrapper
{
    public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
