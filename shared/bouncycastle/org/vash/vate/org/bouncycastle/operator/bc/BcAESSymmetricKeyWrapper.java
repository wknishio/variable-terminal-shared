package org.vash.vate.org.bouncycastle.operator.bc;

import org.vash.vate.org.bouncycastle.crypto.engines.AESWrapEngine;
import org.vash.vate.org.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyWrapper
    extends BcSymmetricKeyWrapper
{
    public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
