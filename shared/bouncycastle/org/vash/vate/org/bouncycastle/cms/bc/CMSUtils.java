package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.params.KeyParameter;
import org.vash.vate.org.bouncycastle.operator.GenericKey;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
