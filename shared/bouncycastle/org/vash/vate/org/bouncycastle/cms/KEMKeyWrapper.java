package org.vash.vate.org.bouncycastle.cms;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.operator.AsymmetricKeyWrapper;

public abstract class KEMKeyWrapper
    extends AsymmetricKeyWrapper
{
    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        super(algorithmId);
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();
}
