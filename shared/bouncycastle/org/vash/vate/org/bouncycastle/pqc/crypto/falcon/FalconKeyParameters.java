package org.vash.vate.org.bouncycastle.pqc.crypto.falcon;

import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class FalconKeyParameters
    extends AsymmetricKeyParameter
{

    private final FalconParameters params;

    public FalconKeyParameters(boolean isprivate, FalconParameters parameters)
    {
        super(isprivate);
        this.params = parameters;
    }

    public FalconParameters getParameters()
    {
        return params;
    }
}
