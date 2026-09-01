package org.vash.vate.org.bouncycastle.pqc.crypto.sphincsplus;

import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SPHINCSPlusKeyParameters
    extends AsymmetricKeyParameter
{
    final SPHINCSPlusParameters parameters;

    protected SPHINCSPlusKeyParameters(boolean isPrivate, SPHINCSPlusParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }

    public SPHINCSPlusParameters getParameters()
    {
        return parameters;
    }
}
