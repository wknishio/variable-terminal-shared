package org.vash.vate.org.bouncycastle.crypto.agreement;

import org.vash.vate.org.bouncycastle.crypto.CryptoServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.DHKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ECKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.X448PrivateKeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, DHKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, X448PrivateKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, 224, k, CryptoServicePurpose.AGREEMENT);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, X25519PrivateKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, 128, k, CryptoServicePurpose.AGREEMENT);
    }
}
