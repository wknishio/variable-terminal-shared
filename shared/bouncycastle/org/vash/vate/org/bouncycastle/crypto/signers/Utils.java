package org.vash.vate.org.bouncycastle.crypto.signers;

import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.CryptoServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.CryptoServicePurpose;
import org.vash.vate.org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.vash.vate.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.vash.vate.org.bouncycastle.crypto.params.DSAKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.ECKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.params.GOST3410KeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, DSAKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, GOST3410KeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, CipherParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, k, getPurpose(forSigning));
    }

    static CryptoServicePurpose getPurpose(boolean forSigning)
    {
        return forSigning ? CryptoServicePurpose.SIGNING : CryptoServicePurpose.VERIFYING;
    }
}
