package org.vash.vate.org.bouncycastle.pqc.crypto.ntruprime;

import org.vash.vate.org.bouncycastle.util.Arrays;

public class SNTRUPrimePublicKeyParameters
    extends SNTRUPrimeKeyParameters
{
    private final byte[] encH;

    public SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters params, byte[] encH)
    {
        super(false, params);
        this.encH = Arrays.clone(encH);
    }

    byte[] getEncH()
    {
        return encH;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encH);
    }
}
