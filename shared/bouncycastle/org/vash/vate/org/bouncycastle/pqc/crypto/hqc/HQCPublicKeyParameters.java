package org.vash.vate.org.bouncycastle.pqc.crypto.hqc;

import org.vash.vate.org.bouncycastle.util.Arrays;

public class HQCPublicKeyParameters
    extends HQCKeyParameters
{
    private final byte[] pk;

    public HQCPublicKeyParameters(HQCParameters params, byte[] pk)
    {
        super(true, params);
        this.pk = Arrays.clone(pk);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
