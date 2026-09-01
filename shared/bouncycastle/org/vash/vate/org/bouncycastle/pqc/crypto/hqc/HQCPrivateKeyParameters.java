package org.vash.vate.org.bouncycastle.pqc.crypto.hqc;

import org.vash.vate.org.bouncycastle.util.Arrays;

public class HQCPrivateKeyParameters
    extends HQCKeyParameters
{
    private final byte[] sk;

    public HQCPrivateKeyParameters(HQCParameters params, byte[] sk)
    {
        super(true, params);
        this.sk = Arrays.clone(sk);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(this.sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(this.sk);
    }
}
