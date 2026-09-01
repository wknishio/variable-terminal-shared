package org.vash.vate.org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.vash.vate.org.bouncycastle.math.ec.ECConstants;
import org.vash.vate.org.bouncycastle.util.BigIntegers;

class ECUtil
{
    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k;
        do
        {
            k = BigIntegers.createRandomBigInteger(nBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));
        return k;
    }
}
