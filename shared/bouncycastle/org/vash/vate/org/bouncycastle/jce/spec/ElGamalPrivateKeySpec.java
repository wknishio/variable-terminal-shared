package org.vash.vate.org.bouncycastle.jce.spec;

import java.math.BigInteger;

/**
 * This class specifies an ElGamal private key with its associated parameters.
 *
 * @see ElGamalPublicKeySpec
 */
public class ElGamalPrivateKeySpec
    extends ElGamalKeySpec
{
    private BigInteger  x;

    public ElGamalPrivateKeySpec(
        BigInteger              x,
        ElGamalParameterSpec    spec)
    {
        super(spec);

        this.x = x;
    }

    /**
     * Returns the private value  x</code>.
     *
     * @return the private value  x</code>
     */
    public BigInteger getX()
    {
        return x;
    }
}
