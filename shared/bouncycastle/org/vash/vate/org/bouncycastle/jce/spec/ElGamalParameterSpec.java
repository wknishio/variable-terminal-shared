package org.vash.vate.org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class ElGamalParameterSpec
    implements AlgorithmParameterSpec
{
    private BigInteger  p;
    private BigInteger  g;

    /**
     * Constructs a parameter set for Diffie-Hellman, using a prime modulus
     *  p</code> and a base generator  g</code>.
     * 
     * @param p the prime modulus
     * @param g the base generator
     */
    public ElGamalParameterSpec(
        BigInteger  p,
        BigInteger  g)
    {
        this.p = p;
        this.g = g;
    }

    /**
     * Returns the prime modulus  p</code>.
     *
     * @return the prime modulus  p</code>
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * Returns the base generator  g</code>.
     *
     * @return the base generator  g</code>
     */
    public BigInteger getG()
    {
        return g;
    }
}
