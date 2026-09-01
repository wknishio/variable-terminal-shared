package org.vash.vate.org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.vash.vate.org.bouncycastle.crypto.BasicAgreement;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.RawAgreement;
import org.vash.vate.org.bouncycastle.util.BigIntegers;

public final class BasicRawAgreement
    implements RawAgreement
{
    public final BasicAgreement basicAgreement;

    public BasicRawAgreement(BasicAgreement basicAgreement)
    {
        if (basicAgreement == null)
        {
            throw new NullPointerException("'basicAgreement' cannot be null");
        }

        this.basicAgreement = basicAgreement;
    }

    public void init(CipherParameters parameters)
    {
        basicAgreement.init(parameters);
    }

    public int getAgreementSize()
    {
        return basicAgreement.getFieldSize();
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        BigInteger z = basicAgreement.calculateAgreement(publicKey);
        BigIntegers.asUnsignedByteArray(z, buf, off, getAgreementSize());
    }
}
