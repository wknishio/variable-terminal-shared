package org.vash.vate.org.bouncycastle.pkcs;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.operator.MacCalculator;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password)
        throws OperatorCreationException;

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}
