package org.vash.vate.org.bouncycastle.operator;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface PBEMacCalculatorProvider
{
    MacCalculator get(AlgorithmIdentifier algorithm, char[] password)
        throws OperatorCreationException;
}
