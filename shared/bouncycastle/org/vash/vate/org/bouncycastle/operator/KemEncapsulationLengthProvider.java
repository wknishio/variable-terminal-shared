package org.vash.vate.org.bouncycastle.operator;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KemEncapsulationLengthProvider
{
    int getEncapsulationLength(AlgorithmIdentifier kemAlgorithm);
}
