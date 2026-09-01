package org.vash.vate.org.bouncycastle.pkcs;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface PKCS12MacCalculatorBuilderProvider
{
    PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier);
}
