package org.vash.vate.org.bouncycastle.operator;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KeyWrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException;
}
