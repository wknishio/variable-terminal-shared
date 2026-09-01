package org.vash.vate.org.bouncycastle.operator.bc;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.crypto.ExtendedDigest;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public interface BcDigestProvider
{
    ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException;
}
