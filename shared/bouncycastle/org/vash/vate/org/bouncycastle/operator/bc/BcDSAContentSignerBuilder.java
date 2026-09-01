package org.vash.vate.org.bouncycastle.operator.bc;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.crypto.Digest;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.signers.DSADigestSigner;
import org.vash.vate.org.bouncycastle.crypto.signers.DSASigner;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public class BcDSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcDSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new DSASigner(), dig);
    }
}
