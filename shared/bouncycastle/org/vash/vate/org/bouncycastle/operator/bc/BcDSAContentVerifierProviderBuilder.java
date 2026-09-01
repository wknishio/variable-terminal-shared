package org.vash.vate.org.bouncycastle.operator.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.vash.vate.org.bouncycastle.crypto.Digest;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.crypto.signers.DSADigestSigner;
import org.vash.vate.org.bouncycastle.crypto.signers.DSASigner;
import org.vash.vate.org.bouncycastle.crypto.util.PublicKeyFactory;
import org.vash.vate.org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public class BcDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcDSAContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
    {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlg);

        return new DSADigestSigner(new DSASigner(), dig);
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}
