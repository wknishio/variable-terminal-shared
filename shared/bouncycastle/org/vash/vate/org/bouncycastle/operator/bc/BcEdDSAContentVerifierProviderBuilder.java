package org.vash.vate.org.bouncycastle.operator.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.crypto.signers.Ed25519Signer;
import org.vash.vate.org.bouncycastle.crypto.signers.Ed448Signer;
import org.vash.vate.org.bouncycastle.crypto.util.PublicKeyFactory;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public class BcEdDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    public static final byte[] DEFAULT_CONTEXT = new byte[0];

    public BcEdDSAContentVerifierProviderBuilder()
    {
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new Ed448Signer(DEFAULT_CONTEXT);
        }
        else
        {
            return new Ed25519Signer();
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}