package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.cert.X509CertificateHolder;
import org.vash.vate.org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.vash.vate.org.bouncycastle.cms.SignerInformationVerifier;
import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.vash.vate.org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.vash.vate.org.bouncycastle.operator.DigestCalculatorProvider;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;
import org.vash.vate.org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.vash.vate.org.bouncycastle.operator.bc.BcEdDSAContentVerifierProviderBuilder;

public class BcEdDSASignerInfoVerifierBuilder
{
    private BcEdDSAContentVerifierProviderBuilder contentVerifierProviderBuilder;
    private DigestCalculatorProvider digestCalculatorProvider;
    private CMSSignatureAlgorithmNameGenerator sigAlgNameGen;
    private SignatureAlgorithmIdentifierFinder sigAlgIdFinder;

    public BcEdDSASignerInfoVerifierBuilder(CMSSignatureAlgorithmNameGenerator sigAlgNameGen, SignatureAlgorithmIdentifierFinder sigAlgIdFinder, DigestAlgorithmIdentifierFinder digestAlgorithmFinder, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.sigAlgNameGen = sigAlgNameGen;
        this.sigAlgIdFinder = sigAlgIdFinder;
        this.contentVerifierProviderBuilder = new BcEdDSAContentVerifierProviderBuilder();
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public SignerInformationVerifier build(X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(certHolder), digestCalculatorProvider);
    }

    public SignerInformationVerifier build(AsymmetricKeyParameter pubKey)
        throws OperatorCreationException
    {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(pubKey), digestCalculatorProvider);
    }
}
