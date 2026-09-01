package org.vash.vate.org.bouncycastle.cert;

import org.vash.vate.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.vash.vate.org.bouncycastle.operator.ContentVerifierProvider;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder
{
    ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
        throws OperatorCreationException;

    ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
        throws OperatorCreationException;
}
