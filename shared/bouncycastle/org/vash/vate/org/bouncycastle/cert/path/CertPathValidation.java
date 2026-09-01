package org.vash.vate.org.bouncycastle.cert.path;

import org.vash.vate.org.bouncycastle.cert.X509CertificateHolder;
import org.vash.vate.org.bouncycastle.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
