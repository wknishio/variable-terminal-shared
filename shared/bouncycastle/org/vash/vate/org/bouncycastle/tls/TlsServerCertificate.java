package org.vash.vate.org.bouncycastle.tls;

/**
 * Server certificate carrier interface.
 */
public interface TlsServerCertificate
{
    Certificate getCertificate();

    CertificateStatus getCertificateStatus();
}
