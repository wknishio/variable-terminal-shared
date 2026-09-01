package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import org.vash.vate.org.bouncycastle.crypto.Digest;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.digests.NullDigest;
import org.vash.vate.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.vash.vate.org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.vash.vate.org.bouncycastle.crypto.params.RSAKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.GenericSigner;
import org.vash.vate.org.bouncycastle.crypto.signers.RSADigestSigner;
import org.vash.vate.org.bouncycastle.tls.DigitallySigned;
import org.vash.vate.org.bouncycastle.tls.SignatureAlgorithm;
import org.vash.vate.org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.vash.vate.org.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the verification of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSAVerifier
    extends BcTlsVerifier
{
    public BcTlsRSAVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
    {
        Digest nullDigest = new NullDigest();

        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        Signer signer;
        if (algorithm != null)
        {
            if (algorithm.getSignature() != SignatureAlgorithm.rsa)
            {
                throw new IllegalStateException("Invalid algorithm: " + algorithm);
            }

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            signer = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        }
        signer.init(false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(digitallySigned.getSignature());
    }
}
