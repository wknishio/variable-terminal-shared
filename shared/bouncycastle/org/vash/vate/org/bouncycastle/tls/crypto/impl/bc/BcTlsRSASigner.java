package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.crypto.CryptoException;
import org.vash.vate.org.bouncycastle.crypto.Digest;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.digests.NullDigest;
import org.vash.vate.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.vash.vate.org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.vash.vate.org.bouncycastle.crypto.params.ParametersWithRandom;
import org.vash.vate.org.bouncycastle.crypto.params.RSAKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.GenericSigner;
import org.vash.vate.org.bouncycastle.crypto.signers.RSADigestSigner;
import org.vash.vate.org.bouncycastle.tls.AlertDescription;
import org.vash.vate.org.bouncycastle.tls.SignatureAlgorithm;
import org.vash.vate.org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.vash.vate.org.bouncycastle.tls.TlsFatalAlert;
import org.vash.vate.org.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSASigner
    extends BcTlsSigner
{
    /**
     * @deprecated Use constructor without 'publicKey' parameter.
     */
    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, RSAKeyParameters publicKey)
    {
        this(crypto, privateKey);
    }

    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        Digest nullDigest = new NullDigest();

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
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
