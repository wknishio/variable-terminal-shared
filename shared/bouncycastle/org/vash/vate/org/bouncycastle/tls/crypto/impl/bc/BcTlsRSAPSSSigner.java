package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.crypto.CryptoException;
import org.vash.vate.org.bouncycastle.crypto.Digest;
import org.vash.vate.org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.vash.vate.org.bouncycastle.crypto.params.ParametersWithRandom;
import org.vash.vate.org.bouncycastle.crypto.params.RSAKeyParameters;
import org.vash.vate.org.bouncycastle.crypto.signers.PSSSigner;
import org.vash.vate.org.bouncycastle.tls.AlertDescription;
import org.vash.vate.org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.vash.vate.org.bouncycastle.tls.SignatureScheme;
import org.vash.vate.org.bouncycastle.tls.TlsFatalAlert;

/**
 * Operator supporting the generation of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSSigner
    extends BcTlsSigner
{
    private final int signatureScheme;

    public BcTlsRSAPSSSigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        Digest digest = crypto.createDigest(cryptoHashAlgorithm);

        PSSSigner signer = PSSSigner.createRawSigner(new RSABlindedEngine(), digest);
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
