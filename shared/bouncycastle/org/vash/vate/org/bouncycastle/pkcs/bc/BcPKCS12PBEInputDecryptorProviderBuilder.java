package org.vash.vate.org.bouncycastle.pkcs.bc;

import java.io.InputStream;

import org.vash.vate.org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.crypto.CipherParameters;
import org.vash.vate.org.bouncycastle.crypto.ExtendedDigest;
import org.vash.vate.org.bouncycastle.crypto.digests.SHA1Digest;
import org.vash.vate.org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.vash.vate.org.bouncycastle.crypto.io.CipherInputStream;
import org.vash.vate.org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.vash.vate.org.bouncycastle.operator.GenericKey;
import org.vash.vate.org.bouncycastle.operator.InputDecryptor;
import org.vash.vate.org.bouncycastle.operator.InputDecryptorProvider;

public class BcPKCS12PBEInputDecryptorProviderBuilder
{
    private ExtendedDigest digest;

    public BcPKCS12PBEInputDecryptorProviderBuilder()
    {
         this(new SHA1Digest());
    }

    public BcPKCS12PBEInputDecryptorProviderBuilder(ExtendedDigest digest)
    {
         this.digest = digest;
    }

    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
            {
                final PaddedBufferedBlockCipher engine = PKCS12PBEUtils.getEngine(algorithmIdentifier.getAlgorithm());

                PKCS12PBEParams           pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithmIdentifier.getAlgorithm(), digest, engine.getBlockSize(), pbeParams, password);

                engine.init(false, params);

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return algorithmIdentifier;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, engine);
                    }

                    public GenericKey getKey()
                    {
                        return new GenericKey(algorithmIdentifier, PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
                    }
                };
            }
        };

    }
}
