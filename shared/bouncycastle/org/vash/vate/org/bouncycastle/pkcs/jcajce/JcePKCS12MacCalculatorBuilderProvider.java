package org.vash.vate.org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import org.vash.vate.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.vash.vate.org.bouncycastle.asn1.DERNull;
import org.vash.vate.org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.jcajce.PKCS12Key;
import org.vash.vate.org.bouncycastle.jcajce.io.MacOutputStream;
import org.vash.vate.org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.vash.vate.org.bouncycastle.jcajce.util.JcaJceHelper;
import org.vash.vate.org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.vash.vate.org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.vash.vate.org.bouncycastle.operator.GenericKey;
import org.vash.vate.org.bouncycastle.operator.MacCalculator;
import org.vash.vate.org.bouncycastle.operator.OperatorCreationException;
import org.vash.vate.org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.vash.vate.org.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;

public class JcePKCS12MacCalculatorBuilderProvider
    implements PKCS12MacCalculatorBuilderProvider
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePKCS12MacCalculatorBuilderProvider()
    {
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PKCS12MacCalculatorBuilder get(final AlgorithmIdentifier algorithmIdentifier)
    {
        return new PKCS12MacCalculatorBuilder()
        {
            public MacCalculator build(final char[] password)
                throws OperatorCreationException
            {
                final PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                try
                {
                    final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                    final Mac mac = helper.createMac(algorithm.getId());

                    PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());

                    final SecretKey key = new PKCS12Key(password);

                    mac.init(key, defParams);

                    return new MacCalculator()
                    {
                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return new AlgorithmIdentifier(algorithm, pbeParams);
                        }

                        public OutputStream getOutputStream()
                        {
                            return new MacOutputStream(mac);
                        }

                        public byte[] getMac()
                        {
                            return mac.doFinal();
                        }

                        public GenericKey getKey()
                        {
                            return new GenericKey(getAlgorithmIdentifier(), key.getEncoded());
                        }
                    };
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create MAC calculator: " + e.getMessage(), e);
                }
            }

            public AlgorithmIdentifier getDigestAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
            }
        };
    }
}
