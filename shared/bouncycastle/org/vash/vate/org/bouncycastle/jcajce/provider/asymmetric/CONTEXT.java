package org.vash.vate.org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.vash.vate.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.vash.vate.org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.vash.vate.org.bouncycastle.jcajce.spec.ContextParameterSpec;

public class CONTEXT
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".CONTEXT$";

    public static class ContextAlgorithmParametersSpi
        extends java.security.AlgorithmParametersSpi
    {
        private ContextParameterSpec contextParameterSpec;

        protected boolean isASN1FormatString(String format)
        {
            return format == null || format.equals("ASN.1");
        }

        protected AlgorithmParameterSpec engineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == null)
            {
                throw new NullPointerException("argument to getParameterSpec must not be null");
            }
            if (paramSpec != ContextParameterSpec.class)
            {
                throw new IllegalArgumentException("argument to getParameterSpec must be ContextParameterSpec.class");
            }

            return contextParameterSpec;
        }

         
        protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException
        {
            if (!(algorithmParameterSpec instanceof ContextParameterSpec))
            {
                throw new IllegalArgumentException("argument to engineInit must be a ContextParameterSpec");
            }

            this.contextParameterSpec = (ContextParameterSpec)algorithmParameterSpec;
        }

         
        protected void engineInit(byte[] bytes)
            throws IOException
        {
            throw new IllegalStateException("not implemented");
        }

         
        protected void engineInit(byte[] bytes, String s)
            throws IOException
        {
            throw new IllegalStateException("not implemented");
        }

         
        protected byte[] engineGetEncoded()
            throws IOException
        {
            throw new IllegalStateException("not implemented");
        }

         
        protected byte[] engineGetEncoded(String s)
            throws IOException
        {
            throw new IllegalStateException("not implemented");
        }

         
        protected String engineToString()
        {
            return "ContextParameterSpec";
        }
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.CONTEXT", PREFIX + "ContextAlgorithmParametersSpi");
        }
    }
}
