package org.vash.vate.org.bouncycastle.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.vash.vate.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.vash.vate.org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * ContentSigner for "Unsigned X.509 Certificates"
 */
public class NoSignatureContentSigner
    implements ContentSigner
{
     
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(X509ObjectIdentifiers.id_alg_unsigned);
    }

     
    public OutputStream getOutputStream()
    {
        return new OutputStream()
        {
             
            public void write(byte[] buf, int off, int len)
                throws IOException
            {
                // do nothing
            }

             
            public void write(int i)
                throws IOException
            {
                // do nothing
            }
        };
    }

     
    public byte[] getSignature()
    {
        return new byte[0];
    }
}
