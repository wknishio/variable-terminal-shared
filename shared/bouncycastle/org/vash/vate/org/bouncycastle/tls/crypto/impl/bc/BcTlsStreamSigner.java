package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.vash.vate.org.bouncycastle.crypto.CryptoException;
import org.vash.vate.org.bouncycastle.crypto.Signer;
import org.vash.vate.org.bouncycastle.crypto.io.SignerOutputStream;
import org.vash.vate.org.bouncycastle.tls.AlertDescription;
import org.vash.vate.org.bouncycastle.tls.TlsFatalAlert;
import org.vash.vate.org.bouncycastle.tls.crypto.TlsStreamSigner;

class BcTlsStreamSigner
    implements TlsStreamSigner
{
    private final SignerOutputStream output;

    BcTlsStreamSigner(Signer signer)
    {
        this.output = new SignerOutputStream(signer);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return output.getSigner().generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
