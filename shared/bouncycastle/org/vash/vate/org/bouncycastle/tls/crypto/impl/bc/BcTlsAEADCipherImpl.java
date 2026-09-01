package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.crypto.InvalidCipherTextException;
import org.vash.vate.org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.vash.vate.org.bouncycastle.crypto.params.AEADParameters;
import org.vash.vate.org.bouncycastle.crypto.params.KeyParameter;
import org.vash.vate.org.bouncycastle.tls.AlertDescription;
import org.vash.vate.org.bouncycastle.tls.TlsFatalAlert;
import org.vash.vate.org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.vash.vate.org.bouncycastle.util.Arrays;

final class BcTlsAEADCipherImpl
    implements TlsAEADCipherImpl
{
    private final boolean isEncrypting;
    private final AEADBlockCipher cipher;

    private KeyParameter key;

    BcTlsAEADCipherImpl(AEADBlockCipher cipher, boolean isEncrypting)
    {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void init(byte[] nonce, int macSize)
    {
        cipher.init(isEncrypting, new AEADParameters(key, macSize * 8, nonce, null));
    }

    public int getOutputSize(int inputLength)
    {
        return cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] additionalData, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        throws IOException
    {
        if (!Arrays.isNullOrEmpty(additionalData))
        {
            cipher.processAADBytes(additionalData, 0, additionalData.length);
        }

        int len = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);

        try
        {
            len += cipher.doFinal(output, outputOffset + len);
        }
        catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        return len;
    }
}
