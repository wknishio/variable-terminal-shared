package org.vash.vate.org.bouncycastle.tls.crypto.impl.bc;

class Exceptions
{
    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new org.vash.vate.org.bouncycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
