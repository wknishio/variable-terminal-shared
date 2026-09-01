package org.vash.vate.org.bouncycastle.tsp.cms;

import org.vash.vate.org.bouncycastle.tsp.TimeStampToken;

public class ImprintDigestInvalidException
    extends Exception
{
    private TimeStampToken token;

    public ImprintDigestInvalidException(String message, TimeStampToken token)
    {
        super(message);

        this.token = token;
    }

    public TimeStampToken getTimeStampToken()
    {
        return token;
    }
}
