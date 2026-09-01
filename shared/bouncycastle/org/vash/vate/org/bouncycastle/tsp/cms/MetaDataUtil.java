package org.vash.vate.org.bouncycastle.tsp.cms;

import java.io.IOException;

import org.vash.vate.org.bouncycastle.asn1.ASN1Encoding;
import org.vash.vate.org.bouncycastle.asn1.ASN1String;
import org.vash.vate.org.bouncycastle.asn1.cms.Attributes;
import org.vash.vate.org.bouncycastle.asn1.cms.MetaData;
import org.vash.vate.org.bouncycastle.cms.CMSException;
import org.vash.vate.org.bouncycastle.operator.DigestCalculator;

class MetaDataUtil
{
    private final MetaData          metaData;

    MetaDataUtil(MetaData metaData)
    {
        this.metaData = metaData;
    }

    void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
        throws CMSException
    {
        if (metaData != null && metaData.isHashProtected())
        {
            try
            {
                calculator.getOutputStream().write(metaData.getEncoded(ASN1Encoding.DER));
            }
            catch (IOException e)
            {
                throw new CMSException("unable to initialise calculator from metaData: " + e.getMessage(), e);
            }
        }
    }

    String getFileName()
    {
        if (metaData != null)
        {
            return convertString(metaData.getFileNameUTF8());
        }

        return null;
    }

    String getMediaType()
    {
        if (metaData != null)
        {
            return convertString(metaData.getMediaTypeIA5());
        }

        return null;
    }

    Attributes getOtherMetaData()
    {
        if (metaData != null)
        {
            return metaData.getOtherMetaData();
        }

        return null;
    }

    private String convertString(ASN1String s)
    {
        if (s != null)
        {
            return s.toString();
        }

        return null;
    }
}
