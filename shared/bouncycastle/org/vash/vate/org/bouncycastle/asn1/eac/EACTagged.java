package org.vash.vate.org.bouncycastle.asn1.eac;

import org.vash.vate.org.bouncycastle.asn1.ASN1Sequence;
import org.vash.vate.org.bouncycastle.asn1.ASN1TaggedObject;
import org.vash.vate.org.bouncycastle.asn1.BERTags;
import org.vash.vate.org.bouncycastle.asn1.DEROctetString;
import org.vash.vate.org.bouncycastle.asn1.DERTaggedObject;

class EACTagged
{
    static ASN1TaggedObject create(int eacTag, ASN1Sequence seq)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, seq);
    }

    static ASN1TaggedObject create(int eacTag, PublicKeyDataObject key)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, key);
    }

    static ASN1TaggedObject create(int eacTag, byte[] octets)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, new DEROctetString(octets));
    }
}
