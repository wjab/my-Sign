using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirmaSimple
{
    public class Enum
    {
    }

    public enum SignMethod
    {
        RSAwithSHA1,
        RSAwithSHA256
    }

    public enum DigestMethod
    {
        SHA1,
        SHA256
    }

    /// <summary>
    /// Types of signature standards that can be contained in XadesSignedXml class instance
    /// </summary>
    public enum KnownSignatureStandard
    {
        /// <summary>
        /// XML Digital Signature (XMLDSIG)
        /// </summary>
        XmlDsig,
        /// <summary>
        /// XML Advanced Electronic Signature (XAdES) 
        /// </summary>
        Xades
    }

}
