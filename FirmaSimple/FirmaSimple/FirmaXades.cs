using Microsoft.Xades;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Schema;

namespace FirmaSimple
{
    public class FirmaXades : IDisposable
    {
        private List<Org.BouncyCastle.X509.X509Crl> _crls;
        private string _signMethodUri;
        private string _refsMethodUri;

        private SignMethod _signMethod;
        private DigestMethod _refsDigestMethod;

        private bool _disposeCryptoProvider;
        private RSACryptoServiceProvider _rsaKey;

        private X509Certificate2 _signCertificate;

        private XmlDocument _document;
        private XadesSignedXml _xadesSignedXml;

        private string _policyHash;
        private string _policyId;
        private string _objectReference;
        private string _signatureId;
        private string _policyUri;
        private string _mimeType;
        private string _signatureValueId;
        private string id;

        #region Constants
        public const string SHA1Uri = "http://www.w3.org/2000/09/xmldsig#sha1";
        public const string SHA256Uri = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string RSAwithSHA1Uri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        public const string RSAwithSHA256Uri = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        #endregion



        #region Constructors
        public FirmaXades()
        {
            id = Guid.NewGuid().ToString("N");
            this.SignMethod = SignMethod.RSAwithSHA256;
            this.RefsDigestMethod = DigestMethod.SHA256;

            _crls = new List<Org.BouncyCastle.X509.X509Crl>();
        }

        #endregion

        /// <summary>
        /// Tipo de algoritmo para la huella de la firma
        /// </summary>
        public SignMethod SignMethod
        {
            get
            {
                return _signMethod;
            }
            set
            {
                _signMethod = value;

                switch (_signMethod)
                {
                    case SignMethod.RSAwithSHA1:
                        _signMethodUri = RSAwithSHA1Uri; ;
                        break;

                    case SignMethod.RSAwithSHA256:
                        _signMethodUri = RSAwithSHA256Uri;
                        break;
                }
            }
        }

        /// <summary>
        /// Tipo de algoritmo para la huella de las referencias
        /// </summary>
        public DigestMethod RefsDigestMethod
        {
            get
            {
                return _refsDigestMethod;
            }

            set
            {
                _refsDigestMethod = value;

                switch (_refsDigestMethod)
                {
                    case DigestMethod.SHA1:
                        _refsMethodUri = SHA1Uri;
                        break;

                    case DigestMethod.SHA256:
                        _refsMethodUri = SHA256Uri;
                        break;
                }
            }
        }

        public void Dispose()
        {
            if (_disposeCryptoProvider && _rsaKey != null)
            {
                _rsaKey.Clear();
            }
        }

        /// <summary>
        /// Establece el identificador de la política de firma
        /// </summary>
        public string PolicyIdentifier
        {
            get
            {
                return _policyId;
            }

            set
            {
                _policyId = value;
            }
        }

        /// <summary>
        /// Establece la huella en base 64 de la politica de firma
        /// </summary>
        public string PolicyHash
        {
            get
            {
                return _policyHash;
            }
            set
            {
                _policyHash = value;
            }
        }

        /// <summary>
        /// Inserta un documento XML para generar una firma enveloped.
        /// </summary>
        /// <param name="fileName"></param>
        public void SetContentEnveloped(XmlDocument document)
        {
            _document = new XmlDocument();
            //_document.PreserveWhitespace = true;
            //_document.Load(fileName);
            _document = document;

            CreateEnvelopedDocument();
        }

        /// <summary>
        /// Construye el documento enveloped
        /// </summary>
        private void CreateEnvelopedDocument()
        {
            Reference reference = new Reference();

            _xadesSignedXml = new XadesSignedXml(_document);

            reference.DigestMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            reference.Id = "r-id-1";
            reference.Uri = "";
            reference.Type = "";

            //for (int i = 0; i < _document.DocumentElement.Attributes.Count; i++)
            //{
            //    if (_document.DocumentElement.Attributes[i].Name.Equals("id", StringComparison.InvariantCultureIgnoreCase))
            //    {
            //        reference.Uri = "#" + _document.DocumentElement.Attributes[i].Value;
            //        break;
            //    }
            //}

            XmlDsigEnvelopedSignatureTransform xmlDsigEnvelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
            //xmlDsigEnvelopedSignatureTransform.Algorithm = "http://www.w3.org/TR/1999/REC-xpath-19991116";

            //XmlDocument doc = new XmlDocument();
            //XmlElement xpathElem = doc.CreateElement("XPath");
            //xpathElem.InnerText = "not(ancestor-or-self::ds:Signature)";
            //XmlDsigXPathTransform xform = new XmlDsigXPathTransform();
            //xform.LoadInnerXml(xpathElem.SelectNodes("."));

            //reference.AddTransform(xform);

            reference.AddTransform(xmlDsigEnvelopedSignatureTransform);

            _objectReference = reference.Id;

            _xadesSignedXml.AddReference(reference);
        }

        /// <summary>
        /// Realiza el proceso de firmado
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="signMethod"></param>
        public void Sign(X509Certificate2 certificate, SignMethod? signMethod = null)
        {
            if (certificate == null)
            {
                throw new Exception("Es necesario un certificado válido para la firma.");
            }

            if (signMethod.HasValue)
            {
                this.SignMethod = signMethod.Value;
            }

            if (!string.IsNullOrEmpty(_signatureId) && _document != null &&
                _document.SelectSingleNode("//*[@Id='" + _signatureId + "']") != null)
            {
                throw new Exception("El documento ya ha sido firmado, debe seleccionar otro método de firma.");
            }

            if (string.IsNullOrEmpty(_signatureId))
            {
                SetSignatureId();
            }

            _signCertificate = certificate;

            AddCertificateInfo();
            AddXadesInfo();

            foreach (Reference reference in _xadesSignedXml.SignedInfo.References)
            {
                reference.DigestMethod = _refsMethodUri;
            }

            _xadesSignedXml.SignedInfo.SignatureMethod = _signMethodUri;

            ComputeSignature();

            UpdateDocument();

            XmlNode xmlNode = _document.SelectSingleNode("//*[@Id='" + _signatureId + "']");
            _xadesSignedXml = new XadesSignedXml(_document);
            _xadesSignedXml.LoadXml((XmlElement)xmlNode);
        }

        private void AddCertificateInfo()
        {
            SetCryptoServiceProvider();

            _xadesSignedXml.SigningKey = _rsaKey;

            KeyInfo keyInfo = new KeyInfo();
            //keyInfo.Id = "KeyInfoId-" + _signatureId;
            keyInfo.AddClause(new KeyInfoX509Data((X509Certificate)_signCertificate));
            //keyInfo.AddClause(new RSAKeyValue((RSA)_rsaKey));

            _xadesSignedXml.KeyInfo = keyInfo;

            /*Reference reference = new Reference();

            reference.Id = "";// "ReferenceKeyInfo";
            reference.Uri = "#KeyInfoId-" + _signatureId;

            _xadesSignedXml.AddReference(reference);*/
        }

        private void SetCryptoServiceProvider()
        {
            string providerName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
            int providerType = 24;

            var key = (RSACryptoServiceProvider)_signCertificate.PrivateKey;

            if (_rsaKey != null &&
                key.CspKeyContainerInfo.UniqueKeyContainerName == _rsaKey.CspKeyContainerInfo.UniqueKeyContainerName)
            {
                return;
            }
            else if (_rsaKey != null && _disposeCryptoProvider)
            {
                _rsaKey.Clear();
            }


            if (key.CspKeyContainerInfo.ProviderName == "Microsoft Strong Cryptographic Provider" ||
                key.CspKeyContainerInfo.ProviderName == "Microsoft Enhanced Cryptographic Provider v1.0" ||
                key.CspKeyContainerInfo.ProviderName == "Microsoft Base Cryptographic Provider v1.0")
            {
                Type CspKeyContainerInfo_Type = typeof(CspKeyContainerInfo);

                FieldInfo CspKeyContainerInfo_m_parameters = CspKeyContainerInfo_Type.GetField("m_parameters", BindingFlags.NonPublic | BindingFlags.Instance);
                CspParameters parameters = (CspParameters)CspKeyContainerInfo_m_parameters.GetValue(key.CspKeyContainerInfo);

                var cspparams = new CspParameters(providerType, providerName, key.CspKeyContainerInfo.KeyContainerName);
                cspparams.Flags = parameters.Flags;
                _rsaKey = new RSACryptoServiceProvider(cspparams);

                _disposeCryptoProvider = true;
            }
            else
            {
                _rsaKey = key;
                _disposeCryptoProvider = false;
            }
        }
        
        private void AddXadesInfo()
        {
            _xadesSignedXml.Signature.Id = _signatureId;
            XadesObject xadesObject = new XadesObject();
            //xadesObject.Id = "XadesObjectId-" + Guid.NewGuid().ToString();
            //xadesObject.QualifyingProperties.Id = "QualifyingProperties-" + Guid.NewGuid().ToString();
            xadesObject.QualifyingProperties.Target = "#id" + id; // _signatureId
            xadesObject.QualifyingProperties.SignedProperties.Id = "xades-id-" + id; //SignedProperties-   // _signatureId

            AddSignatureProperties(
                xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties,
                xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties,
                xadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties,
                _mimeType, _signCertificate);

            _xadesSignedXml.AddXadesObject(xadesObject);
        }


        private void AddSignatureProperties(SignedSignatureProperties signedSignatureProperties, SignedDataObjectProperties signedDataObjectProperties,
                   UnsignedSignatureProperties unsignedSignatureProperties, string mimeType, X509Certificate2 certificado)
        {
            Cert cert;

            cert = new Cert();
            cert.IssuerSerial.X509IssuerName = certificado.IssuerName.Name;
            cert.IssuerSerial.X509SerialNumber = HexToDecimal(certificado.SerialNumber);
            SetCertDigest(_signCertificate.GetRawCertData(), _refsMethodUri, cert.CertDigest); 
            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);

            if (!string.IsNullOrEmpty(_policyId))
            {
                signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = false;
                signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyId.Identifier.IdentifierUri = _policyId;
                //signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyId.Identifier.di
            }

            if (!string.IsNullOrEmpty(_policyUri))
            {
                SigPolicyQualifier spq = new SigPolicyQualifier();
                spq.AnyXmlElement = _document.CreateElement("Identifier"); // "SPURI", XadesSignedXml.XadesNamespaceUri
                spq.AnyXmlElement.InnerText = _policyUri;

                signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyQualifiers.SigPolicyQualifierCollection.Add(spq);
            }

            if (!string.IsNullOrEmpty(_policyHash))
            {
                signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestMethod.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
                signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestValue = Convert.FromBase64String(PolicyHash);
            }

            signedSignatureProperties.SigningTime = Convert.ToDateTime( DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:ssZ"));

            if (!string.IsNullOrEmpty(mimeType))
            {
                DataObjectFormat newDataObjectFormat = new DataObjectFormat();

                newDataObjectFormat.MimeType = mimeType;
                newDataObjectFormat.ObjectReferenceAttribute = "#" + _objectReference;

                signedDataObjectProperties.DataObjectFormatCollection.Add(newDataObjectFormat);
            }

        }

        public static void SetCertDigest(byte[] rawCert, string digestAlgorithm, DigestAlgAndValueType destination)
        {
            using (var hashAlg = GetHashAlg(digestAlgorithm))
            {
                destination.DigestMethod.Algorithm = digestAlgorithm;
                destination.DigestValue = hashAlg.ComputeHash(rawCert);
            }
        }

        public static HashAlgorithm GetHashAlg(string digestAlgorithm)
        {
            if (digestAlgorithm == FirmaXades.SHA1Uri)
            {
                return SHA1.Create();
            }
            else if (digestAlgorithm == FirmaXades.SHA256Uri)
            {
                return SHA256.Create();
            }
            else
            {
                throw new Exception("Algoritmo no soportado");
            }
        }

        public static string HexToDecimal(string hex)
        {
            List<int> dec = new List<int> { 0 };

            foreach (char c in hex)
            {
                int carry = Convert.ToInt32(c.ToString(), 16);

                for (int i = 0; i < dec.Count; ++i)
                {
                    int val = dec[i] * 16 + carry;
                    dec[i] = val % 10;
                    carry = val / 10;
                }

                while (carry > 0)
                {
                    dec.Add(carry % 10);
                    carry /= 10;
                }
            }

            var chars = dec.Select(d => (char)('0' + d));
            var cArr = chars.Reverse().ToArray();
            return new string(cArr);
        }

        /// <summary>
        /// Establece el identificador para la firma
        /// </summary>
        private void SetSignatureId()
        {
            //string id = Guid.NewGuid().ToString("N");

            _signatureId = "Id-" + id;
            _signatureValueId = "value-id" + id;
        }

        private void ComputeSignature()
        {
            try
            {
                _xadesSignedXml.ComputeSignature();
                _xadesSignedXml.SignatureValueId = _signatureValueId;
            }
            catch (Exception exception)
            {
               throw new Exception("Ha ocurrido durante el proceso de firmado: " + exception.Message);
            }
        }

        /// <summary>
        /// Actualiza el documento resultante
        /// </summary>
        internal void UpdateDocument()
        {
            if (_document == null)
            {
                _document = new XmlDocument();
            }

            if (_document.DocumentElement != null)
            {
                XmlNode xmlNode = _document.SelectSingleNode("//*[@Id='" + _xadesSignedXml.Signature.Id + "']");

                if (xmlNode != null)
                {

                    XmlNamespaceManager nm = new XmlNamespaceManager(_document.NameTable);
                    nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
                    nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

                    XmlNode xmlQPNode = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties", nm);
                    XmlNode xmlUnsingedPropertiesNode = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", nm);

                    if (xmlUnsingedPropertiesNode != null)
                    {
                        xmlUnsingedPropertiesNode.InnerXml = _xadesSignedXml.XadesObject.QualifyingProperties.UnsignedProperties.GetXml().InnerXml;
                    }
                    else
                    {
                        xmlUnsingedPropertiesNode = _document.ImportNode(_xadesSignedXml.XadesObject.QualifyingProperties.UnsignedProperties.GetXml(), true);
                        xmlQPNode.AppendChild(xmlUnsingedPropertiesNode);
                    }

                }
                else
                {
                    XmlElement xmlSigned = _xadesSignedXml.GetXml();

                    byte[] canonicalizedElement = ApplyTransform(xmlSigned, new XmlDsigC14NTransform());

                    XmlDocument doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.LoadXml(Encoding.UTF8.GetString(canonicalizedElement));

                    XmlNode canonSignature = _document.ImportNode(doc.DocumentElement, true);

                    _xadesSignedXml.GetSignatureElement().AppendChild(canonSignature);
                }
            }
            else
            {
                _document.LoadXml(_xadesSignedXml.GetXml().OuterXml);
            }
        }

        /// <summary>
        /// Aplica una transformación al elemento especificado
        /// </summary>
        /// <param name="element"></param>
        /// <param name="transform"></param>
        /// <returns></returns>
        public static byte[] ApplyTransform(XmlElement element, System.Security.Cryptography.Xml.Transform transform)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(element.OuterXml);

            using (MemoryStream ms = new MemoryStream(buffer))
            {
                transform.LoadInput(ms);
                using (MemoryStream transformedStream = (MemoryStream)transform.GetOutput(typeof(Stream)))
                {
                    return transformedStream.ToArray();
                }
            }
        }

        public XmlDocument Document
        {
            get
            {
                return _document;
            }
        }

    }
}
