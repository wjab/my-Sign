using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FirmaSimple
{
    class Program
    {
        static void Main(string[] args)
        {
            string policyIdentifier = "https://tribunet.hacienda.go.cr/docs/esquemas/2016/v4.1/Resolucion_Comprobantes_Electronicos_DGT-R-48-2016.pdf";

            X509Certificate2 cert = new X509Certificate2(@"C:\DigitalInvoice\Tests\310156726431.p12", "1980");

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(@"C:\DigitalInvoice\Tests\simple.xml");


            FirmaXades xades = new FirmaXades();
            xades.PolicyIdentifier = policyIdentifier;
            xades.PolicyHash = Convert.ToBase64String(Encoding.UTF8.GetBytes(policyIdentifier));

            xades.SetContentEnveloped(document);

            xades.Sign(cert);

            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = new UTF8Encoding();
            using (var writer = XmlWriter.Create(@"C:\DigitalInvoice\Tests\signed.xml", settings))
            {
                xades.Document.Save(writer);
            }

        }
    }
}
