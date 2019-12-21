using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace TestIdP
{
    public static class SigningHelper
    {
        public enum SignatureType
        {
            Response,
            Assertion
        };
        /// <summary>
        /// Signs an XML Document for a Saml Response
        /// </summary>
        /// <param name="xml"></param>
        /// <param name="cert2"></param>
        /// <param name="referenceId"></param>
        /// <returns></returns>
        public static XmlElement SignDoc(XmlDocument doc, X509Certificate2 cert2, string referenceId, string referenceValue, Models.IdPOptionsModel options)
        {
            SamlSignedXml sig = new SamlSignedXml(doc, referenceId);

            // Add the key to the SignedXml xmlDocument. 
            //sig.SigningKey = cert2.PrivateKey;

            sig.SigningKey = cert2.GetRSAPrivateKey();

            if (options.UseSHA256)
            { 
                //otherwise - defaults to SHA1
                sig.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                
            }
            // Create a reference to be signed. 
            Reference reference = new Reference();

            reference.Uri = String.Empty;
            reference.Uri = "#" + referenceValue;

            // Add an enveloped transformation to the reference. 
            XmlDsigEnvelopedSignatureTransform env = new
                XmlDsigEnvelopedSignatureTransform();
            //XmlDsigC14NTransform env2 = new XmlDsigC14NTransform();
            XmlDsigExcC14NTransform env2 = new XmlDsigExcC14NTransform();

            reference.AddTransform(env);
            reference.AddTransform(env2);
            if (options.UseSHA256)
            {
                reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            }
            // Add the reference to the SignedXml object. 
            sig.AddReference(reference);
            

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate). 
            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyData = new KeyInfoX509Data(cert2);

            keyInfo.AddClause(keyData);

            sig.KeyInfo = keyInfo;

            sig.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            // Compute the signature. 
            sig.ComputeSignature();

            // Get the XML representation of the signature and save it to an XmlElement object. 
            XmlElement xmlDigitalSignature = sig.GetXml();

            return xmlDigitalSignature;
        }
    }
}