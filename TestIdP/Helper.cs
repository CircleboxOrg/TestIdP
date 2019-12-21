using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
namespace TestIdP
{
    public static class Helper
    {
        public static string GetSAMLResponse(string request, string username)
        {
            string destination = "https://login.microsoftonline.com/login.srf";
            string recipient = "https://login.microsoftonline.com/login.srf";
            string issuer = "https://accounts.google.com/o/saml2?idpid=C00s8nnu4";

            //XDocument xdRequest = XDocument.Parse(request);
            XNamespace xnSAML2p = "urn:oasis:names:tc:SAML:2.0:protocol";
            XNamespace xnSAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";
            XNamespace xnDS = "http://www.w3.org/2000/09/xmldsig#";

            XDocument xdResponse = new XDocument();
            var xeResponse = new XElement(xnSAML2p + "Response");
            xeResponse.SetAttributeValue("Destination", destination);
            
            var responseId = Guid.NewGuid();

            xeResponse.SetAttributeValue("ID", String.Format("_{0:N}", responseId));

            //xeResponse.SetAttributeValue("InResponseTo", requestId);


            xdResponse.Add(xeResponse);

            

            //2019 - 12 - 11T15: 44:21.256Z
            var str = xdResponse.ToString();
            var sb = new StringBuilder();


            ResponseType response = new ResponseType();
            // Response Main Area
            response.ID = "_" + Guid.NewGuid().ToString();
            response.Destination = recipient;
            response.Version = "2.0";
            response.IssueInstant = System.DateTime.UtcNow;

            NameIDType issuerForResponse = new NameIDType();
            issuerForResponse.Value = issuer.Trim();

            response.Issuer = issuerForResponse;

            StatusType status = new StatusType();

            status.StatusCode = new StatusCodeType();
            status.StatusCode.Value =
              "urn:oasis:names:tc:SAML:2.0:status:Success";

            response.Status = status;

            

            return "";
        }


        public static void TestSigningAndVerifying()
        {
            //byte[] signature = Helper.Sign("<saml2:Assertion xmlns:saml2=\"urn: oasis:names: tc: SAML: 2.0:assertion\" Version=\"2.0\" ID=\"_XqYld3HBsd0NjTozz99ZqNu9M2xs0zlg\" IssueInstant=\"2019 - 12 - 12T13: 40:21.113Z\"><saml2:Issuer xmlns:saml2=\"urn: oasis: names: tc: SAML: 2.0:assertion">https://devel.private.id</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn: oasis: names: tc: SAML: 2.0:nameid - format:persistent">testuser@private.id</saml2:NameID><saml2:SubjectConfirmation Method="urn: oasis: names: tc: SAML: 2.0:cm: bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2019 - 12 - 12T14: 40:21.113Z" Recipient="https://login.microsoftonline.com/login.srf"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2019-12-12T13:40:21.113Z" NotOnOrAfter="2019-12-12T14:40:21.113Z"/><saml2:AuthnStatement AuthnInstant="2019-12-12T13:40:21.113Z" SessionIndex="376495580"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml2:Attribute Name="IDPEmail"><saml2:AttributeValue xsi:type="xs:anyType">testuser@private.id</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>", "scott@private.id");
            // Verify signature. Testcert.cer corresponds to "cn=my cert subject"

            var b = Helper.Verify("Test", signature, @"C:\Users\Jeff Trotman\OneDrive - Technicality, LLC\Private.id\mycert.pem");
            

        }
        public static byte[] Sign(string text, string certSubject)

        {
            // Access Personal (MY) certificate store of current user
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);

            // Find the certificate we'll use to sign
            RSACryptoServiceProvider csp = null;
            foreach (X509Certificate2 cert in my.Certificates)
            {
                if (cert.Subject.Contains(certSubject))
                {
                    // We found it.
                    // Get its associated CSP and private key
                    csp = (RSACryptoServiceProvider)cert.PrivateKey;
                }
            }

            if (csp == null)
            {
                throw new Exception("No valid cert was found");
            }

            // Hash the data
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);

            // Sign the hash
            return csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));

        }

        public static bool Verify(string text, byte[] signature, string certPath)

        {
            // Load the certificate we'll use to verify the signature from a file
            X509Certificate2 cert = new X509Certificate2(certPath);
            // Note:
            // If we want to use the client cert in an ASP.NET app, we may use something like this instead:
            // X509Certificate2 cert = new X509Certificate2(Request.ClientCertificate.Certificate);

            // Get its associated CSP and public key
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
            var publicKeyXml = csp.ToXmlString(false);
            // Hash the data
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);

            // Verify the signature with the hash
            return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
        }

        public static string Decrypt(string digest, string certPath)
        {
            // Load the certificate we'll use to verify the signature from a file
            X509Certificate2 cert = new X509Certificate2(certPath);
            // Note:
            // If we want to use the client cert in an ASP.NET app, we may use something like this instead:
            // X509Certificate2 cert = new X509Certificate2(Request.ClientCertificate.Certificate);

            // Get its associated CSP and public key
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
            //var publicKeyXml = csp.ToXmlString(false);
            // Hash the data
            //SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();

            
            byte[] data = encoding.GetBytes(digest);
            //byte[] hash = sha1.ComputeHash(data);

            // Verify the signature with the hash
            //return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
            var cleartextarr = csp.Decrypt(digest, false);
            return cleartextarr.ToString();
        }

    }
}