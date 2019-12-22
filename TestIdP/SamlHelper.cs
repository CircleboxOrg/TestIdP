using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using log4net;
using System.Net;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Serialization;
using System.IO;

namespace TestIdP
{
    public static class SamlHelper
    {
        private static ILog Logger = LogManager.GetLogger(typeof(SamlHelper));

        /// <summary>
        /// Creates a Version 1.1 Saml Assertion
        /// </summary>
        /// <param name="issuer">Issuer</param>
        /// <param name="subject">Subject</param>
        /// <param name="attributes">Attributes</param>
        /// <returns>returns a Version 2.0 Saml Assertion</returns>
        private static AssertionType CreateSamlAssertion(string issuer, string recipient, string subject, string audience, string nameIdPolicyFormat, Dictionary<string, string> attributes)
        {
            // Here we create some SAML assertion with ID and Issuer name. 
            AssertionType assertion = new AssertionType();
            assertion.ID = "_" + Guid.NewGuid().ToString();

            NameIDType issuerForAssertion = new NameIDType();
            issuerForAssertion.Value = issuer.Trim();

            assertion.Issuer = issuerForAssertion;
            assertion.Version = "2.0";

            assertion.IssueInstant = System.DateTime.UtcNow;

            //Not before, not after conditions 
            ConditionsType conditions = new ConditionsType();
            conditions.NotBefore = DateTime.UtcNow;
            conditions.NotBeforeSpecified = true;
            conditions.NotOnOrAfter = DateTime.UtcNow.AddMinutes(5);
            conditions.NotOnOrAfterSpecified = true;

            AudienceRestrictionType audienceRestriction = new AudienceRestrictionType();
            audienceRestriction.Audience = new string[] { audience.Trim() };

            conditions.Items = new ConditionAbstractType[] { audienceRestriction };

            //Name Identifier to be used in Saml Subject
            NameIDType nameIdentifier = new NameIDType();
            //nameIdentifier.NameQualifier = domain.Trim();
            nameIdentifier.Format = nameIdPolicyFormat;
            nameIdentifier.Value = subject.Trim();

            SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
            SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();

            subjectConfirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
            
            subjectConfirmation.SubjectConfirmationData = subjectConfirmationData;
            // 
            // Create some SAML subject. 
            SubjectType samlSubject = new SubjectType();

            AttributeStatementType attrStatement = new AttributeStatementType();
            AuthnStatementType authStatement = new AuthnStatementType();
            authStatement.AuthnInstant = DateTime.UtcNow;
            AuthnContextType context = new AuthnContextType();
            context.ItemsElementName = new ItemsChoiceType5[] { ItemsChoiceType5.AuthnContextClassRef };
            //context.Items = new object[] { "AuthnContextClassRef" };
            context.Items = new object[] { "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" };
            authStatement.AuthnContext = context;

            samlSubject.Items = new object[] { nameIdentifier, subjectConfirmation };

            assertion.Subject = samlSubject;

            IPHostEntry ipEntry =
                Dns.GetHostEntry(System.Environment.MachineName);

            SubjectLocalityType subjectLocality = new SubjectLocalityType();
            subjectLocality.Address = ipEntry.AddressList[0].ToString();

            attrStatement.Items = new AttributeType[attributes.Count];
            int i = 0;
            // Create userName SAML attributes. 
            foreach (KeyValuePair<string, string> attribute in attributes)
            {
                AttributeType attr = new AttributeType();
                attr.Name = attribute.Key;
                //attr.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
                attr.AttributeValue = new object[] { attribute.Value };
                attrStatement.Items[i] = attr;
                i++;
            }
            assertion.Conditions = conditions;

            assertion.Items = new StatementAbstractType[] { authStatement, attrStatement };

            return assertion;

        }
        /// <summary>
        /// GetPostSamlResponse - Returns a Base64 Encoded String with the SamlResponse in it.
        /// </summary>
        /// <param name="recipient">Recipient</param>
        /// <param name="issuer">Issuer</param>
        /// <param name="domain">Domain</param>
        /// <param name="subject">Subject</param>
        /// <param name="storeLocation">Certificate Store Location</param>
        /// <param name="storeName">Certificate Store Name</param>
        /// <param name="findType">Certificate Find Type</param>
        /// <param name="certLocation">Certificate Location</param>
        /// <param name="findValue">Certificate Find Value</param>
        /// <param name="certFile">Certificate File (used instead of the above Certificate Parameters)</param>
        /// <param name="certPassword">Certificate Password (used instead of the above Certificate Parameters)</param>
        /// <param name="attributes">A list of attributes to pass</param>
        /// <param name="signatureType">Whether to sign Response or Assertion</param>
        /// <returns>A base64Encoded string with a SAML response.</returns>
        public static string GetPostSamlResponse(string recipient, string issuer, string subject, string audience, string requestid, string nameIdPolicyFormat,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes, SigningHelper.SignatureType signatureType, Models.IdPOptionsModel options)
        {
            ResponseType response = new ResponseType();
            // Response Main Area
            response.ID = "_" + Guid.NewGuid().ToString("N");
            response.Destination = recipient;
            response.Version = "2.0";
            response.IssueInstant = System.DateTime.UtcNow;
            response.InResponseTo = requestid;

            NameIDType issuerForResponse = new NameIDType();
            issuerForResponse.Value = issuer.Trim();

            response.Issuer = issuerForResponse;

            StatusType status = new StatusType();

            status.StatusCode = new StatusCodeType();
            status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Success";

            response.Status = status;

            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            if(options.UseNamespaces)
            { 
                ns.Add("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
                ns.Add("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
                ns.Add("ds", "http://www.w3.org/2000/09/xmldsig#");
            }
            XmlSerializer responseSerializer =
                new XmlSerializer(response.GetType());

            StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = Encoding.UTF8;
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;

            XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);

            string samlString = string.Empty;

            AssertionType assertionType = SamlHelper.CreateSamlAssertion(
                issuer.Trim(), recipient.Trim(), subject.Trim(), audience.Trim(), nameIdPolicyFormat, attributes);

            response.Items = new AssertionType[] { assertionType };

            responseSerializer.Serialize(responseWriter, response, ns);
            responseWriter.Close();

            samlString = stringWriter.ToString();

            samlString = samlString.Replace("SubjectConfirmationData",
                string.Format("SubjectConfirmationData NotOnOrAfter=\"{0:o}\" Recipient=\"{1}\" InResponseTo=\"{2:D}\" ",
                DateTime.UtcNow.AddMinutes(5), recipient, requestid));

            stringWriter.Close();

            XmlDocument doc = new XmlDocument();
            //doc.LoadXml(samlString);
            byte[] samlBytes = Encoding.UTF8.GetBytes(samlString);
            var ms = new MemoryStream(samlBytes);
            doc.Load(ms);

            X509Certificate2 cert = null;
            if (System.IO.File.Exists(certFile))
            {
                try
                { 
                cert = new X509Certificate2(certFile, certPassword);
                }
                catch(Exception ex)
                {
                    ;
                }
            }
            else
            {
                X509Store store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection coll = store.Certificates.Find(findType, findValue, false);
                if (coll.Count < 1)
                {
                    throw new ArgumentException("Unable to locate certificate");
                }
                cert = coll[0];
                store.Close();
            }

            XmlElement signature =
                SigningHelper.SignDoc(doc, cert, "ID",
                signatureType == SigningHelper.SignatureType.Response ? response.ID : assertionType.ID,
                options);

            doc.DocumentElement.InsertBefore(signature,
                doc.DocumentElement.ChildNodes[1]);

            if (SamlHelper.Logger.IsDebugEnabled)
            {
                SamlHelper.Logger.DebugFormat(
                    "Saml Assertion before encoding = {0}",
                    doc.OuterXml.ToString());
            }
            //string responseStr = doc.OuterXml;

            //byte[] base64EncodedBytes =
            //    Encoding.UTF8.GetBytes(responseStr);
            
            if (options.IncludeXmlDeclaration)
            { 
                //Create an XML declaration. 
                XmlDeclaration xmldecl;
                xmldecl = doc.CreateXmlDeclaration("1.0","UTF-8", "no");
                //Add the new node to the document.
                XmlElement root = doc.DocumentElement;
                doc.InsertBefore(xmldecl, root);

            }

            byte[] base64EncodedBytes = Encoding.UTF8.GetBytes(doc.OuterXml);

            string returnValue = System.Convert.ToBase64String(
                base64EncodedBytes);

            return returnValue;
        }
        /// <summary>
        /// GetPostSamlResponse - Returns a Base64 Encoded String with the SamlResponse in it with a Default Signature type.
        /// </summary>
        /// <param name="recipient">Recipient</param>
        /// <param name="issuer">Issuer</param>
        /// <param name="domain">Domain</param>
        /// <param name="subject">Subject</param>
        /// <param name="storeLocation">Certificate Store Location</param>
        /// <param name="storeName">Certificate Store Name</param>
        /// <param name="findType">Certificate Find Type</param>
        /// <param name="certLocation">Certificate Location</param>
        /// <param name="findValue">Certificate Find Value</param>
        /// <param name="certFile">Certificate File (used instead of the above Certificate Parameters)</param>
        /// <param name="certPassword">Certificate Password (used instead of the above Certificate Parameters)</param>
        /// <param name="attributes">A list of attributes to pass</param>
        /// <returns>A base64Encoded string with a SAML response.</returns>
        public static string GetPostSamlResponse(string recipient, string issuer, string subject, string audience, string requestid, string nameIdPolicyFormat,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes, Models.IdPOptionsModel options)
        {
            return GetPostSamlResponse(recipient, issuer, subject, audience, requestid, nameIdPolicyFormat, storeLocation, storeName, findType, certFile, certPassword, findValue, attributes,
                SigningHelper.SignatureType.Response, options);
        }
    }
}