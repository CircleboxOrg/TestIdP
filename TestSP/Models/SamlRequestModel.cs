using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Xml.Linq;
namespace TestSP.Models
{
    public class SamlRequestModel
    {
        public string SAMLRequest { 
            get
            {
                XNamespace samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
                //var xd = new XDocument();
                var xe = new XElement(samlp + "AuthnRequest",
                    new XAttribute(XNamespace.Xmlns + "samlp", "urn:oasis:names:tc:SAML:2.0:protocol"));

                xe.SetAttributeValue("ID", "_" + Guid.NewGuid().ToString());
                xe.SetAttributeValue("Version", "2.0");
                xe.SetAttributeValue("IssueInstant", System.DateTime.UtcNow.ToString());

                XNamespace nsassertion = "urn:oasis:names:tc:SAML:2.0:assertion";
                var xeIssuer = new XElement(nsassertion + "Issuer", "urn:federation:MicrosoftOnline");
                xe.Add(xeIssuer);

                var xeNameIDPolicy = new XElement(samlp + "NameIDPolicy");
                xeNameIDPolicy.SetAttributeValue("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
                xe.Add(xeNameIDPolicy);

                return xe.ToString();
            }
        }

        public string Base64SAMLRequest
        {
            get
            {
                UTF8Encoding encoding = new UTF8Encoding();
                byte[] data = encoding.GetBytes(this.SAMLRequest);
                return Convert.ToBase64String(data);
            }
        }
        public string RelayState { 
            get {
                return "TestRelayState";
            } 
        }
        public string username { get; set; }

        public SamlRequestModel()
        {
            this.username = "petey@ducttapetechnology.com";
        }
    }
}