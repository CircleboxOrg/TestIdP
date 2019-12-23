using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Text;
using System.Net;
using System.IO;
using System.Xml.Serialization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using log4net;
using System.Xml.Schema;
using System.Xml;
using System.Xml.Linq;

namespace TestIdP.Controllers
{
    public class HomeController : Controller
    {
        private ILog Logger = LogManager.GetLogger("TestIdP");

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string SAMLRequest, string RelayState, string username, int spId = 0)
        {
            //byte[] requestBytes = Convert.FromBase64String(System.Web.HttpUtility.UrlDecode(SAMLRequest));
            byte[] requestBytes = Convert.FromBase64String(SAMLRequest);
            var encoding = new UTF8Encoding();
            var requestString = encoding.GetString(requestBytes);
            XNamespace samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
            XNamespace nsassertion = "urn:oasis:names:tc:SAML:2.0:assertion";

            XDocument xdRequest = XDocument.Parse(requestString);
            XElement xeAuthnRequest = xdRequest.Element(samlp + "AuthnRequest");
            string requestId = xeAuthnRequest.Attribute("ID").Value;
            string requestVersion = xeAuthnRequest.Attribute("Version").Value;
            string requestIssueInstant = xeAuthnRequest.Attribute("IssueInstant").Value;
            string requestIssuer = xeAuthnRequest.Element(nsassertion + "Issuer").Value;
            string nameIdPolicyFormat = xeAuthnRequest.Element(samlp + "NameIDPolicy").Attribute("Format").Value;

            Session["requestId"] = requestId;
            Session["requestVersion"] = requestVersion;
            Session["requestIssueInstant"] = requestIssueInstant;
            Session["requestIssuer"] = requestIssuer;
            Session["nameIdPolicyFormat"] = nameIdPolicyFormat;
            Session["RelayState"] = RelayState;
            Session["username"] = username;
            Session["spId"] = spId;

            return RedirectToAction("Signin");

        }

        public ActionResult Signin()
        {
            var model = new Models.IdPOptionsModel();
            model.EchoRelayState = false;
            model.IncludeXmlDeclaration = true;
            model.SetHeaderToUrlEncoded = true;
            model.SignAssertion = true;
            model.UrlEncodeRelayState = false;
            model.UrlEncodeSamlResponse = false;
            model.UseNamespaces = true;
            model.UseSHA256 = false;

            ViewData.Model = model;
            return View();
        }

        [HttpPost]
        public ActionResult Signin(Models.IdPOptionsModel options)
        {
            string requestId = Session["requestId"].ToString(); 
            string requestVersion = Session["requestVersion"].ToString();
            string requestIssuesInstant = Session["requestIssueInstant"].ToString();
            string requestIssuer = Session["requestIssuer"].ToString();
            string nameIdPolicyFormat = Session["nameIdPolicyFormat"].ToString();
            string RelayState = Session["RelayState"].ToString();
            string username = Session["username"].ToString();
            int spId = Convert.ToInt32(Session["spId"]);

            
            SigningHelper.SignatureType signatureType = SigningHelper.SignatureType.Response;
            if (options.SignAssertion)
            {
                signatureType = SigningHelper.SignatureType.Assertion;
            }

            string strRecipient = Properties.Settings.Default.Recipient;
            string strIssuer = Properties.Settings.Default.Issuer;
            string strSubject = username;
            string strAudience = requestIssuer;

            // Set Parameters to the method call to either the configuration value or a default value
            StoreLocation storeLocation = StoreLocation.CurrentUser;
            StoreName storeName = StoreName.My;
            X509FindType findType = X509FindType.FindByThumbprint;
            string certFileLocation = "";
            string certPassword = Properties.Settings.Default.CertPassword;
            string certFindKey = Properties.Settings.Default.CertThumbprint;

            Dictionary<string, string> attributes = new Dictionary<string, string>();
            attributes.Add("IDPEmail", username);
            string stringSamlResponse = "";
            try
            {
                stringSamlResponse = SamlHelper.GetPostSamlResponse(strRecipient,
                                strIssuer, strSubject, strAudience, requestId, nameIdPolicyFormat,
                                storeLocation, storeName, findType,
                                certFileLocation, certPassword, certFindKey,
                                attributes, signatureType, options);
                if (options.UrlEncodeSamlResponse)
                {
                    stringSamlResponse = System.Web.HttpUtility.UrlEncode(stringSamlResponse);
                }
                
            }
            catch (Exception ex)
            {
                ViewData["Error"] = ex.ToString();
            }
            Logger.DebugFormat(
                    "PostData = {0}", stringSamlResponse);


            //
            var model = new Models.SAMLResponseModel();

            model.SAMLResponse = stringSamlResponse;
            if (options.EchoRelayState)
            {
                if (options.UrlEncodeRelayState)
                {
                    model.RelayState = System.Web.HttpUtility.UrlEncode(RelayState);
                    
                }
                else
                {
                    model.RelayState = RelayState;
                }
            }
            else
            {
                //send hardcoded value back
                model.RelayState = "idp.technicality.online";
                if (options.UrlEncodeRelayState)
                {
                    model.RelayState = System.Web.HttpUtility.UrlEncode(model.RelayState);
                }
                
            }
 
            if (spId == 1)
            {
                // return to TestSP URL
                model.Destination = Properties.Settings.Default.TestSPUrl;
            }
            else
            { 
                model.Destination = strRecipient;
            }

            if (options.SetHeaderToUrlEncoded)
            {
                model.Enctype = "application/x-www-form-urlencoded";
            }
            else
            {
                model.Enctype = "multipart/form-data";
            }
            ViewData.Model = model;

            return View("SamlResponse");
        }

        
    }
}