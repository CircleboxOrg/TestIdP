using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace TestSP.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var model = new Models.SamlRequestModel();
            ViewData.Model = model;
            return View();
        }


        [HttpPost]
        public ActionResult Receive(string SAMLResponse, string RelayState)
        {
            byte[] responseBytes = null;

            // not sure if we need to UrlDecode or not
            string responseBase64 = "";
            try
            {
                responseBase64 = System.Web.HttpUtility.UrlDecode(SAMLResponse);
                responseBytes = Convert.FromBase64String(responseBase64);
                
            }
            catch(Exception)
            {
                // if that didn't work - we didn't need to UrlDecode
                responseBase64 = SAMLResponse;
                responseBytes = Convert.FromBase64String(responseBase64);
                
            }
            // save the base 64 response
            System.IO.File.WriteAllText(HttpRuntime.BinDirectory + "samlResponse.txt", responseBase64);
            
            var encoding = new System.Text.UTF8Encoding();
            var responseString = encoding.GetString(responseBytes);
            ViewData.Model = responseString;
            return new FileContentResult(responseBytes, "application/xml");
            
        }

    }
}