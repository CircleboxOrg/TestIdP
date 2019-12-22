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



            //if (HttpContext.Request.Headers["Content-Type"].StartsWith("multipart/form-data"))
            //{
                System.IO.File.WriteAllText(HttpRuntime.BinDirectory + "samlResponse.txt", SAMLResponse);
                responseBytes = Convert.FromBase64String(SAMLResponse);
            //}
            //else
            //{
            //    System.IO.File.WriteAllText(HttpRuntime.BinDirectory + "samlResponse.txt", System.Web.HttpUtility.UrlDecode(SAMLResponse));
            //    responseBytes = Convert.FromBase64String(System.Web.HttpUtility.UrlDecode(SAMLResponse));
            //}

            var encoding = new System.Text.UTF8Encoding();
            var responseString = encoding.GetString(responseBytes);
            ViewData.Model = responseString;
            return new FileContentResult(responseBytes, "application/xml");
            
        }

    }
}