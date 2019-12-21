using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TestIdP.Models
{
    public class SAMLResponseModel
    {
        public string Destination { get; set; }
        public string SAMLResponse { get; set; }
        public string RelayState { get; set; }
    }
}