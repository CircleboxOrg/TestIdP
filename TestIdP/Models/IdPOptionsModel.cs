using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TestIdP.Models
{
    public class IdPOptionsModel
    {
        public bool EchoRelayState { get; set; }
        public bool UseSHA256 { get; set; }
        public bool SetHeaderToUrlEncoded { get; set; }
        public bool UrlEncodeSamlResponse { get; set; }
        public bool UrlEncodeRelayState { get; set; }
        public bool UseNamespaces { get; set; }
        public bool IncludeXmlDeclaration { get; set; }
        public bool SignAssertion { get; set; }
    }
}