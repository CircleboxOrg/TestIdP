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
    }
}