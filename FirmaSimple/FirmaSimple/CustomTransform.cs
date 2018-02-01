using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FirmaSimple
{
    public class CustomTransform : Transform
    {
        public override Type[] InputTypes => throw new NotImplementedException();

        public override Type[] OutputTypes => throw new NotImplementedException();

        public override object GetOutput()
        {
            throw new NotImplementedException();
        }

        public override object GetOutput(Type type)
        {
            throw new NotImplementedException();
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            throw new NotImplementedException();
        }

        public override void LoadInput(object obj)
        {
            throw new NotImplementedException();
        }

        protected override XmlNodeList GetInnerXml()
        {
            throw new NotImplementedException();
        }
    }
}
