using davidsp8.common.Security.Saml;
using davidsp8.common.Security.Saml20;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace GenerateTokenConsol
{
    class Program
    {
        static void Main(string[] args)
        {
            var signatureXmlElement = GenerateSignature();

            ParseSignature(signatureXmlElement);

        }


        private static XmlElement GenerateSignature()
        {

            Dictionary<string, string> attributes = new Dictionary<string, string>();

            // Set Parameters to the method call to either the configuration value or a default value
            StoreLocation storeLocation = StoreLocation.LocalMachine;
            StoreName storeName = StoreName.Root;
            X509FindType findType = X509FindType.FindByThumbprint;
            string certFileLocation = @"D:\SslCertificates\SamRootCertificate.pfx";
            string certPassword = null;
            string certFindKey = "";
            bool signAssertion = false;
            SigningHelper.SignatureType signatureType = SigningHelper.SignatureType.Response;
            if (signAssertion)
            {
                signatureType = SigningHelper.SignatureType.Assertion;
            }

            return GetSignature("RecipientWontok",
                "IssuerWontok", "DomainCom", "SubjectSecurity",
                storeLocation, storeName, findType,
                certFileLocation, certPassword, certFindKey,
                attributes, signatureType);


        }

        public static void ParseSignature(XmlElement signatureXmlElement)
        {
            SignedXml signedXml = new SignedXml();

            signedXml.LoadXml(((System.Xml.XmlElement)(signatureXmlElement)));


            RSA key = null;
            var e = signedXml.KeyInfo.GetEnumerator();
            while (e.MoveNext())
            {
                X509Certificate2 cert = (X509Certificate2)((System.Security.Cryptography.Xml.KeyInfoX509Data)e.Current).Certificates[0];
                var isValidSSOCert = ValidateCertificate(cert);

                key = (RSA)((System.Security.Cryptography.RSACryptoServiceProvider)(cert.PublicKey.Key));

                break;
            }

        }


        public static void ParseSamlResponse(string samldata)
        {
            //Check the args. 
            bool isValidSSOCert = false;
            if (null == samldata)
                throw new ArgumentNullException("samldata");

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.LoadXml(samldata);

            // Load the certificate from the store.
            //X509Certificate2 certi = GetCertificateBySubject(CertificateSubject);

            // Create a new SignedXml object and pass it 
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            XmlNamespaceManager xMan = new XmlNamespaceManager(xmlDocument.NameTable);
            xMan.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            xMan.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            xMan.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");


            // Find the "Signature" node            
            var sign = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/ds:Signature", xMan);

            // Find the "assertion" node            
            var assert = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion", xMan);

            signedXml.LoadXml(((System.Xml.XmlElement)(sign)));


            RSA key = null;
            var e = signedXml.KeyInfo.GetEnumerator();
            while (e.MoveNext())
            {
                X509Certificate2 cert = (X509Certificate2)((System.Security.Cryptography.Xml.KeyInfoX509Data)e.Current).Certificates[0];
                isValidSSOCert = ValidateCertificate(cert);

                key = (RSA)((System.Security.Cryptography.RSACryptoServiceProvider)(cert.PublicKey.Key));

                break;
            }

            string firstName = string.Empty, lastName = string.Empty, username = string.Empty, uid = string.Empty, authlevel = string.Empty, dynattr = string.Empty;


            var xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'firstname']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                firstName = xNode.InnerText;
            }

            xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'lastname']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                lastName = xNode.InnerText;
            }

            xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'username']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                username = xNode.InnerText;
            }

            xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'uid']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                uid = xNode.InnerText;
            }

            xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'authlevel']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                authlevel = xNode.InnerText;
            }

            xNode = xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name = 'dynattr']/saml:AttributeValue", xMan);
            if (xNode != null)
            {
                dynattr = xNode.InnerText;
            }

            string primaryUsername = string.Empty;
            // dynattr = "Key1=Value1|CSMCUUID=dd9e5356cd5d4f4f8a9d3e67cab5e77d|tsafeun=tisrepl_1_ts@bigpond.com|Key2|Key3=Value3|Key4=Value4";//For dev testing only

            var Dictdynattr = dynattr.Split('|');

            foreach (var item in Dictdynattr)
            {
                if (item.Contains("="))
                {
                    if (item.Split('=')[0] == "tsafeun")
                    {
                        primaryUsername = item.Split('=')[1];
                    }
                }
            }
        }


        private static bool ValidateCertificate(X509Certificate2 cert)
        {
            bool result = false;
            bool chainIsValid = false;

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chainIsValid = chain.Build(cert);

            if ((cert.SubjectName.Name == cert.IssuerName.Name) && chainIsValid)
            {
                result = true;
            }
            return result;
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
        public static string GetPostSamlResponse(string recipient, string issuer, string domain, string subject,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes, SigningHelper.SignatureType signatureType)
        {
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
            status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Success";

            response.Status = status;

            XmlSerializer responseSerializer =
                new XmlSerializer(response.GetType());

            StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;
            settings.Encoding = Encoding.UTF8;

            XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);

            string samlString = string.Empty;

            AssertionType assertionType = CreateSamlAssertion(
                issuer.Trim(), recipient.Trim(), domain.Trim(), subject.Trim(), attributes);

            response.Items = new AssertionType[] { assertionType };

            responseSerializer.Serialize(responseWriter, response);
            responseWriter.Close();

            samlString = stringWriter.ToString();

            samlString = samlString.Replace("SubjectConfirmationData",
                string.Format("SubjectConfirmationData NotOnOrAfter=\"{0:o}\" Recipient=\"{1}\"",
                DateTime.UtcNow.AddMinutes(5), recipient));

            stringWriter.Close();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlString);
            X509Certificate2 cert = null;
            if (System.IO.File.Exists(certFile))
            {
                cert = new X509Certificate2(certFile, certPassword);
            }
            else
            {
                X509Store store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection coll = store.Certificates.Find(findType, findValue, true);
                if (coll.Count <1)
                {
                    throw new ArgumentException("Unable to locate certificate");
                }
                cert = coll[0];
                store.Close();
            }

            XmlElement signature =
                SigningHelper.SignDoc(doc, cert, "ID",
                signatureType == SigningHelper.SignatureType.Response ? response.ID : assertionType.ID);

            doc.DocumentElement.InsertBefore(signature,
                doc.DocumentElement.ChildNodes[1]);

            string responseStr = doc.OuterXml;

            byte[] base64EncodedBytes =
                Encoding.UTF8.GetBytes(responseStr);

            string returnValue = System.Convert.ToBase64String(
                base64EncodedBytes);

            return returnValue;
        }


        public static XmlElement GetSignature(string recipient, string issuer, string domain, string subject,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes, SigningHelper.SignatureType signatureType)
        {
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
            status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Success";

            response.Status = status;

            XmlSerializer responseSerializer =
                new XmlSerializer(response.GetType());

            StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;
            settings.Encoding = Encoding.UTF8;

            XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);

            string samlString = string.Empty;

            AssertionType assertionType = CreateSamlAssertion(
                issuer.Trim(), recipient.Trim(), domain.Trim(), subject.Trim(), attributes);

            response.Items = new AssertionType[] { assertionType };

            responseSerializer.Serialize(responseWriter, response);
            responseWriter.Close();

            samlString = stringWriter.ToString();

            samlString = samlString.Replace("SubjectConfirmationData",
                string.Format("SubjectConfirmationData NotOnOrAfter=\"{0:o}\" Recipient=\"{1}\"",
                DateTime.UtcNow.AddMinutes(5), recipient));

            stringWriter.Close();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlString);
            X509Certificate2 cert = null;

            cert = new X509Certificate2(certFile, certPassword);

            XmlElement signature =
                SigningHelper.SignDoc(doc, cert, "ID",
                signatureType == SigningHelper.SignatureType.Response ? response.ID : assertionType.ID);

            return signature;

        }

        private static AssertionType CreateSamlAssertion(string issuer, string recipient, string domain, string subject, Dictionary<string, string> attributes)
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
            audienceRestriction.Audience = new string[] { domain.Trim() };

            conditions.Items = new ConditionAbstractType[] { audienceRestriction };

            //Name Identifier to be used in Saml Subject
            NameIDType nameIdentifier = new NameIDType();
            nameIdentifier.NameQualifier = domain.Trim();
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
            context.Items = new object[] { "AuthnContextClassRef" };
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
                attr.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
                attr.AttributeValue = new object[] { attribute.Value };
                attrStatement.Items[i] = attr;
                i++;
            }
            assertion.Conditions = conditions;

            assertion.Items = new StatementAbstractType[] { authStatement, attrStatement };

            return assertion;

        }


    }
}
