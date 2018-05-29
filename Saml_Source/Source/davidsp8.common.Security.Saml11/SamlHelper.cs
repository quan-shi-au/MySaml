using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Serialization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IdentityModel.Tokens;
using System.Net;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.IdentityModel.Selectors;
using System.ServiceModel.Security;
using System.Collections;
using log4net;
using davidsp8.common.Security.Saml;

namespace davidsp8.common.Security.Saml11 {
    public static class SamlHelper {
        private static ILog Logger = LogManager.GetLogger(typeof(SamlHelper));

        #region Obsolete Methods
        [Obsolete]
        private static SamlAssertion CreateSamlAssertion(string issuer, string domain, string subject, Dictionary<string, string> attributes) {
            // Here we create some SAML assertion with ID and Issuer name. 
            SamlAssertion assertion = new SamlAssertion();
            assertion.AssertionId = "_" + Guid.NewGuid().ToString();
            assertion.Issuer = issuer;

            //Not before, not after conditions 
            assertion.Conditions = new SamlConditions(DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(10));

            // 
            // Create some SAML subject. 
            SamlSubject samlSubject = new SamlSubject();
            samlSubject.Name = subject;
            samlSubject.NameQualifier = subject;

            samlSubject.ConfirmationMethods.Add("urn:oasis:names:tc:SAML:1.0:cm:bearer");
            // 
            // Now create the SAML statement containing one attribute and one subject. 
            SamlAttributeStatement samlAttributeStatement = new SamlAttributeStatement();
            samlAttributeStatement.SamlSubject = samlSubject;
            // 
            // Create userName SAML attributes. 
            foreach (KeyValuePair<string, string> attribute in attributes) {
                SamlAttribute attr = new SamlAttribute();
                attr.Name = attribute.Key;
                attr.Namespace = domain;
                attr.AttributeValues.Add(subject);
                samlAttributeStatement.Attributes.Add(attr);

            }
            // Append the statement to the SAML assertion. 
            assertion.Statements.Add(samlAttributeStatement);

            IPHostEntry ipEntry =
                Dns.GetHostEntry(System.Environment.MachineName);

            SamlAuthenticationStatement samlAuthenticationStatement =
                new SamlAuthenticationStatement(samlSubject,
                    "urn:oasis:names:tc:SAML:1.0:am:password",
                    DateTime.UtcNow, null, ipEntry.AddressList[0].ToString(),
                null);

            assertion.Statements.Add(samlAuthenticationStatement);
            return assertion;

        }
        [Obsolete]
        public static string GetAssertion(
            string issuer, string subject, Dictionary<string, string> attributes) {

            return SamlHelper.SerializeToken(
                SamlHelper.CreateSamlAssertion(issuer, subject, subject, attributes));

        }
        [Obsolete]
        private static string SerializeToken(SamlAssertion assertion) {
            SamlSecurityToken token = new SamlSecurityToken(assertion);

            SamlSerializer serializer = new SamlSerializer();
            WSSecurityTokenSerializer tokenSerializer = new WSSecurityTokenSerializer();
            StringWriter stringWriter = new StringWriter();

            XmlTextWriter xmltextWriter = new XmlTextWriter(stringWriter);

            serializer.WriteToken(token, xmltextWriter, tokenSerializer);

            return stringWriter.ToString();

        }
        [Obsolete]
        public static string GetAssertion(
            string issuer, string subject, string certLocation, string certPassword,
            Dictionary<string, string> attributes) {
            // Create certificate from file. It must contain private key! 
            X509Certificate2 cert = new X509Certificate2(certLocation, certPassword);

            // The private key contained in the certificate will be used to sign the token. 
            X509AsymmetricSecurityKey signingKey = new X509AsymmetricSecurityKey(cert);

            SecurityKeyIdentifier ski = new SecurityKeyIdentifier(new
                X509ThumbprintKeyIdentifierClause(cert));

            SamlAssertion assertion =
                SamlHelper.CreateSamlAssertion(issuer, subject, subject, attributes);

            assertion.SigningCredentials = new
                SigningCredentials(signingKey, SecurityAlgorithms.RsaSha1Signature,
                SecurityAlgorithms.Sha1Digest, ski);
            return SamlHelper.SerializeToken(assertion);

        }
        #endregion

        /// <summary>
        /// Creates a Version 1.1 Saml Assertion
        /// </summary>
        /// <param name="issuer">Issuer</param>
        /// <param name="subject">Subject</param>
        /// <param name="attributes">Attributes</param>
        /// <returns>returns a Version 1.1 Saml Assertoion</returns>
        private static AssertionType CreateSaml11Assertion(string issuer, string domain, string subject, Dictionary<string, string> attributes) {
            // Create some SAML assertion with ID and Issuer name. 
            AssertionType assertion = new AssertionType();
            assertion.AssertionID = "_" + Guid.NewGuid().ToString();
            assertion.Issuer = issuer.Trim();
            assertion.MajorVersion = "1";
            assertion.MinorVersion = "1";
            assertion.IssueInstant = System.DateTime.UtcNow;

            //Not before, not after conditions 
            ConditionsType conditions = new ConditionsType();
            conditions.NotBefore = DateTime.UtcNow;
            conditions.NotBeforeSpecified = true;
            conditions.NotOnOrAfter = DateTime.UtcNow.AddMinutes(10);
            conditions.NotOnOrAfterSpecified = true;
            //Name Identifier to be used in Saml Subject
            NameIdentifierType nameIdentifier = new NameIdentifierType();
            nameIdentifier.NameQualifier = domain.Trim();
            nameIdentifier.Value = subject.Trim();

            SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
            subjectConfirmation.ConfirmationMethod = new string[] { "urn:oasis:names:tc:SAML:1.0:cm:bearer" };
            // 
            // Create some SAML subject. 
            SubjectType samlSubject = new SubjectType();

            AttributeStatementType attrStatement = new AttributeStatementType();
            AuthenticationStatementType authStatement = new AuthenticationStatementType();
            authStatement.AuthenticationMethod = "urn:oasis:names:tc:SAML:1.0:am:password";
            authStatement.AuthenticationInstant = System.DateTime.UtcNow;

            samlSubject.Items = new object[] { nameIdentifier, subjectConfirmation};

            attrStatement.Subject = samlSubject;
            authStatement.Subject = samlSubject;
            
            IPHostEntry ipEntry =
                Dns.GetHostEntry(System.Environment.MachineName);

            SubjectLocalityType subjectLocality = new SubjectLocalityType();
            subjectLocality.IPAddress = ipEntry.AddressList[0].ToString();

            authStatement.SubjectLocality = subjectLocality;

            attrStatement.Attribute = new AttributeType[attributes.Count];
            int i=0;
            // Create userName SAML attributes. 
            foreach (KeyValuePair<string, string> attribute in attributes) {
                AttributeType attr = new AttributeType();
                attr.AttributeName = attribute.Key;
                attr.AttributeNamespace= domain;
                attr.AttributeValue = new object[] {attribute.Value};
                attrStatement.Attribute[i] = attr;
                i++;
            }
            assertion.Conditions = conditions;

            assertion.Items = new StatementAbstractType[] {authStatement, attrStatement};

            return assertion;

        }
        /// <summary>
        /// Returns a Base64 Encoded String with the SamlResponse in it.
        /// </summary>
        /// <param name="recipient">Recipient</param>
        /// <param name="issuer">Issuer</param>
        /// <param name="subject">Subject</param>
        /// <param name="certLocation">Certificate Location</param>
        /// <param name="certPassword">Certificate Password</param>
        /// <param name="attributes">A list of attributes to pass</param>
        /// <returns></returns>
        public static string GetPostSamlResponse(string recipient, string issuer, string domain, string subject,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes, SigningHelper.SignatureType signatureType) {
            ResponseType response = new ResponseType();
            // Create Response
            response.ResponseID = "_" + Guid.NewGuid().ToString();

            response.MajorVersion = "1";
            response.MinorVersion = "1";
            response.IssueInstant = System.DateTime.UtcNow;
            response.Recipient = recipient;

            StatusType status = new StatusType();
            
            status.StatusCode = new StatusCodeType();
            status.StatusCode.Value = new XmlQualifiedName("Success", "urn:oasis:names:tc:SAML:1.0:protocol");
            
            response.Status = status;

            // Create Assertion
            AssertionType assertionType = SamlHelper.CreateSaml11Assertion(
                issuer.Trim(), domain.Trim(), subject.Trim(), attributes);
            
            response.Assertion = new AssertionType[] {assertionType};

            //Serialize
            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            ns.Add("samlp", "urn:oasis:names:tc:SAML:1.0:protocol");
            ns.Add("saml", "urn:oasis:names:tc:SAML:1.0:assertion");
            XmlSerializer responseSerializer =
                new XmlSerializer(response.GetType());
            StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;
            settings.Encoding = Encoding.UTF8;

            XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);

            responseSerializer.Serialize(responseWriter, response, ns);
            responseWriter.Close();

            string samlString = stringWriter.ToString();
            stringWriter.Close();
            // Sign the document
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlString);
            X509Certificate2 cert = null;
            if (System.IO.File.Exists(certFile)) {
                cert = new X509Certificate2(certFile, certPassword);
            } else {
                X509Store store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection coll = store.Certificates.Find(findType, findValue, true);
                if (coll.Count <1) {
                    throw new ArgumentException("Unable to locate certificate");
                }
                cert = coll[0];
                store.Close();
            }
            XmlElement signature = SigningHelper.SignDoc(
                doc, cert, "ResponseID", response.ResponseID);

            doc.DocumentElement.InsertBefore(signature,
                doc.DocumentElement.ChildNodes[0]);

            if (SamlHelper.Logger.IsDebugEnabled) {
                SamlHelper.Logger.DebugFormat(
                    "Saml Assertion before encoding = {0}",
                    doc.OuterXml.ToString());
            }
            // Base64Encode and URL Encode
            byte[] base64EncodedBytes =
                Encoding.UTF8.GetBytes(doc.OuterXml);

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
        public static string GetPostSamlResponse(string recipient, string issuer, string domain, string subject,
            StoreLocation storeLocation, StoreName storeName, X509FindType findType, string certFile, string certPassword, object findValue,
            Dictionary<string, string> attributes) {
            return GetPostSamlResponse(recipient, issuer, domain, subject, storeLocation, storeName, findType, certFile, certPassword, findValue, attributes,
                SigningHelper.SignatureType.Response);
        }

    }
}
