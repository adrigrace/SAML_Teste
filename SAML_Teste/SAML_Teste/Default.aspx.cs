using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

using SecurityTokenTypes = Microsoft.IdentityModel.Tokens.SecurityTokenTypes; 

namespace SAML_Teste
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        #region Configuration Information

        private const int tokenLifetime = 1; // In minutes. 
        private const string issuer = "localhost:default:idp:entityId";
        private const string appliesTo = "localhost:default:sp:entityId"; // Audience restriction 
        protected const string assertionConsumerEndpoint = "https://localhost:9031/sp/ACS.saml2";
        private const string signingCertCommonName = "CN=Adriana Maria Marques";
        private static readonly Dictionary<string, string> claimDescriptors = new Dictionary<string, string>  
    {  
        { "FooUrl", "https://localhost:51374/SpSample/?foo=bar" }, 
        { ClaimTypes.Anonymous, "33" }, 
        { ClaimTypes.NameIdentifier, "joe" }, 
    };

        #endregion

        protected void Page_Load(object sender, EventArgs e)
        {
            var samlResponse = CreateSamlResponse();

            SAMLResponse.Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponse));
        }

        private string CreateSamlResponse()
        {
            var claims = CreateClaims();
            var tokenHandler = new Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler(); ;
            var token = CreateToken(claims, tokenHandler);

            return CreateSamlResponseXml(tokenHandler, token);
        }

        private static Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken CreateToken(IEnumerable<Claim> claims,
            Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler tokenHandler)
        {
            var descriptor = CreateTokenDescriptor(claims);
            var token = tokenHandler.CreateToken(descriptor) as Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken;

            AddAuthenticationStatement(token);
            AddConfirmationData(token);

            return token;
        }

        private static void AddConfirmationData(Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken token)
        {
            var confirmationData = new Microsoft.IdentityModel.Tokens.Saml2.Saml2SubjectConfirmationData
            {
                Recipient = new Uri(assertionConsumerEndpoint),
                NotOnOrAfter = DateTime.UtcNow.AddMinutes(tokenLifetime),
            };

            token.Assertion.Subject.SubjectConfirmations.Add(new Microsoft.IdentityModel.Tokens.Saml2.Saml2SubjectConfirmation(
                Saml2Constants.ConfirmationMethods.Bearer, confirmationData));
        }

        private static void AddAuthenticationStatement(Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken token)
        {
            // Chage to "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" or something. 
            var authenticationMethod = "urn:none";

            var authenticationContext = new Microsoft.IdentityModel.Tokens.Saml2.Saml2AuthenticationContext(new Uri(authenticationMethod));
            var authenticationStatement = new Microsoft.IdentityModel.Tokens.Saml2.Saml2AuthenticationStatement(authenticationContext);

            token.Assertion.Statements.Add(authenticationStatement);
        }

        private static string CreateSamlResponseXml(Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler tokenHandler, Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken token)
        {
            var buffer = new StringBuilder();

            using (var stringWriter = new StringWriter(buffer))
            using (var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings()))
            {
                xmlWriter.WriteStartElement("Response", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("IssueInstant", DateTime.UtcNow.ToString("s"));
                xmlWriter.WriteAttributeString("ID", "_" + Guid.NewGuid());
                xmlWriter.WriteAttributeString("Version", "2.0");

                xmlWriter.WriteStartElement("Status");
                xmlWriter.WriteStartElement("StatusCode");
                xmlWriter.WriteAttributeString("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
                xmlWriter.WriteEndElement();
                xmlWriter.WriteEndElement();

                tokenHandler.WriteToken(xmlWriter, token);

                xmlWriter.WriteEndElement();
            }

            return buffer.ToString();
        }

        private static Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor CreateTokenDescriptor(IEnumerable<Claim> claims)
        {
            var descriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor()
            {
                TokenType = SecurityTokenTypes.OasisWssSaml2TokenProfile11,
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(1)),
                AppliesToAddress = appliesTo,
                TokenIssuerName = issuer,
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = GetSigningCredentials(),
            };

            return descriptor;
        }

        private static SigningCredentials GetSigningCredentials()
        {

            //var signingCert = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.CurrentUser, signingCertCommonName);

            //var signingCert = CertificateUtil.GetCertificate
            //    (StoreName.My,
            //    StoreLocation.CurrentUser, "Adriana Maria Marques");

            //var signingCert = CertificateUtil.GetCertificate(StoreName.CertificateAuthority, 
            //    StoreLocation.CurrentUser, "_NOT_TRUST_FiddlerRoot");

            var signingCert = CertificateUtil.GetCertificate(StoreName.My,
                StoreLocation.CurrentUser, "Adriana Maria Marques");

            return new Microsoft.IdentityModel.SecurityTokenService.X509SigningCredentials(signingCert);

            
        }

        private static IEnumerable<Claim> CreateClaims()
        {
            foreach (var claimDescriptor in claimDescriptors)
            {
                yield return new Claim(claimDescriptor.Key, claimDescriptor.Value);
            }
        }
    }
}