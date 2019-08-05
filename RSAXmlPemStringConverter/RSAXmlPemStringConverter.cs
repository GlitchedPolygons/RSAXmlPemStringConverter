using System;
using System.IO;
using System.Xml;
using System.Text;
using System.Security.Cryptography;

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace GlitchedPolygons.ExtensionMethods.RSAXmlPemStringConverter
{
    /// <summary>
    /// Extension method class for converting <c>string</c> RSA keys from and to the xml/pem formats.
    /// </summary>
    public static class RSAXmlPemStringConverter
    {
        /// <summary>
        /// Returns the specified XML RSA key <c>string</c> converted to the PEM format.
        /// </summary>
        /// <param name="xml">The XML <c>string</c> containing the RSA key.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="InvalidKeyException">Invalid XML RSA Key</exception>
        public static string XmlToPem(this string xml)
        {
            using (var rsa = RSA.Create())
            {
                rsa.FromXmlStringNetCore(xml);

                // Try to get the private and public key pair first.
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                if (keyPair != null)
                {
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
                    return FormatPem(Convert.ToBase64String(privateKeyInfo.GetEncoded()), "RSA PRIVATE KEY");
                }

                // At this point, the XML RSA key contains only the public key.
                RsaKeyParameters publicKey = DotNetUtilities.GetRsaPublicKey(rsa);
                if (publicKey != null)
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                    return FormatPem(Convert.ToBase64String(publicKeyInfo.GetEncoded()), "PUBLIC KEY");
                }
            }

            throw new InvalidKeyException("Invalid XML RSA Key");
        }

        /// <summary>
        /// Returns the specified RSA key (PEM <c>string</c>) converted to XML.
        /// </summary>
        /// <param name="pem">The PEM <c>string</c> to convert to XML.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="InvalidKeyException">Unsupported PEM format</exception>
        public static string PemToXml(this string pem)
        {
            if (pem.StartsWith("-----BEGIN RSA PRIVATE KEY-----") || pem.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return FormatXml(pem, obj =>
                {
                    if (obj is RsaPrivateCrtKeyParameters privateKey)
                    {
                        return DotNetUtilities.ToRSA(privateKey);
                    }
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlStringNetCore(true));
            }

            if (pem.StartsWith("-----BEGIN RSA PUBLIC KEY-----") || pem.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return FormatXml(pem, obj =>
                {
                    var publicKey = (RsaKeyParameters)obj;
                    return DotNetUtilities.ToRSA(publicKey);
                }, rsa => rsa.ToXmlStringNetCore(false));
            }

            throw new InvalidKeyException("Invalid PEM format");
        }

        private static string FormatPem(string pem, string keyType)
        {
            var stringBuilder = new StringBuilder(512);
            stringBuilder.AppendFormat("-----BEGIN {0}-----\n", keyType);

            int line = 1;
            const int WIDTH = 64;
            while ((line - 1) * WIDTH < pem.Length)
            {
                int startIndex = (line - 1) * WIDTH;
                int length = line * WIDTH > pem.Length
                    ? pem.Length - startIndex
                    : WIDTH;
                stringBuilder.AppendFormat("{0}\n", pem.Substring(startIndex, length));
                line++;
            }

            return stringBuilder.AppendFormat("-----END {0}-----\n", keyType).ToString();
        }

        private static string FormatXml(string pem, Func<object, RSA> getRsa, Func<RSA, string> getKey)
        {
            using (var memoryStream = new MemoryStream())
            using (var streamWriter = new StreamWriter(memoryStream))
            using (var streamReader = new StreamReader(memoryStream))
            {
                streamWriter.Write(pem);
                streamWriter.Flush();
                memoryStream.Position = 0;
                var pemReader = new PemReader(streamReader);
                object keyPair = pemReader.ReadObject();
                using (var rsa = getRsa.Invoke(keyPair))
                {
                    return getKey.Invoke(rsa);
                }
            }
        }

        /// <summary>
        /// Converts an <see cref="RSA"/> instance to a portable xml <c>string</c>.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance whose key params you want to export to a portable xml <c>string</c>.</param>
        /// <param name="includePrivateParameters">Should the private key be exported?</param>
        /// <returns>The exported RSA key <c>string</c> in portable xml.</returns>
        public static string ToXmlStringNetCore(this RSA rsa, bool includePrivateParameters = false)
        {
            try
            {
                var rsaParameters = rsa.ExportParameters(includePrivateParameters);

                if (includePrivateParameters)
                {
                    return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                        Convert.ToBase64String(rsaParameters.Modulus),
                        Convert.ToBase64String(rsaParameters.Exponent),
                        Convert.ToBase64String(rsaParameters.P),
                        Convert.ToBase64String(rsaParameters.Q),
                        Convert.ToBase64String(rsaParameters.DP),
                        Convert.ToBase64String(rsaParameters.DQ),
                        Convert.ToBase64String(rsaParameters.InverseQ),
                        Convert.ToBase64String(rsaParameters.D)
                    );
                }

                return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                    Convert.ToBase64String(rsaParameters.Modulus),
                    Convert.ToBase64String(rsaParameters.Exponent)
                );
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Imports an xml <c>string</c> that was obtained using <see cref="ToXmlStringNetCore"/> into an <see cref="RSA"/> instance.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance to import the key into.</param>
        /// <param name="xmlString">The xml <c>string</c> that contains the RSA key to import.</param>
        public static void FromXmlStringNetCore(this RSA rsa, string xmlString)
        {
            var rsaParameters = new RSAParameters();

            var xml = new XmlDocument();
            xml.LoadXml(xmlString);

            if (xml.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xml.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": rsaParameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                        case "Exponent": rsaParameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        case "P": rsaParameters.P = Convert.FromBase64String(node.InnerText); break;
                        case "Q": rsaParameters.Q = Convert.FromBase64String(node.InnerText); break;
                        case "DP": rsaParameters.DP = Convert.FromBase64String(node.InnerText); break;
                        case "DQ": rsaParameters.DQ = Convert.FromBase64String(node.InnerText); break;
                        case "InverseQ": rsaParameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                        case "D": rsaParameters.D = Convert.FromBase64String(node.InnerText); break;
                    }
                }
            }
            else
            {
                throw new InvalidKeyException("Invalid XML RSA key.");
            }

            rsa.ImportParameters(rsaParameters);
        }
    }
}
