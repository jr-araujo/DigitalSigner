using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSigner
{
    public class DigitalSignerA1
    {
        #region
        protected FileStream PrivateKey { get; set; }
        #endregion

        public DigitalSignerA1(string certificatePath)
        {
            this.PrivateKey = new FileStream(certificatePath, FileMode.Open);
        }

        public void ApplySignatureToPDF(string sourcePDF, string pathSignedPDF, string certificatePassword)
        {
            SignPdf(sourcePDF, pathSignedPDF, this.PrivateKey, certificatePassword, "", "");
        }

        /// <summary>
        /// Signs a PDF document using iTextSharp library
        /// </summary>
        /// <param name="sourceDocument">The path of the source pdf document which is to be signed</param>
        /// <param name="destinationPath">The path at which the signed pdf document should be generated</param>
        /// <param name="privateKeyStream">A Stream containing the private/public key in .pfx format which would be used to sign the document</param>
        /// <param name="keyPassword">The password for the private key</param>
        /// <param name="reason">String describing the reason for signing, would be embedded as part of the signature</param>
        /// <param name="location">Location where the document was signed, would be embedded as part of the signature</param>
        private void SignPdf(string sourceDocument, string destinationPath, Stream privateKeyStream, string keyPassword, string reason, string location)
        {
            Pkcs12Store pk12 = new Pkcs12Store(privateKeyStream, keyPassword.ToCharArray());
            privateKeyStream.Dispose();

            //then Iterate throught certificate entries to find the private key entry
            string alias = null;
            foreach (string tAlias in pk12.Aliases)
            {
                if (pk12.IsKeyEntry(tAlias))
                {
                    alias = tAlias;
                    break;
                }
            }

            var pk = pk12.GetKey(alias).Key;

            // reader and stamper
            PdfReader reader = new PdfReader(sourceDocument);

            using (FileStream fout = new FileStream(destinationPath, FileMode.Create, FileAccess.ReadWrite))
            {
                using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fout, '\0'))
                {
                    // appearance
                    PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                    //appearance.Image = new iTextSharp.text.pdf.PdfImage();
                    appearance.Reason = reason;
                    appearance.Location = location;
                    appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(20, 10, 170, 60), 1, "Icsi-Vendor");
                    // digital signature
                    IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
                    MakeSignature.SignDetached(appearance, es, new X509Certificate[] { pk12.GetCertificate(alias).Certificate }, null, null, null, 0, CryptoStandard.CMS);

                    stamper.Close();
                }
            }
        }

        /// <summary>
        /// Verifies the signature of a prevously signed PDF document using the specified public key
        /// </summary>
        /// <param name="pdfFile">a Previously signed pdf document</param>
        /// <param name="publicKeyStream">Public key to be used to verify the signature in .cer format</param>
        /// <exception cref="System.InvalidOperationException">Throw System.InvalidOperationException if the document is not signed or the signature could not be verified</exception>
        public void VerifyPdfSignature(string pdfFile, Stream publicKeyStream)
        {
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(publicKeyStream);
            publicKeyStream.Dispose();

            PdfReader reader = new PdfReader(pdfFile);
            AcroFields af = reader.AcroFields;
            var names = af.GetSignatureNames();

            if (names.Count == 0)
            {
                throw new InvalidOperationException("No Signature present in pdf file.");
            }

            foreach (string name in names)
            {
                if (!af.SignatureCoversWholeDocument(name))
                {
                    throw new InvalidOperationException(string.Format("The signature: {0} does not covers the whole document.", name));
                }

                PdfPKCS7 pk = af.VerifySignature(name);
                var cal = pk.SignDate;
                var pkc = pk.Certificates;

                if (!pk.Verify())
                {
                    throw new InvalidOperationException("The signature could not be verified.");
                }
                if (!pk.VerifyTimestampImprint())
                {
                    throw new InvalidOperationException("The signature timestamp could not be verified.");
                }

                List<VerificationException> fails = CertificateVerification.VerifyCertificates(pkc, new X509Certificate[] { certificate }, null, cal).ToList();

                if (fails != null)
                {
                    throw new InvalidOperationException("The file is not signed using the specified key-pair.");
                }
            }
        }
    }
}
