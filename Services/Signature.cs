using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Commons.Bouncycastle.Crypto;
using iText.Forms.Form.Element;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Layout.Borders;
using iText.Signatures;
using Org.BouncyCastle.Pkcs;

namespace sign.Services;

public class Signature : ISignature
{
    protected static readonly String CERT_PATH = "keys/openssl.pfx";

    public MemoryStream Sign(MemoryStream src)
    {
        ElectronicSignatureInfoDTO signatureInfo = new ElectronicSignatureInfoDTO();
        signatureInfo.Bottom = 25;
        signatureInfo.Left = 25;
        signatureInfo.PageNumber = 1;

        return SignDocumentSignature(src, signatureInfo);
    }


    protected MemoryStream SignDocumentSignature(MemoryStream src, ElectronicSignatureInfoDTO signatureInfo)
    {
        var output = new MemoryStream();

        src.Position = 0;
        output.Position = 0;

        var reader = new PdfReader(src);

        PdfSigner pdfSigner = new PdfSigner(reader, output, new StampingProperties());
        pdfSigner.SetCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);

        // Set the name indicating the field to be signed.
        // The field can already be present in the document but shall not be signed
        pdfSigner.SetFieldName("signature");

        SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.GetFieldName())
                .SetContent("Firmado digitalmente por \n Sistema de cursos \n " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"))
                .SetFontSize(10);

        pdfSigner
            .SetPageNumber(signatureInfo.PageNumber)
            .SetPageRect(new Rectangle(signatureInfo.Left, signatureInfo.Bottom, 160, 80))
            .SetSignatureAppearance(appearance);

        char[] password = "123456".ToCharArray();
        IExternalSignature pks = GetPrivateKeySignature(CERT_PATH, password);
        IX509Certificate[] chain = GetCertificateChain(CERT_PATH, password);
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
        OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(ocspVerifier);
        List<ICrlClient> crlClients = new List<ICrlClient>(new[] {new CrlClientOnline()});

        
        // Sign the document using the detached mode, CMS or CAdES equivalent.
        // This method closes the underlying pdf document, so the instance
        // of PdfSigner cannot be used after this method call
        pdfSigner.SignDetached(pks, chain, crlClients, ocspClient, null, 0, PdfSigner.CryptoStandard.CMS);

        return output;
    }

    /// Method reads pkcs12 file's first private key and returns a
    /// <see cref="PrivateKeySignature"/> instance, which uses SHA-512 hash algorithm. 
    private PrivateKeySignature GetPrivateKeySignature(String certificatePath, char[] password)
    {
        String? alias = null;
        Pkcs12Store pk12 = new Pkcs12StoreBuilder().Build();
        pk12.Load(new FileStream(certificatePath, FileMode.Open, FileAccess.Read), password);

        foreach (var a in pk12.Aliases)
        {
            alias = ((String) a);
            if (pk12.IsKeyEntry(alias))
            {
                break;
            }
        }

        IPrivateKey pk = new PrivateKeyBC(pk12.GetKey(alias).Key);
        return new PrivateKeySignature(pk, DigestAlgorithms.SHA512);
    }

    /// Method reads first public certificate chain
    private IX509Certificate[] GetCertificateChain(String certificatePath, char[] password)
    {
        IX509Certificate[] chain;
        String? alias = null;
        Pkcs12Store pk12 = new Pkcs12StoreBuilder().Build();
        pk12.Load(new FileStream(certificatePath, FileMode.Open, FileAccess.Read), password);

        foreach (var a in pk12.Aliases)
        {
            alias = ((String) a);
            if (pk12.IsKeyEntry(alias))
            {
                break;
            }
        }

        X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
        chain = new IX509Certificate[ce.Length];
        for (int k = 0; k < ce.Length; ++k)
        {
            chain[k] = new X509CertificateBC(ce[k].Certificate);
        }

        return chain;
    }

    protected class ElectronicSignatureInfoDTO
    {
        public int PageNumber { get; set; }

        public float Left { get; set; }

        public float Bottom { get; set; }
    }

}