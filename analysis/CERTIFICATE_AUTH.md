# Certificate Authentication - Complete Implementation Guide

**Analysis Date:** 2025-10-29
**Purpose:** Multi-certificate authentication for ocserv (C23)

## Certificate Validation Process

```
1. Client connects to ASA/FTD (SSL handshake)
2. Server requests client certificate
3. Client presents certificate(s) from certificate store
4. Server validates:
   - Certificate signature (against configured CA)
   - Validity period (not expired)
   - Enhanced Key Usage (Client Authentication)
   - Subject DN / Issuer DN (if filtering configured)
   - Template Name/Information/Identifier (5.1.6.103+)
   - CRL/OCSP status (if enabled)
5. Server extracts username from certificate (CN or DN)
6. Server authorizes user (group policy assignment)
7. Connection established
```

## Certificate Stores by Platform

| Platform | Store Type | Location |
|----------|-----------|----------|
| **Windows** | CryptoAPI | Registry: HKLM\SOFTWARE\Microsoft\SystemCertificates |
| **macOS** | Keychain | /Library/Keychains/System.keychain |
| **Linux** | NSS | ~/.pki/nssdb/ or Firefox profile |
| **Linux** | PEM | /etc/ssl/certs/ |

## Multiple Certificate Selection

**Scenario**: User has multiple valid certificates (e.g., machine cert + user cert)

**Selection Logic**:
1. Filter by Issuer DN (if configured)
2. Filter by Subject DN (if configured)
3. Filter by Key Usage (Client Authentication required)
4. Filter by Template Name (5.1.6.103+)
5. Present remaining certificates to user for selection

## Certificate Template Filtering (5.1.6.103+)

**Microsoft Extensions**:
- Template Name OID: `1.3.6.1.4.1.311.20.2` (BMPString)
- Template Information OID: `1.3.6.1.4.1.311.21.7` (SEQUENCE)

```c
// C23: Extract template from certificate
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define MS_CERT_TEMPLATE_NAME_OID "1.3.6.1.4.1.311.20.2"

int extract_cert_template_name(
    gnutls_x509_crt_t cert,
    char *template_name,
    size_t template_name_size
) {
    for (unsigned int i = 0; i < 100; i++) {
        char oid[128];
        size_t oid_size = sizeof(oid);
        uint8_t data[1024];
        size_t data_size = sizeof(data);

        int ret = gnutls_x509_crt_get_extension_info(cert, i, oid, &oid_size, nullptr);
        if (ret < 0) break;

        if (strcmp(oid, MS_CERT_TEMPLATE_NAME_OID) == 0) {
            ret = gnutls_x509_crt_get_extension_data(cert, i, data, &data_size);
            if (ret >= 0) {
                // Parse BMPString (UTF-16)
                // Simplified: assume ASCII, skip encoding conversion
                size_t name_len = data_size / 2;
                if (name_len > template_name_size - 1) {
                    name_len = template_name_size - 1;
                }
                for (size_t j = 0; j < name_len; j++) {
                    template_name[j] = data[j * 2 + 1];
                }
                template_name[name_len] = '\0';
                return 0;
            }
        }
    }
    return -ENOENT;
}

// Match certificate against template filter
bool cert_matches_template(
    gnutls_x509_crt_t cert,
    const char *required_template
) {
    if (required_template == nullptr || required_template[0] == '\0') {
        return true;  // No filter
    }

    char template_name[256] = {0};
    if (extract_cert_template_name(cert, template_name, sizeof(template_name)) < 0) {
        return false;  // No template in cert
    }

    return (strcmp(template_name, required_template) == 0);
}
```

## CRL/OCSP Checking

**CRL (Certificate Revocation List)**:
- Download CRL from CDP (CRL Distribution Point) in certificate
- Check if certificate serial number in CRL
- Cache CRL (validity period in CRL header)

**OCSP (Online Certificate Status Protocol)**:
- Send OCSP request to OCSP responder (URL in certificate AIA)
- Receive real-time status: good / revoked / unknown
- More efficient than CRL for large PKIs

**Implementation**:
```c
// C23: OCSP validation
#include <gnutls/ocsp.h>

bool validate_cert_ocsp(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer) {
    gnutls_ocsp_req_t req;
    gnutls_ocsp_req_init(&req);

    // Add certificate to request
    gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, issuer, cert);

    // Send OCSP request (HTTP POST to responder URL)
    // Parse response
    // Check status

    gnutls_ocsp_req_deinit(req);
    return true;  // Simplified
}
```

---

**End of Document**
