package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import io.github.vvb2060.keyattestation.AppApplication;

public class ProvisioningInfo {
    private static final String OID = "1.3.6.1.4.1.11129.2.1.30";

    private Integer certsIssued;
    private String manufacturer;
    private String validatedAttestedEntity;
    private String vbMetaApproval;
    private String vbMetaDigest;
    private String buildFingerprintApproval;
    private String buildFingerprint;
    private Boolean lostDevice;

    private ProvisioningInfo(Map map) {
        for (var key : map.getKeys()) {
            String path = "provisioning";
            try {
                int tag = intValueExact((Number) key);
                path += "." + tag;
                switch (tag) {
                    case 1 -> certsIssued = intValueExact((Number) map.get(key));
                    case 3 -> manufacturer = CborUtils.getUnicodeString(map, key);
                    case 4 -> validatedAttestedEntity = CborUtils.getUnicodeString(map, key);
                    case 5 -> parseBuildInfo((Map) map.get(key));
                    case 6 -> lostDevice = CborUtils.getBoolean(map, key);
                    default -> Log.w(AppApplication.TAG, "Unknown " + path + ": "
                            + map.get(key).getClass().getSimpleName());
                }
            } catch (RuntimeException e) {
                Log.w(AppApplication.TAG, "Invalid " + path + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void parseBuildInfo(Map map) {
        // shortcut: key 5 follows observed certificates, update if its schema changes.
        for (var key : map.getKeys()) {
            String path = "provisioning.5";
            try {
                int tag = intValueExact((Number) key);
                path += "." + tag;
                switch (tag) {
                    case 1 -> vbMetaApproval = CborUtils.getUnicodeString(map, key);
                    case 2 -> vbMetaDigest = CborUtils.getUnicodeString(map, key);
                    case 3 -> buildFingerprintApproval = CborUtils.getUnicodeString(map, key);
                    case 4 -> buildFingerprint = CborUtils.getUnicodeString(map, key);
                    default -> Log.w(AppApplication.TAG, "Unknown " + path + ": "
                            + map.get(key).getClass().getSimpleName());
                }
            } catch (RuntimeException e) {
                Log.w(AppApplication.TAG, "Invalid " + path + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private static int intValueExact(Number number) {
        var value = number.getValue();
        if (value.bitLength() > 31) {
            throw new ArithmeticException("Integer out of range");
        }
        return value.intValue();
    }

    public static ProvisioningInfo get(X509Certificate cert) {
        var bytes = cert.getExtensionValue(OID);
        if (bytes == null) return null;
        try {
            var asn1 = Asn1Utils.getAsn1EncodableFromBytes(bytes);
            var cborBytes = Asn1Utils.getByteArrayFromAsn1(asn1);
            var data = CborUtils.decodeCbor(cborBytes);
            if (!(data instanceof Map map)) {
                Log.w(AppApplication.TAG, "Invalid provisioning info type");
                return null;
            }
            return new ProvisioningInfo(map);
        } catch (CborException | CertificateParsingException | RuntimeException e) {
            Log.e(AppApplication.TAG, "Invalid provisioning info: " + e.getClass().getSimpleName());
            return null;
        }
    }

    public Integer getCertsIssued() {
        return certsIssued;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getValidatedAttestedEntity() {
        return validatedAttestedEntity;
    }

    public String getVbMetaApproval() {
        return vbMetaApproval;
    }

    public String getVbMetaDigest() {
        return vbMetaDigest;
    }

    public String getBuildFingerprintApproval() {
        return buildFingerprintApproval;
    }

    public String getBuildFingerprint() {
        return buildFingerprint;
    }

    public Boolean getLostDevice() {
        return lostDevice;
    }
}
