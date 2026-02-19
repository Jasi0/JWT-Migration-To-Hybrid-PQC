package com.example.app;

import com.example.common.Base64Url;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Utility to compute exact header/payload/signature sizes (raw and Base64URL) for compact JWTs
 * and append a CSV row to target/token_sizes.csv.
 *
 * CSV columns:
 * label,header_raw_bytes,payload_raw_bytes,signature_raw_bytes,header_b64_chars,payload_b64_chars,signature_b64_chars
 *
 * - raw_bytes are computed after Base64URL decoding of each segment
 * - b64_chars are simply the string lengths of the corresponding Base64URL segments
 */
public final class TokenSizeReport {

    private static final Path CSV_PATH = Path.of("target", "token_sizes.csv");
    private static final String HEADER = "label,header_raw_bytes,payload_raw_bytes,signature_raw_bytes,header_b64_chars,payload_b64_chars,signature_b64_chars\n";

    private TokenSizeReport() {
        // utility
    }

    public static void appendRow(String label, String compactToken) {
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("label must not be null/empty");
        }
        if (compactToken == null || compactToken.isEmpty()) {
            throw new IllegalArgumentException("compactToken must not be null/empty");
        }
        String[] parts = compactToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Token must have 3 parts");
        }

        byte[] headerRaw = Base64Url.decode(parts[0]);
        byte[] payloadRaw = Base64Url.decode(parts[1]);
        byte[] signatureRaw = Base64Url.decode(parts[2]);

        int headerRawBytes = headerRaw.length;
        int payloadRawBytes = payloadRaw.length;
        int signatureRawBytes = signatureRaw.length;

        int headerB64Chars = parts[0].length();
        int payloadB64Chars = parts[1].length();
        int signatureB64Chars = parts[2].length();

        String line = String.join(",",
                escape(label),
                Integer.toString(headerRawBytes),
                Integer.toString(payloadRawBytes),
                Integer.toString(signatureRawBytes),
                Integer.toString(headerB64Chars),
                Integer.toString(payloadB64Chars),
                Integer.toString(signatureB64Chars)
        ) + "\n";

        try {
            ensureHeader();
            Files.writeString(CSV_PATH, line, StandardCharsets.UTF_8,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write token size CSV", e);
        }
    }

    private static void ensureHeader() throws IOException {
        if (!Files.exists(CSV_PATH)) {
            Files.createDirectories(CSV_PATH.getParent());
            Files.writeString(CSV_PATH, HEADER, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        }
    }

    private static String escape(String v) {
        // minimal CSV escape: wrap in quotes if contains comma or quote, double quotes inside
        if (v.contains(",") || v.contains("\"")) {
            return "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }
}