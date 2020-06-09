package awsv4;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

public final class AmazonSignatureV4Utils
{
    private static final String SCHEME = "AWS4";
    private static final String AWS4_TERMINATOR = "aws4_request";

    private static final String[] ENCODED_CHARACTERS_WITH_SLASHES = new String[] {"+", "*", "%7E", "%2F"};
    private static final String[] ENCODED_CHARACTERS_WITH_SLASHES_REPLACEMENTS = new String[] {"%20", "%2A", "~", "/"};

    private static final String[] ENCODED_CHARACTERS_WITHOUT_SLASHES = new String[] {"+", "*", "%7E"};
    private static final String[] ENCODED_CHARACTERS_WITHOUT_SLASHES_REPLACEMENTS = new String[] {"%20", "%2A", "~"};

    private AmazonSignatureV4Utils()
    {}

    protected static String getCanonicalURI(URI endpoint)
    {
        return getCanonicalURI(endpoint, true);
    }

    protected static String getCanonicalURI(URI endpoint, boolean doubleEncoded)
    {
        if (endpoint == null)
        {
            return "/";
        }
        String encodedPath = endpoint.getRawPath();
        if (StringUtils.isEmpty(encodedPath))
        {
            return "/";
        }

        return getCanonicalURI(encodedPath, doubleEncoded);
    }

    protected static String getCanonicalURI(String encodedPath, boolean doubleEncoded)
    {
        final String value = doubleEncoded? urlEncodeKeepSlash(encodedPath) : encodedPath;
        if (value.startsWith("/"))
        {
            return value;
        }
        else
        {
            return "/".concat(value);
        }
    }

    protected static String urlEncodeKeepSlash(String url)
    {
        return urlEncode(url, true);
    }

    protected static String urlEncode(String url)
    {
        return urlEncode(url, false);
    }

    private static String urlEncode(String url, boolean keepSlash)
    {
        if(url == null)
        {
            return null;
        }

        try
        {
            String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8.name());
            if(keepSlash)
            {
                return StringUtils.replaceEach(encoded, ENCODED_CHARACTERS_WITH_SLASHES, ENCODED_CHARACTERS_WITH_SLASHES_REPLACEMENTS);
            }
            return StringUtils.replaceEach(encoded, ENCODED_CHARACTERS_WITHOUT_SLASHES, ENCODED_CHARACTERS_WITHOUT_SLASHES_REPLACEMENTS);
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException(StandardCharsets.UTF_8.name() + " encoding is not supported.", e);
        }
    }

    protected static String getCanonicalQueryString(Map<String, List<String>> queryParameters)
    {
        if (queryParameters == null || queryParameters.isEmpty())
        {
            return "";
        }

        Map<String, List<String>> sortedParameters = new TreeMap<>();

        List<String> paramValues;
        List<String> encodedParamValues;

        for(Map.Entry<String, List<String>> param : queryParameters.entrySet())
        {
            paramValues = param.getValue();

            if (paramValues == null || paramValues.isEmpty()) // This parameter has no value, use empty string as value.
            {
                paramValues = Arrays.asList("");
            }

            encodedParamValues = new ArrayList<>(paramValues.size());
            for(String paramValue : paramValues)
            {
                encodedParamValues.add(urlEncode(paramValue == null? "" : paramValue));
            }

            if (encodedParamValues.size() > 1) // This parameter has multiple values, so sort values.
            {
                Collections.sort(encodedParamValues);
            }

            sortedParameters.put(urlEncode(param.getKey()), encodedParamValues);
        }

        StringBuilder sb = new StringBuilder();

        for(Map.Entry<String, List<String>> sortedParam : sortedParameters.entrySet())
        {
            for (String paramValue : sortedParam.getValue())
            {
                if(sb.length() > 1)
                {
                    sb.append('&');
                }
                sb.append(sortedParam.getKey()).append('=').append(paramValue);
            }
        }

        return sb.toString();
    }

    static String getCanonicalHeaders(Map<String, List<String>> filteredSigningHeaders)
    {
        if (filteredSigningHeaders == null || filteredSigningHeaders.isEmpty())
        {
            return "";
        }

        StringBuilder builder = new StringBuilder();

        filteredSigningHeaders.forEach((headerName, headerValues) -> {
//            /*
//                 TODO header name
//                      官方文件：去掉前後空白
//                      aws-sdk2：連續空白轉成單一空白
//            */
//            appendCompactedString(builder, headerName);
//            builder.append(':');
//
//            /*
//                TODO header value
//                     官方文件：header有多value時，用逗號連接 + 連續空白轉成單一空白
//                             eg: multi-header:v1,v2
//                     aws-sdk2：header有多value時，一個header name對應一個 header value。連續空白轉成單一空白
//                               eg: multi-header:v1\nmulti-header:v2
//             */
//            appendCompactedString(builder, StringUtils.join(headerValues, ','));
//            builder.append('\n');

            for (String headerValue : headerValues) {
                appendCompactedString(builder, headerName);
                builder.append(":");
                if (headerValue != null) {
                    appendCompactedString(builder, headerValue);
                }
                builder.append("\n");
            }
        });

        return builder.toString();
    }

    /**
     * This method appends a string to a string builder and collapses contiguous
     * white space is a single space.
     *
     * This is equivalent to:
     *      destination.append(source.replaceAll("\\s+", " "))
     * but does not create a Pattern object that needs to compile the match
     * string; it also prevents us from having to make a Matcher object as well.
     *
     */
    private static void appendCompactedString(final StringBuilder destination, final String source) {
        boolean previousIsWhiteSpace = false;
        int length = source.length();

        for (int i = 0; i < length; i++) {
            char ch = source.charAt(i);
            if (isWhiteSpace(ch)) {
                if (previousIsWhiteSpace) {
                    continue;
                }
                destination.append(' ');
                previousIsWhiteSpace = true;
            } else {
                destination.append(ch);
                previousIsWhiteSpace = false;
            }
        }
    }

    /**
     * Tests a char to see if is it whitespace.
     * This method considers the same characters to be white
     * space as the Pattern class does when matching \s
     *
     * @param ch the character to be tested
     * @return true if the character is white  space, false otherwise.
     */
    private static boolean isWhiteSpace(final char ch) {
        return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\u000b' || ch == '\r' || ch == '\f';
    }

    static String getSignedHeaders(Map<String, List<String>> filteredSigningHeaders)
    {
        if (filteredSigningHeaders == null || filteredSigningHeaders.isEmpty())
        {
            return "";
        }

        return StringUtils.join(filteredSigningHeaders.keySet(), ";");
    }

    static String getCanonicalRequest(String httpRequestMethod,
                                      String canonicalURI,
                                      String canonicalQueryString,
                                      String canonicalHeaders,
                                      String signedHeaders,
                                      String hashedPayload)
    {
        StringBuilder builder = new StringBuilder();
        builder.append(httpRequestMethod).append('\n');
        builder.append(canonicalURI).append('\n');
        builder.append(canonicalQueryString).append('\n');
        builder.append(canonicalHeaders).append('\n');
        builder.append(signedHeaders).append('\n');
        builder.append(hashedPayload);

        return builder.toString();
    }

    /**
     * Do message digest hash.
     *
     * @param data the raw data to hash.
     * @param algorithm messageDigest algorithm, eg. SHA-256.
     * @return hashed value.
     * @throws NoSuchAlgorithmException if specified algorithm is not supported.
     */
    protected static byte[] hash(byte[] data, String algorithm) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(normalizeMessageDigestAlgorithm(algorithm));
        md.update(data);
        return md.digest();
    }

    private static String normalizeMessageDigestAlgorithm(String algorithm)
    {
        String normalizedAlgorithm = algorithm.toLowerCase();
        if(normalizedAlgorithm.startsWith("sha") && !normalizedAlgorithm.startsWith("sha-"))
        {
            normalizedAlgorithm = normalizedAlgorithm.replaceFirst("sha", "sha-");
        }

        return normalizedAlgorithm.toUpperCase(); //No need to upper case, but for good looking.
    }

    static String getCredentialScope(String dateStamp, String regionName, String serviceName)
    {
        StringBuilder builder = new StringBuilder();
        builder.append(dateStamp).append('/');
        builder.append(regionName).append('/');
        builder.append(serviceName).append('/');
        builder.append(AWS4_TERMINATOR);

        return builder.toString();
    }

    /**
     * @param hmacAlgorithm Eg. "HMAC-SHA256"
     * @param dateTimeStamp date time string with "yyyyMMdd'T'HHmmss'Z'" of ISO8601 format.
     * @param credentialScope
     * @param canonicalRequest
     * @return
     * @throws NoSuchAlgorithmException
     */
    static String getStringToSign(String hmacAlgorithm, String dateTimeStamp, String credentialScope, String canonicalRequest) throws NoSuchAlgorithmException
    {
        StringBuilder builder = new StringBuilder();
        builder.append(SCHEME).append('-').append(hmacAlgorithm).append('\n');
        builder.append(dateTimeStamp).append('\n');
        builder.append(credentialScope).append('\n');

        final String messageDigestAlgorithm = normalizeHmacAlgorithm(hmacAlgorithm).replaceFirst("hmac", "");

        builder.append(Hex.encodeHexString(hash(canonicalRequest.getBytes(StandardCharsets.UTF_8), messageDigestAlgorithm)));

        return builder.toString();
    }

    private static String normalizeHmacAlgorithm(String hmacAlgorithm)
    {
        String normalizedAlgorithm = hmacAlgorithm.toLowerCase();
        normalizedAlgorithm = normalizedAlgorithm.replaceFirst("-", "");

        return normalizedAlgorithm;
    }

    private static byte[] hmac(String hmacAlgorithm, byte[] key, String data) throws Exception
    {
        String normalizedHmacAlgorithm = normalizeHmacAlgorithm(hmacAlgorithm);
        Mac mac = Mac.getInstance(normalizedHmacAlgorithm);
        mac.init(new SecretKeySpec(key, normalizedHmacAlgorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] getSigningKey(String hmacAlgorithm, String secretAccesskey, String dateStamp, String regionName, String serviceName) throws Exception
    {
        byte[] kSecret = (SCHEME + secretAccesskey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmac(hmacAlgorithm, kSecret, dateStamp);
        byte[] kRegion = hmac(hmacAlgorithm, kDate, regionName);
        byte[] kService = hmac(hmacAlgorithm, kRegion, serviceName);
        byte[] kSigning = hmac(hmacAlgorithm, kService, AWS4_TERMINATOR);
        return kSigning;
    }

    /**
     * 跟 software.amazon.awssdk.auth.signer.internal.AbstractAws4Signer#canonicalizeSigningHeaders(java.util.Map) 不同
     */
    private static Map<String, List<String>> filterSigningHeaders(Map<String, List<String>> rawHeaders)
    {
        Map<String, List<String>> filteredHeaders = new TreeMap<>();

        for (Map.Entry<String, List<String>> rawHeader : rawHeaders.entrySet()) {
            String lowerCaseHeader = rawHeader.getKey().toLowerCase();
            if ("host".equals(lowerCaseHeader) || lowerCaseHeader.startsWith("x-")) { //TODO maybe start with "x-asc"
                filteredHeaders.computeIfAbsent(lowerCaseHeader, x -> new ArrayList<>()).addAll(rawHeader.getValue());
            }
        }

        return filteredHeaders;
    }

    public static String getSignature(String algorithmm,
                                      String dateStamp,
                                      String regionName,
                                      String serviceName,
                                      URI endpointURI,
                                      String httpRequestMethod,
                                      Map<String, List<String>> queryParameters,
                                      Map<String, List<String>> rawHeaders,
                                      String payload,
                                      String secretAccesskey) throws Exception
    {
        final String canonicalURI = getCanonicalURI(endpointURI);
        System.out.println("canonicalURI = " + canonicalURI);

        final String canonicalQueryString = getCanonicalQueryString(queryParameters);
        System.out.println("canonicalQueryString = " + canonicalQueryString);

        Map<String, List<String>> filteredSigningHeaders = filterSigningHeaders(rawHeaders);
        final String canonicalHeaders = getCanonicalHeaders(filteredSigningHeaders);
        System.out.println("canonicalHeaders = " + canonicalHeaders);
        final String signedHeaders = getSignedHeaders(filteredSigningHeaders);
        System.out.println("signedHeaders = " + signedHeaders);

        final String hashedPayload = Hex.encodeHexString(hash(payload == null? "".getBytes() : payload.getBytes(StandardCharsets.UTF_8), "SHA-256") );
        System.out.println("hashedPayload = " + hashedPayload);

        final String canonicalRequest = getCanonicalRequest(httpRequestMethod, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload);
        System.out.println("canonicalRequest = " + canonicalRequest);

        final String credentialScope = getCredentialScope(dateStamp, regionName, serviceName);
        System.out.println("credentialScope = " + credentialScope);

        final String dateTimeStamp = rawHeaders.get("X-Amz-Date").get(0);
        System.out.println("dateTimeStamp = " + dateTimeStamp);

        final String stringToSign = getStringToSign(algorithmm, dateTimeStamp, credentialScope, canonicalRequest);
        System.out.println("stringToSign = " + stringToSign);

        byte[] signingKey = getSigningKey(algorithmm, secretAccesskey, dateStamp, regionName, serviceName);
        System.out.println("signingKey = " + Hex.encodeHexString(signingKey));

        final String signature = Hex.encodeHexString(hmac(algorithmm, signingKey, stringToSign));
        System.out.println("signature = " + signature);

        return signature;
    }
}
