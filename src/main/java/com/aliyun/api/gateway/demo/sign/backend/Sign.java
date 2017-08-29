/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.aliyun.api.gateway.demo.sign.backend;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 后端服务签名示例
 */
public class Sign {
    //API网关中所有参与签名计算的HTTP请求头的Key,以应为逗号分割
    private static final String CA_PROXY_SIGN_HEADERS = "X-Ca-Proxy-Signature-Headers";
    //API网关计算的签名
    private static final String CA_PROXY_SIGN = "X-Ca-Proxy-Signature";
    //API网关用于计算签名的密钥Key
    private static final String CA_PROXY_SIGN_SECRET_KEY = "X-Ca-Proxy-Signature-Secret-Key";
    //签名算法HmacSha256
    public static final String HMAC_SHA256 = "HmacSHA256";
    //换行符
    private static char LF = '\n';
    //编码
    private static final String ENCODING = "UTF-8";
    //HTTP POST
    private static final String HTTP_METHOD_POST = "post";
    //HTTP PUT
    private static final String HTTP_METHOD_PUT = "put";
    //HTTP HEADER是否转换成小写（部分WEB容器中接受到的所有HEADER的KEY都是小写）
    private static final boolean HTTP_HEADER_TO_LOWER_CASE = false;

    //签名密钥Map,用于存储多对服务端签名计算密钥,一旦正在使用的密钥泄露,只需要将密钥列表中的其他密钥配置到网关即可进行密钥热替换
    private static Map<String, String> signSecretMap = new HashMap<String, String>();

    static {
        //TODO：修改为自己的密钥组合
        signSecretMap.put("DemoKey1", "DemoSecret1");
        signSecretMap.put("DemoKey2", "DemoSecret2");
        signSecretMap.put("DemoKey3", "DemoSecret3");
    }

    /**
     * Demo
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        String uri = "/demo/uri";
        String httpMethod = "POST";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put(CA_PROXY_SIGN, "C7Lqfn8Spz0DxQTfUJq0NrkEbwNUuTNtC9p3SzRWgv0=");
        headers.put(CA_PROXY_SIGN_HEADERS, "HeaderKey1,HeaderKey2");//注意此处设置的是Demo,实际运行时,参与签名的Header需要从X-Ca-Proxy-Signature-Headers动态读取
        headers.put(CA_PROXY_SIGN_SECRET_KEY, "DemoKey1");
        headers.put("HeaderKey1", "HeaderValue1");
        headers.put("HeaderKey2", "HeaderValue2");

        Map<String, Object> paramsMap = new HashMap<String, Object>();
        paramsMap.put("QueryKey1", "QueryValue1");
        paramsMap.put("QueryKey2", "QueryValue2");
        paramsMap.put("FormKey1", "FormValue1");
        paramsMap.put("FormKey2", "FormValue2");

        byte[] inputStreamBytes = new byte[]{};

        String gatewaySign = headers.get(CA_PROXY_SIGN);
        System.out.println("API网关签名:" + gatewaySign);

        String serviceSign = serviceSign(uri, httpMethod, headers, paramsMap, inputStreamBytes);
        System.out.println("服务端签名:" + serviceSign);

        System.out.println("签名是否相同:" + gatewaySign.equals(serviceSign));
    }

    /**
     * 计算HTTP请求签名
     *
     * @param uri              原始HTTP请求PATH（不包含Query）
     * @param httpMethod       原始HTTP请求方法
     * @param headers          原始HTTP请求所有请求头
     * @param paramsMap        原始HTTP请求所有Query+Form参数
     * @param inputStreamBytes 原始HTTP请求Body体（仅当请求为POST/PUT且非表单请求才需要设置此属性,表单形式的需要将参数放到paramsMap中）
     * @return 签名结果
     * @throws Exception
     */
    public static String serviceSign(String uri, String httpMethod, Map<String, String> headers, Map<String, Object> paramsMap, byte[] inputStreamBytes) throws Exception {
        Map<String, String> headersToSign = buildHeadersToSign(headers);
        String bodyMd5 = buildBodyMd5(httpMethod, inputStreamBytes);
        String resourceToSign = buildResource(uri, paramsMap);
        String stringToSign = buildStringToSign(headersToSign, resourceToSign, httpMethod, bodyMd5);

        Mac hmacSha256 = Mac.getInstance(HMAC_SHA256);
        String secret = signSecretMap.get(headers.get(HTTP_HEADER_TO_LOWER_CASE ? CA_PROXY_SIGN_SECRET_KEY.toLowerCase() : CA_PROXY_SIGN_SECRET_KEY));

        byte[] keyBytes = secret.getBytes(ENCODING);
        hmacSha256.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, HMAC_SHA256));

        return new String(Base64.encodeBase64(hmacSha256.doFinal(stringToSign.getBytes(ENCODING))), ENCODING);
    }

    /**
     * 构建BodyMd5
     *
     * @param httpMethod       HTTP请求方法
     * @param inputStreamBytes HTTP请求Body体字节数组
     * @return Body Md5值
     * @throws IOException
     */
    private static String buildBodyMd5(String httpMethod, byte[] inputStreamBytes) throws IOException {
        if (inputStreamBytes == null) {
            return null;
        }

        if (!httpMethod.equalsIgnoreCase(HTTP_METHOD_POST) && !httpMethod.equalsIgnoreCase(HTTP_METHOD_PUT)) {
            return null;
        }

        InputStream inputStream = new ByteArrayInputStream(inputStreamBytes);
        byte[] bodyBytes = IOUtils.toByteArray(inputStream);
        if (bodyBytes != null && bodyBytes.length > 0) {
            return base64AndMD5(bodyBytes).trim();
        }
        return null;
    }

    /**
     * 将Map转换为用&及=拼接的字符串
     */
    private static String buildMapToSign(Map<String, Object> paramMap) {
        StringBuilder builder = new StringBuilder();

        for (Map.Entry<String, Object> e : paramMap.entrySet()) {
            if (builder.length() > 0) {
                builder.append('&');
            }

            String key = e.getKey();
            Object value = e.getValue();

            if (value != null) {
                if (value instanceof List) {
                    List list = (List) value;
                    if (list.size() == 0) {
                        builder.append(key);
                    } else {
                        builder.append(key).append("=").append(String.valueOf(list.get(0)));
                    }
                } else if (value instanceof Object[]) {
                    Object[] objs = (Object[]) value;
                    if (objs.length == 0) {
                        builder.append(key);
                    } else {
                        builder.append(key).append("=").append(String.valueOf(objs[0]));
                    }
                } else {
                    builder.append(key).append("=").append(String.valueOf(value));
                }
            }
        }

        return builder.toString();
    }

    /**
     * 构建参与签名的HTTP头
     * <pre>
     * 传入的Headers必须将默认的ISO-8859-1转换为UTF-8以支持中文
     * </pre>
     *
     * @param headers HTTP请求头
     * @return 所有参与签名计算的HTTP请求头
     */
    private static Map<String, String> buildHeadersToSign(Map<String, String> headers) {
        Map<String, String> headersToSignMap = new TreeMap<String, String>();

        String headersToSignString = headers.get(HTTP_HEADER_TO_LOWER_CASE ? CA_PROXY_SIGN_HEADERS.toLowerCase() : CA_PROXY_SIGN_HEADERS);

        if (headersToSignString != null) {
            for (String headerKey : headersToSignString.split("\\,")) {
                headersToSignMap.put(headerKey, headers.get(HTTP_HEADER_TO_LOWER_CASE ? headerKey.toLowerCase() : headerKey));
            }
        }

        return headersToSignMap;
    }

    /**
     * 组织待计算签名字符串
     *
     * @param headers        HTTP请求头
     * @param resourceToSign Uri+请求参数的签名字符串
     * @param method         HTTP方法
     * @param bodyMd5        Body Md5值
     * @return 待计算签名字符串
     */
    private static String buildStringToSign(Map<String, String> headers, String resourceToSign, String method, String bodyMd5) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(LF);
        if (StringUtils.isNotBlank(bodyMd5)) {
            sb.append(bodyMd5);
        }
        sb.append(LF);
        sb.append(buildHeaders(headers));
        sb.append(resourceToSign);

        return sb.toString();
    }

    /**
     * 组织Headers签名签名字符串
     *
     * @param headers HTTP请求头
     * @return Headers签名签名字符串
     */
    private static String buildHeaders(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getValue() != null) {
                sb.append(e.getKey().toLowerCase()).append(':').append(e.getValue()).append(LF);
            }
        }
        return sb.toString();
    }

    /**
     * 组织Uri+请求参数的签名字符串
     *
     * @param uri       HTTP请求uri,不包含Query
     * @param paramsMap HTTP请求所有参数（Query+Form参数）
     * @return Uri+请求参数的签名字符串
     */
    private static String buildResource(String uri, Map<String, Object> paramsMap) {
        StringBuilder builder = new StringBuilder();

        // uri
        builder.append(uri);

        // Query+Form
        TreeMap<String, Object> sortMap = new TreeMap<String, Object>();
        sortMap.putAll(paramsMap);


        // 有Query+Form参数
        if (sortMap.size() > 0) {
            builder.append('?');
            builder.append(buildMapToSign(sortMap));
        }

        return builder.toString();
    }

    /**
     * 先进行MD5摘要再进行Base64编码获取摘要字符串
     *
     * @param bytes 待计算字节数组
     * @return
     */
    public static String base64AndMD5(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes can not be null");
        }

        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(bytes);
            final Base64 base64 = new Base64();

            return new String(base64.encode(md.digest()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("unknown algorithm MD5");
        }
    }
}