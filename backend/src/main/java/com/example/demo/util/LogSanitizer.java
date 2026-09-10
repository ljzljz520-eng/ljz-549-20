package com.example.demo.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 构建请求参数摘要，并对敏感字段做脱敏处理。
 *
 * 规则：
 * 1) 手机号字段（phone/mobile/tel 等）：保留前 3 后 4，中间以 **** 代替，如 138****1234；
 * 2) 理由/备注类自由文本字段（reason/remark/memo/comment/note 等）：不落原文，仅记录长度；
 * 3) 密码、证件号、token 等字段：整体以 *** 代替；
 * 4) 其他普通字符串：超长截断，并对其中疑似手机号的内容做掩码；
 * 5) 摘要整体截断到最大长度，保证日志不会无限膨胀。
 *
 * 该类不抛业务异常，任何解析失败均回退为安全的占位摘要。
 */
public final class LogSanitizer {

    // 关闭 HTML 转义，避免 "=" 等字符被转成 = 降低日志可读性
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    /** 中国大陆 11 位手机号（1 开头，第二位 3-9）。 */
    private static final Pattern MOBILE_PATTERN =
            Pattern.compile("(?<![0-9])1[3-9]\\d{9}(?![0-9])");

    private static final Set<String> PHONE_TOKENS =
            Set.of("phone", "mobile", "tel", "telephone", "contact",
                   "shouji", "haoma", "phoneNumber", "mobileNumber",
                   "手机", "电话", "联系方式");

    private static final Set<String> SECRET_TOKENS =
            Set.of("password", "passwd", "pwd", "token", "secret", "credential",
                   "authorization", "auth", "idcard", "idcardno", "idno",
                   "email", "mail", "bankcard", "cardno", "cvv", "captcha",
                   "verifycode", "smscode", "mima", "shenfenzheng", "youxiang",
                   "密码", "证件", "身份证", "邮箱", "银行卡", "验证码");

    private static final Set<String> REASON_TOKENS =
            Set.of("reason", "remark", "memo", "comment", "note", "description", "desc",
                   "liyou", "beizhu", "miaoshu", "shuoming",
                   "理由", "备注", "描述", "说明", "原因", "意见");

    private static final int MAX_VALUE_LENGTH = 64;
    private static final int MAX_SUMMARY_LENGTH = 512;

    private LogSanitizer() {
    }

    /**
     * 生成 query string 参数摘要（已脱敏）。
     *
     * @param queryString 原始 query string（可为 null）
     * @return 参数摘要 JSON，如 {"page":"1"}；无参数时返回 null
     */
    public static String summarizeQuery(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return null;
        }
        JsonObject summary = new JsonObject();
        for (String pair : queryString.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            String rawKey = idx >= 0 ? pair.substring(0, idx) : pair;
            String rawValue = idx >= 0 && idx + 1 <= pair.length() ? pair.substring(idx + 1) : "";
            String key = urlDecode(rawKey);
            String value = maskValue(urlDecode(rawValue));
            putOrAppend(summary, key, value);
        }
        if (summary.size() == 0) {
            return null;
        }
        return cap(GSON.toJson(summary));
    }

    /**
     * 根据容器已解析好的参数 Map 生成表单参数摘要（已脱敏）。
     * 适用于 application/x-www-form-urlencoded：由容器负责解析请求体，
     * 避免过滤器读取原始流后业务方 {@code getParameter()} 失效。
     *
     * @param paramMap    request.getParameterMap() 的结果
     * @param excludeKeys query string 中已出现的 key，避免在 body 摘要中重复
     * @return 参数摘要；无表单参数时返回 null
     */
    public static String summarizeParameterMap(Map<String, String[]> paramMap, Set<String> excludeKeys) {
        if (paramMap == null || paramMap.isEmpty()) {
            return null;
        }
        JsonObject summary = new JsonObject();
        for (Map.Entry<String, String[]> entry : paramMap.entrySet()) {
            String key = entry.getKey();
            if (excludeKeys != null && excludeKeys.contains(key)) {
                continue;
            }
            String[] values = entry.getValue();
            if (values == null || values.length == 0) {
                summary.addProperty(key, "");
            } else if (values.length == 1) {
                summary.addProperty(key, maskByKey(key, values[0]));
            } else {
                JsonArray array = new JsonArray();
                for (String v : values) {
                    array.add(maskByKey(key, v));
                }
                summary.add(key, array);
            }
        }
        if (summary.size() == 0) {
            return null;
        }
        return cap(GSON.toJson(summary));
    }

    /**
     * 生成请求体摘要（已脱敏）。
     * 支持 application/json；application/x-www-form-urlencoded 请改用
     * {@link #summarizeParameterMap(Map, Set)}（由容器解析表单）；
     * 其他类型只记录字节数，不记录正文。
     *
     * @param body        已缓存的请求体（可为 null）
     * @param contentType Content-Type 头（可为 null）
     * @return 参数摘要；无请求体时返回 null
     */
    public static String summarizeBody(String body, String contentType) {
        if (body == null) {
            return null;
        }
        String trimmed = body.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String type = contentType == null ? "" : contentType.toLowerCase();
        try {
            if (type.contains("json") || trimmed.startsWith("{") || trimmed.startsWith("[")) {
                JsonElement parsed = GSON.fromJson(trimmed, JsonElement.class);
                if (parsed == null) {
                    return "{\"body\":\"unparseable_json(" + trimmed.length() + ")\"}";
                }
                JsonElement masked = maskElement(null, parsed);
                return cap(GSON.toJson(masked));
            }
            if (type.contains("x-www-form-urlencoded")) {
                String formSummary = summarizeQuery(trimmed);
                return formSummary != null ? formSummary : "{\"body\":\"empty_form\"}";
            }
            // 其他类型（二进制/文本等）不记录正文，仅记录大小，避免泄露敏感理由等内容
            return "{\"body_type\":\"" + type.replace("\"", "") + "\",\"bytes\":"
                    + body.getBytes(StandardCharsets.UTF_8).length + "}";
        } catch (Exception e) {
            // 任何异常都不应影响业务，仅返回安全占位
            return "{\"body\":\"unparseable(" + trimmed.length() + ")\"}";
        }
    }

    /**
     * 对任意 JsonElement 递归脱敏。
     *
     * @param key 该元素对应的字段名（根元素为 null）
     */
    private static JsonElement maskElement(String key, JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return new JsonPrimitive("null");
        }
        if (element.isJsonObject()) {
            JsonObject source = element.getAsJsonObject();
            JsonObject target = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : source.entrySet()) {
                target.add(entry.getKey(), maskElement(entry.getKey(), entry.getValue()));
            }
            return target;
        }
        if (element.isJsonArray()) {
            JsonArray target = new JsonArray();
            for (JsonElement item : element.getAsJsonArray()) {
                target.add(maskElement(key, item));
            }
            return target;
        }
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        // 数字与布尔值不含敏感文本，保留原始类型，避免 1001 被记成 "1001"；
        // 但若字段名本身是手机号/密钥/理由字段，仍按字符串脱敏
        if ((primitive.isNumber() || primitive.isBoolean())
                && !isPhoneKey(key) && !isSecretKey(key) && !isReasonKey(key)) {
            return primitive;
        }
        return new JsonPrimitive(maskByKey(key, primitive.getAsString()));
    }

    /**
     * 按字段名分类决定脱敏方式。
     */
    private static String maskByKey(String key, String value) {
        if (value == null) {
            return "null";
        }
        if (isPhoneKey(key)) {
            return maskMobile(value);
        }
        if (isSecretKey(key)) {
            return "***";
        }
        if (isReasonKey(key)) {
            // 理由/备注类内容不进日志，只留长度用于联调判断是否有值
            return "[redacted len=" + value.length() + "]";
        }
        return maskValue(value);
    }

    private static boolean isPhoneKey(String key) {
        return containsToken(key, PHONE_TOKENS);
    }

    private static boolean isSecretKey(String key) {
        return containsToken(key, SECRET_TOKENS);
    }

    private static boolean isReasonKey(String key) {
        return containsToken(key, REASON_TOKENS);
    }

    /**
     * 将字段名归一化后按词匹配 token：
     * 拆分驼峰与非字母数字分隔符，既支持英文（claimReason -> claim reason），
     * 也支持中文（认领理由、手机号）。
     */
    private static boolean containsToken(String key, Set<String> tokens) {
        if (key == null || key.isEmpty()) {
            return false;
        }
        String spaced = key.replaceAll("([a-z0-9])([A-Z])", "$1 $2")
                           .replaceAll("[^a-zA-Z0-9\\u4e00-\\u9fa5]+", " ")
                           .trim();
        String lower = spaced.toLowerCase();
        for (String token : tokens) {
            if (containsWord(lower, token)) {
                return true;
            }
        }
        // 中文 token 直接做子串匹配
        return containsChineseToken(key, tokens);
    }

    private static boolean containsWord(String text, String word) {
        if (!word.matches("[a-z0-9]+")) {
            return text.contains(word);
        }
        Matcher m = Pattern.compile("(?<![a-z0-9])" + Pattern.quote(word) + "(?![a-z0-9])")
                           .matcher(text);
        return m.find();
    }

    private static boolean containsChineseToken(String key, Set<String> tokens) {
        for (String token : tokens) {
            String lower = token.toLowerCase();
            if (!lower.matches(".*[\\u4e00-\\u9fa5].*")) {
                continue;
            }
            if (key.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 通用值脱敏：掩码其中的手机号，再做长度截断。
     */
    private static String maskValue(String value) {
        if (value == null) {
            return "null";
        }
        String masked = MOBILE_PATTERN.matcher(value).replaceAll(m -> maskMobile(m.group()));
        return truncate(masked, MAX_VALUE_LENGTH);
    }

    /** 13812341234 -> 138****1234；长度不符则保留首尾少量字符。 */
    private static String maskMobile(String value) {
        if (value == null) {
            return "null";
        }
        String trimmed = value.trim();
        if (trimmed.length() == 11) {
            return trimmed.substring(0, 3) + "****" + trimmed.substring(7);
        }
        if (trimmed.length() > 6) {
            return trimmed.substring(0, 2) + "****" + trimmed.substring(trimmed.length() - 2);
        }
        return "***";
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= max) {
            return value;
        }
        return value.substring(0, max) + "...(" + value.length() + ")";
    }

    private static String cap(String summary) {
        if (summary == null) {
            return null;
        }
        if (summary.length() <= MAX_SUMMARY_LENGTH) {
            return summary;
        }
        return summary.substring(0, MAX_SUMMARY_LENGTH)
                + "...(truncated,total=" + summary.length() + ")";
    }

    private static String urlDecode(String value) {
        if (value == null) {
            return "";
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            // 非法转义序列时保留原始值，随后仍会走脱敏逻辑
            return value;
        }
    }

    /**
     * 同名 query/form 参数出现多次时，聚合为 JSON 数组。
     */
    private static void putOrAppend(JsonObject obj, String key, String value) {
        if (!obj.has(key)) {
            obj.addProperty(key, value);
            return;
        }
        JsonElement existing = obj.get(key);
        JsonArray array;
        if (existing.isJsonArray()) {
            array = existing.getAsJsonArray();
        } else {
            array = new JsonArray();
            array.add(existing.getAsString());
        }
        array.add(value);
        obj.add(key, array);
    }

}
