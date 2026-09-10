package com.example.demo.filter;

import com.example.demo.util.LogSanitizer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 统一请求日志过滤器。
 *
 * 对每次查询（GET）、提交认领（POST）、更新状态（PUT/PATCH）等 /api/** 调用记录：
 *   请求方法、接口路径、响应状态码、耗时(ms)、参数摘要（脱敏）。
 *
 * 设计约束：
 * 1) 日志逻辑全部放在 try/finally 中，任何日志相关异常都被吞掉，绝不改变/中断业务响应；
 * 2) JSON 等非表单请求体通过 CachedBodyHttpServletRequest 缓存读取；
 *    表单（application/x-www-form-urlencoded）交给容器解析参数，不做流包装，
 *    避免读完原始流后业务方 getParameter() 失效；
 * 3) 手机号、理由/备注、密码等敏感内容经 LogSanitizer 脱敏后才入日志；
 * 4) 超大（超过 8KB）或分块传输的请求体不缓存，仅记 query 摘要，保证内存安全；
 * 5) 业务抛异常的请求也在 finally 中完成记录，并按实际结果码记录状态。
 */
@WebFilter(filterName = "requestLoggingFilter", urlPatterns = {"/api/*"})
public class RequestLoggingFilter extends HttpFilter {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = Logger.getLogger(RequestLoggingFilter.class.getName());

    /** 允许缓存进内存的请求体上限（8KB，认领类接口的 JSON 足够小）。 */
    private static final int MAX_CACHEABLE_BODY_BYTES = 8 * 1024;

    private static final Set<String> BODY_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response,
                            FilterChain chain) throws IOException, ServletException {
        // CORS 预检请求不记录，避免噪声
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        long start = System.currentTimeMillis();
        StatusCaptureResponseWrapper responseWrapper = new StatusCaptureResponseWrapper(response);
        HttpServletRequest effectiveRequest = request;
        // 表单类型在进入业务链之前由容器解析参数并生成摘要，其他类型延迟到 finally 读取缓存
        String preBuiltBodySummary = null;

        try {
            if (isBodyMethod(request)) {
                if (isFormRequest(request)) {
                    preBuiltBodySummary = buildFormSummary(request);
                } else {
                    effectiveRequest = maybeWrapWithCachedBody(request);
                }
            }
            chain.doFilter(effectiveRequest, responseWrapper);
        } catch (IOException | ServletException | RuntimeException e) {
            // 业务异常照常抛出，由容器处理；但容器把状态改写为 500 发生在过滤器返回之后，
            // 因此这里先标记状态，保证异常请求也能记录到正确的结果码
            if (!responseWrapper.isCommitted() && responseWrapper.getStatus() < 400) {
                responseWrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            throw e;
        } finally {
            long elapsed = System.currentTimeMillis() - start;
            try {
                String bodySummary = preBuiltBodySummary != null
                        ? preBuiltBodySummary
                        : buildBodySummary(effectiveRequest);
                logAccess(request, responseWrapper.getStatus(), elapsed, bodySummary);
            } catch (Exception loggingFailure) {
                // 日志本身失败绝不能影响接口响应
                LOG.log(Level.FINE, "request logging failed: " + loggingFailure.getMessage(),
                        loggingFailure);
            }
        }
    }

    private boolean isBodyMethod(HttpServletRequest request) {
        return BODY_METHODS.contains(request.getMethod().toUpperCase());
    }

    private boolean isFormRequest(HttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType != null
                && contentType.toLowerCase().contains("application/x-www-form-urlencoded");
    }

    /**
     * 表单请求：在进入业务链前调用 getParameterMap 触发容器解析（解析结果会被容器缓存，
     * 后续业务 Servlet 再调 getParameter 不受影响），并排除 query string 同名字段。
     */
    private String buildFormSummary(HttpServletRequest request) {
        try {
            Set<String> queryKeys = collectQueryKeys(request.getQueryString());
            Map<String, String[]> paramMap = request.getParameterMap();
            return LogSanitizer.summarizeParameterMap(paramMap, queryKeys);
        } catch (Exception e) {
            LOG.log(Level.FINE, "form summary failed: " + e.getMessage(), e);
            return null;
        }
    }

    private Set<String> collectQueryKeys(String queryString) {
        Set<String> keys = new HashSet<>();
        if (queryString == null || queryString.isEmpty()) {
            return keys;
        }
        for (String pair : queryString.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                keys.add(pair.substring(0, idx));
            } else if (!pair.isEmpty()) {
                keys.add(pair);
            }
        }
        return keys;
    }

    private HttpServletRequest maybeWrapWithCachedBody(HttpServletRequest request) throws IOException {
        // 分块传输或声明体过大的请求不缓存，保证内存安全
        if (request.getContentLengthLong() > MAX_CACHEABLE_BODY_BYTES) {
            return request;
        }
        if (request.getHeader("Transfer-Encoding") != null
                && request.getContentLengthLong() < 0) {
            return request;
        }
        return new CachedBodyHttpServletRequest(request);
    }

    private String buildBodySummary(HttpServletRequest effectiveRequest) {
        if (!(effectiveRequest instanceof CachedBodyHttpServletRequest cached)) {
            return null;
        }
        byte[] body = cached.getCachedBody();
        if (body == null || body.length == 0) {
            return null;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        return LogSanitizer.summarizeBody(text, effectiveRequest.getContentType());
    }

    private void logAccess(HttpServletRequest request, int status, long elapsedMs,
                           String bodySummary) {
        StringBuilder params = new StringBuilder();
        String querySummary = LogSanitizer.summarizeQuery(request.getQueryString());
        if (querySummary != null) {
            params.append("query=").append(querySummary);
        }
        if (bodySummary != null) {
            if (params.length() > 0) {
                params.append(' ');
            }
            params.append("body=").append(bodySummary);
        }

        LOG.info(String.format(
                "access | method=%s path=%s status=%d elapsed=%dms%s",
                request.getMethod(),
                request.getRequestURI(),
                status,
                elapsedMs,
                params.length() > 0 ? " params={" + params + "}" : ""));
    }
}
