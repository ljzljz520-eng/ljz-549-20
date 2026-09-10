package com.example.demo.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * 缓存请求体的 HttpServletRequest 包装器。
 *
 * 日志过滤器需要先读取一次 body 以生成参数摘要，而 Servlet 的 InputStream
 * 只能读一次；此包装器把 body 缓存在字节数组中，使后续 Servlet 仍可通过
 * getReader()/getInputStream() 正常读取，日志对业务完全透明。
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        Charset charset = resolveCharset(request.getCharacterEncoding());
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(request.getInputStream(), charset))) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[4096];
            int read;
            while ((read = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, read);
            }
            this.cachedBody = sb.toString().getBytes(charset);
        }
    }

    private static Charset resolveCharset(String encoding) {
        if (encoding == null || encoding.isEmpty()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(encoding);
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    /** 供过滤器获取缓存的原始请求体用于日志摘要。 */
    public byte[] getCachedBody() {
        return cachedBody;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream input = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return input.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // 同步读取，不需要异步回调
            }

            @Override
            public int read() {
                return input.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(
                getInputStream(), resolveCharset(getCharacterEncoding())));
    }
}
