package com.example.demo.filter;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;

/**
 * 记录最终 HTTP 状态码的响应包装器。
 *
 * sendError 之外，Servlet 通常通过 setStatus 设置状态码，
 * 统一覆写以便日志在 finally 阶段拿到真实结果码。
 */
public class StatusCaptureResponseWrapper extends HttpServletResponseWrapper {

    private int httpStatus = SC_OK;

    public StatusCaptureResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public void setStatus(int sc) {
        this.httpStatus = sc;
        super.setStatus(sc);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        this.httpStatus = sc;
        super.sendError(sc, msg);
    }

    @Override
    public void sendError(int sc) throws IOException {
        this.httpStatus = sc;
        super.sendError(sc);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        this.httpStatus = SC_FOUND;
        super.sendRedirect(location);
    }

    @Override
    public int getStatus() {
        return httpStatus;
    }
}
