package com.thornchg.rkt.filter;


import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.service.UserService;
import com.thornchg.rkt.shiro.JWTToken;
import com.thornchg.rkt.utils.JwtUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * 执行顺序
 * preHandle()
 */
public class JwtAuthFilter extends AuthenticatingFilter {
    private final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private static final int tokenRefreshInterval = 300;
    private UserService userService;

    public JwtAuthFilter(UserService userService) {
        this.userService = userService;
        this.setLoginUrl("/login");
    }

    /**
     * 前置处理器 跨域请求会先有一个options的请求  如果是这个请求 不做校验
     *
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) //对于OPTION请求做拦截，不做token校验
            return false;

        return super.preHandle(request, response);
    }

    /**
     * 后置处理器
     *
     * @param request
     * @param response
     */

    @Override
    protected void postHandle(ServletRequest request, ServletResponse response) {
        this.fillCorsHeader(WebUtils.toHttp(request), WebUtils.toHttp(response));
        request.setAttribute("jwtShiroFilter.FILTERED", true);
    }

    /**
     * 是否允许访问 使用
     *
     * @param request
     * @param response
     * @param mappedValue
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (this.isLoginRequest(request, response))
            return true;
        Boolean afterFiltered = (Boolean) (request.getAttribute("jwtShiroFilter.FILTERED"));
        if (BooleanUtils.isTrue(afterFiltered))
            return true;
        boolean allowed = true;
        try {
            allowed = executeLogin(request, response);
        } catch (IllegalStateException e) { //not found any token
            log.error("Not found any token");
            return false;
        } catch (Exception e) {
            log.error("Error occurs when login", e);
        }
        return allowed || super.isPermissive(mappedValue);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest servletRequest, ServletResponse servletResponse) {
        String token = getAuthzHeader(servletRequest);
        /*if (StringUtils.isNotBlank(token)&&!JwtUtils.isTokenExpired(token)) {
            JWTToken jwtToken = new JWTToken(token);
            String salt = userService.getTokenSalt(jwtToken.getUsername());
            if (salt!=null) {
                jwtToken.setSalt(salt);
                return jwtToken;
            }
        }*/
        if (StringUtils.isNotBlank(token)){
            return new JWTToken(token);
        }

        return null;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletResponse httpResponse = WebUtils.toHttp(servletResponse);
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setStatus(HttpStatus.SC_NON_AUTHORITATIVE_INFORMATION);
        fillCorsHeader(WebUtils.toHttp(servletRequest), httpResponse);
        return false;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        String newToken = null;
        if (token instanceof JWTToken) {
            JWTToken jwtToken = (JWTToken) token;
            User user = (User) subject.getPrincipal();
            boolean shouldRefresh = shouldTokenRefresh(JwtUtils.getIssuedAt(jwtToken.getToken()));
            //token签发时间超过5分钟  刷新token
            if (shouldRefresh) {
                newToken = userService.generateJwtToken(user.getUsername());
            }
        }
        if (StringUtils.isNotBlank(newToken))
            httpResponse.setHeader("x-auth-token", newToken);

        return true;
    }

    /**
     * token验证出被篡改后执行
     *
     * @param token
     * @param e
     * @param request
     * @param response
     * @return
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        log.error("Validate token fail, token:{}, error:{}", token.toString(), e.getMessage());
        return false;
    }

    /**
     * 从请求头中获取token串
     *
     * @param request
     * @return
     */
    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        String header = httpRequest.getHeader("x-auth-token");
        return StringUtils.removeStart(header, "Bearer ");
    }

    /**
     * token是否应该刷新
     *
     * @param issueAt
     * @return
     */

    protected boolean shouldTokenRefresh(Date issueAt) {
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(tokenRefreshInterval).isAfter(issueTime);
    }

    /**
     * 在响应头中添加跨域字段
     *
     * @param httpServletRequest
     * @param httpServletResponse
     */
    protected void fillCorsHeader(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,HEAD");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
    }
}
