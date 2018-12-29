package com.thornchg.rkt.controller;


import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>
 * 用户 前端控制器
 * </p>
 *
 * @author yc
 * @since 2018-12-28
 */
@RestController
@RequestMapping("/user/user")
public class UserController {
    private Logger logger = LoggerFactory.getLogger(UserController.class);
    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }
    /**
     * 用户名密码登录
     * @param request
     * @return token
     */
    @PostMapping(value = "/login")
    public ResponseEntity<Void> login(@RequestBody User loginInfo, HttpServletRequest request, HttpServletResponse response){
        Subject subject = SecurityUtils.getSubject();
        try {
            UsernamePasswordToken token = new UsernamePasswordToken(loginInfo.getUsername(), loginInfo.getPassword());
            subject.login(token);

            User user = (User) subject.getPrincipal();
            String newToken = userService.generateJwtToken(user.getUsername());
            response.setHeader("x-auth-token", newToken);

            return ResponseEntity.ok().build();
        }catch (IncorrectCredentialsException e){
            logger.error("User {} login password error, Reason:{}", loginInfo.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        catch (AuthenticationException e) {
            logger.error("User {} login fail, Reason:{}", loginInfo.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * 退出登录
     * @return
     */
    @GetMapping(value = "/logout")
    public ResponseEntity<Void> logout() {
        Subject subject = SecurityUtils.getSubject();
        if(subject.getPrincipals() != null) {
            User user = (User)subject.getPrincipals().getPrimaryPrincipal();
            userService.deleteLoginInfo(user.getUsername());
        }
        SecurityUtils.getSubject().logout();
        return ResponseEntity.ok().build();
    }

}
