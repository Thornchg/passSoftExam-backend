package com.thornchg.rkt.shiro;

import java.util.ArrayList;
import java.util.List;

import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.service.UserService;
import jdk.internal.org.objectweb.asm.commons.AdviceAdapter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;


public class DbShiroRealm extends AuthorizingRealm {
    private final Logger log = LoggerFactory.getLogger(DbShiroRealm.class);

    private static final String encryptSalt = "F12839WhsnnEV$#23b";
    private UserService userService;

    public DbShiroRealm(UserService userService) {
        this.userService = userService;
        this.setCredentialsMatcher(new HashedCredentialsMatcher(Sha256Hash.ALGORITHM_NAME));
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken userpasswordToken = (UsernamePasswordToken) token;
        String username = userpasswordToken.getUsername();
        User user = userService.getUserInfo(username);
        if (user == null)
            throw new AuthenticationException("用户名或者密码错误");

        return new SimpleAuthenticationInfo(user, user.getPassword(), ByteSource.Util.bytes(encryptSalt), "dbRealm");
    }


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        User user = (User) principals.getPrimaryPrincipal();
        List<String> roles = userService.getUserRoles(user.getId());

//        roles.add(user.getRole());
        /*if(roles == null) {
            roles = userService.getUserRoles(user.getId());
            user.setRoles(roles);
        }*/
        simpleAuthorizationInfo.addRoles(roles);
        Cache<Object, AuthorizationInfo> authorizationCache = getAuthorizationCache();
        System.out.println("dbCacheSize=>" + authorizationCache.size());


        return simpleAuthorizationInfo;
    }

}
