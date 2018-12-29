package com.thornchg.rkt.config;

import com.thornchg.rkt.filter.AnyRolesAuthorizationFilter;
import com.thornchg.rkt.filter.JwtAuthFilter;
import com.thornchg.rkt.service.UserService;
import com.thornchg.rkt.shiro.DbShiroRealm;
import com.thornchg.rkt.shiro.JWTCredentialsMatcher;
import com.thornchg.rkt.shiro.JWTShiroRealm;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import java.util.Arrays;
import java.util.Map;

@Configuration
public class ShiroConfig {
    /**
     * 配置过滤器
     *
     * @param securityManager
     * @param userService
     * @return
     * @throws Exception
     */
    @Bean
    public FilterRegistrationBean<Filter> filterRegistrationBean(SecurityManager securityManager, UserService userService) throws Exception {
        FilterRegistrationBean<Filter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter((Filter) shiroFilter(securityManager, userService).getObject());
        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
        filterRegistration.setAsyncSupported(true);
        filterRegistration.setEnabled(true);
        filterRegistration.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ASYNC);

        return filterRegistration;
    }

    /**
     * 设置shiro过滤器
     */
    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager, UserService userService) {
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        Map<String, Filter> filterMap = factoryBean.getFilters();
        filterMap.put("authcToken", createAuthFilter(userService));
        filterMap.put("anyRole", createRolesFilter());
        factoryBean.setFilters(filterMap);
        factoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition().getFilterChainMap());

        return factoryBean;
    }

    @Bean
    public SecurityManager securityManager(UserService userService, EhCacheManager ehCacheManager,
                                           JWTCredentialsMatcher jwtCredentialsMatcher
            , SessionStorageEvaluator sessionStorageEvaluator) {


        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealms(Arrays.asList(jwtShiroRealm(userService, jwtCredentialsMatcher)
                , dbShiroRealm(userService)));

        defaultWebSecurityManager.setCacheManager(ehCacheManager);
        ((DefaultSubjectDAO) defaultWebSecurityManager.getSubjectDAO())
                .setSessionStorageEvaluator(sessionStorageEvaluator);
        return defaultWebSecurityManager;
    }

    protected JwtAuthFilter createAuthFilter(UserService userService) {
        return new JwtAuthFilter(userService);
    }

    protected AnyRolesAuthorizationFilter createRolesFilter() {

        return new AnyRolesAuthorizationFilter();
    }

    @Bean
    protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/login", "noSessionCreation,anon");
        chainDefinition.addPathDefinition("/logout", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/image/**", "anon");
        chainDefinition.addPathDefinition("/admin/**", "noSessionCreation,authcToken,anyRole[admin,manager]"); //只允许admin或manager角色的用户访问
        chainDefinition.addPathDefinition("/article/list", "noSessionCreation,authcToken");
        chainDefinition.addPathDefinition("/article/*", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/**", "noSessionCreation,authcToken");
        return chainDefinition;
    }
    @Bean
    public EhCacheManagerFactoryBean cacheManagerFactoryBean(){
        EhCacheManagerFactoryBean ehCacheManagerFactoryBean=
                new EhCacheManagerFactoryBean();
        ehCacheManagerFactoryBean.setConfigLocation(new ClassPathResource("ehcache.xml"));
        ehCacheManagerFactoryBean.setShared(true);
        return ehCacheManagerFactoryBean;
    }
    @Bean
    public EhCacheManager ehCacheManager(EhCacheManagerFactoryBean cacheManagerFactoryBean) {
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManager(cacheManagerFactoryBean.getObject());
//        ehCacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
        return ehCacheManager;
    }
    @Bean
    public EhCacheCacheManager ehCacheCacheManager(EhCacheManagerFactoryBean cacheManagerFactoryBean){
        return new EhCacheCacheManager(cacheManagerFactoryBean.getObject());
    }

    @Bean
    protected SessionStorageEvaluator sessionStorageEvaluator() {
        DefaultWebSessionStorageEvaluator sessionStorageEvaluator = new DefaultWebSessionStorageEvaluator();
        sessionStorageEvaluator.setSessionStorageEnabled(false);
        return sessionStorageEvaluator;
    }

    @Bean("dbRealm")
    public Realm dbShiroRealm(UserService userService) {
        DbShiroRealm myShiroRealm = new DbShiroRealm(userService);
        myShiroRealm.setAuthorizationCachingEnabled(true);
        myShiroRealm.setAuthorizationCacheName("dbAuthorizationCache");
        return myShiroRealm;
    }

    @Bean("jwtRealm")
    public Realm jwtShiroRealm(UserService userService, JWTCredentialsMatcher credentialsMatcher) {
        JWTShiroRealm myShiroRealm = new JWTShiroRealm(userService);
        myShiroRealm.setCredentialsMatcher(credentialsMatcher);
        myShiroRealm.setAuthenticationCachingEnabled(true);
        myShiroRealm.setAuthenticationCacheName("jwtAuthenticationCache");
        myShiroRealm.setAuthorizationCachingEnabled(true);
        myShiroRealm.setAuthorizationCacheName("jwtAuthorizationCache");

//        myShiroRealm.set
        return myShiroRealm;
    }

    @Bean
    public JWTCredentialsMatcher jwtCredentialsMatcher() {
        return new JWTCredentialsMatcher();
    }


    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
        return defaultAdvisorAutoProxyCreator;
    }

    /**
     * 由spring管理shiro生命周期
     *
     * @return
     */
    @Bean(name = "lifecycleBeanPostProcessor")
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }
}
