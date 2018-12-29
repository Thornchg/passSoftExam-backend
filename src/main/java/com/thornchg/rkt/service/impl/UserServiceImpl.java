package com.thornchg.rkt.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.mapper.UserMapper;
import com.thornchg.rkt.service.UserService;
import com.thornchg.rkt.shiro.JWTToken;
import com.thornchg.rkt.utils.JwtUtils;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.List;

/**
 * <p>
 * 用户 服务实现类
 * </p>
 *
 * @author yc
 * @since 2018-12-28
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    private static final String encryptSalt = "F12839WhsnnEV$#23b";
    @Resource
    private CacheManager cacheManager;

//	@Autowired
//	private StringRedisTemplate redisTemplate;

    /**
     * 保存user登录信息，返回token
     *
     * @param username
     */
    @Override
    public String generateJwtToken(String username) {
        String salt = "12345";//JwtUtils.generateSalt();
        //将salt保存到数据库或者缓存中
        //redisTemplate.opsForValue().set("token:"+username, salt, 3600, TimeUnit.SECONDS);
        Cache cache = cacheManager.getCache("userCache");
        cache.put("token:" + username, salt);
        return JwtUtils.sign(username, salt, 3600);
    }

    /**
     * 获取上次token生成时的salt值和登录用户信息
     *
     * @param username
     * @return
     */
    @Override
    public User getJwtTokenInfo(String username) {
        String salt = "12345";

        /**
         * @todo 从数据库或者缓存中取出jwt token生成时用的salt
         * salt = redisTemplate.opsForValue().get("token:"+username);
         */
        User user = getUserInfo(username);
        return user;
    }


    /**
     * 清除token信息
     *
     * @param username 登录用户名
     */
    @Override
    public void deleteLoginInfo(String username) {
        /**
         * @todo 删除数据库或者缓存中保存的salt
         * redisTemplate.delete("token:"+username);
         */
        Cache cache = cacheManager.getCache("userCache");
        cache.evict("token:" + username);

    }

    /**
     * 获取数据库中保存的用户信息，主要是加密后的密码
     *
     * @param userName
     * @return
     */
    @Override
    public User getUserInfo(String userName) {
        User user = new User();
        if (userName.equals("admin")) {
            user.setId("1L");
            user.setUsername("admin");
            user.setPassword(new Sha256Hash("123456", encryptSalt).toHex());
        } else if (userName.equals("user")) {
            user.setId("2L");
            user.setUsername("user");
            user.setPassword(new Sha256Hash("123456", encryptSalt).toHex());
        }
        return user;
    }

    /**
     * 获取用户角色列表，强烈建议从缓存中获取
     *
     * @param userId
     * @return
     */
    @Override
    public List<String> getUserRoles(String userId) {
        if (userId.equals("1L")) {
            return Collections.singletonList("admin");
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public String getTokenSalt(String username) {
        Cache cache = cacheManager.getCache("userCache");
        return cache.get("token:" + username, String.class);
    }

}
