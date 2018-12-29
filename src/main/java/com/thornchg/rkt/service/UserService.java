package com.thornchg.rkt.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.shiro.JWTToken;

import java.util.List;

/**
 * <p>
 * 用户 服务类
 * </p>
 *
 * @author yc
 * @since 2018-12-28
 */
public interface UserService extends IService<User> {

    String generateJwtToken(String username);

    User getJwtTokenInfo(String username);

    void deleteLoginInfo(String username);

    User getUserInfo(String userName);

    List<String> getUserRoles(String userId);

//    boolean IsValidForJwtToken(String username,String token);

    String getTokenSalt(String username);
}
