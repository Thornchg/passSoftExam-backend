package com.thornchg.rkt;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.Resource;

@RunWith(SpringRunner.class)
@SpringBootTest
public class PassSoftExamApplicationTests {
    @Resource
    private CacheManager cacheManager;

    @Test
    public void contextLoads() {
        System.out.println(StringUtils.join(cacheManager.getCacheNames(), ","));
        Cache cache = cacheManager.getCache("userCache");
        cache.put("key", "123");
        System.out.println("缓存成功");
        String res = cache.get("key", String.class);
        System.out.println(res);
    }

}

