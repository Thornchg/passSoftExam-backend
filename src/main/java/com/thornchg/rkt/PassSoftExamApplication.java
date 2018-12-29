package com.thornchg.rkt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
@MapperScan("com.thornchg.rkt.mapper")
public class PassSoftExamApplication {

    public static void main(String[] args) {
        SpringApplication.run(PassSoftExamApplication.class, args);
    }
}

