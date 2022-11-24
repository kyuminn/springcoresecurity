package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

//Springboot application이 구동될 때 특정 코드를 실행시키기 위해 ApplicationRunner를 구현한 class
@RequiredArgsConstructor
@Component
public class SecurityIntializer implements ApplicationRunner {

    // DB로부터 role_hierarchy 정보를 가져와 포매팅한 결과값을
    // RoleHierarchyImpl에 전달

    private final RoleHierarchyService roleHierarchyService;
    private final RoleHierarchyImpl roleHierarchyImpl;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // role_hierarchy table에서 계층권한을 가져온 뒤 포맷팅한 문자열
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchyImpl.setHierarchy(allHierarchy);
    }
}
