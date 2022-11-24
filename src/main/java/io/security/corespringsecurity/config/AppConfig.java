package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.AccessIPRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository, AccessIPRepository accessIPRepository) {
        SecurityResourceService SecurityResourceService = new SecurityResourceService(resourcesRepository,accessIPRepository);
        return SecurityResourceService;
    }
}
