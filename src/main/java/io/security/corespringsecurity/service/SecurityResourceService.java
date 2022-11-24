package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIPRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Database에서 요청경로와 그 경로에 필요한 권한정보를 가져와서 Map 객체로 파싱하는 class
 */
@Slf4j
@RequiredArgsConstructor
public class SecurityResourceService {

    private final ResourcesRepository resourcesRepository;
    private final AccessIPRepository accessIPRepository;

//    private ResourcesRepository resourcesRepository;
//    private AccessIPRepository accessIPRepository;
//
//    public SecurityResourceService(ResourcesRepository resourcesRepository,AccessIPRepository accessIPRepository) {
//        this.resourcesRepository = resourcesRepository;
//        this.accessIPRepository = accessIPRepository;
//    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        // DB로부터 관련 정보를 가져옴
        List<Resources> resourcesList = resourcesRepository.findAllResources();

        // 가져온 정보를 LinkedHashMap<> 타입으로 가공 후 return
        resourcesList.forEach(re ->
                {
                    List<ConfigAttribute> configAttributeList = new ArrayList<>();
                    re.getRoleSet().forEach(ro -> {
                        // SecurityConfig는 ConfigAttribute 타입의 구현체
                        configAttributeList.add(new SecurityConfig(ro.getRoleName()));
                        result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributeList);
                    });
                }
        );
        return result;
    }

    public List<String> getAccessIPList() {
        List<String> acceptIpList = accessIPRepository.findAll()
                .stream()
                .map(accessIP -> accessIP.getIpAddress())
                .collect(Collectors.toList());
        return acceptIpList;
    }
}