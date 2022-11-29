package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;
// UrlResourcesMapFacotryBean과 동일한 로직
@RequiredArgsConstructor
public class MethodResourcesFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {
    private final SecurityResourceService securityResourceService;
    private String resourceType;
    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

//    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
//        this.securityResourceService = securityResourceService;
//    }

    private LinkedHashMap<String, List<ConfigAttribute>> resourcesMap;

    public void init() {
        // DB에서 정보 추출하여 가공한 값을 받아서 resourceMap에 담음
        resourcesMap = securityResourceService.getMethodResourceList();
    }

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {
        if (resourcesMap == null) {
            // resourceMap bean 생성해주기!
            init();
        }
        return resourcesMap;
    }

    @Override
    public Class<LinkedHashMap> getObjectType() {
        return LinkedHashMap.class;
    }

    // 메모리에 단 하나만 존재하도록 singleTon
    @Override
    public boolean isSingleton() {
        return true;
    }


}
