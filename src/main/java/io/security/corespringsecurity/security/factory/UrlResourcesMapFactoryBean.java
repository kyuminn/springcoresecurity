package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

// DB로부터 얻은 자원요청/권한 정보를 ResourceMap bean으로 생성해서 UrlFilterInvocationSecurityMetadataSource에 전달
// ResourceMap bean => UrlFilterInvacationSecurityMetadatSource의 requestMap 이라고 생각하면됨
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap;

    public void init() {
        // DB에서 정보 추출하여 가공한 값을 받아서 resourceMap에 담음
            resourcesMap = securityResourceService.getResourceList();
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() {
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
