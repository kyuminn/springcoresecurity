package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

// 요청경로와 그 경로에 필요한 권한을 Map으로 저장하고 있는 class 
//FitlerSecurityInterceptor 가 후에 이 class안의 Map을 참조하여 인가처리를 진행
@Slf4j
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    //ConfigAttribute : 권한정보
    // requestMap : 요청정보와 권한정보가 key와 value로 이루어진 map
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;
    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap,SecurityResourceService securityResourceService) {
        this.requestMap = requestMap;
        this.securityResourceService = securityResourceService;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // Object o 를 FilterInvocation로 다운캐스팅
        // FilterInvocation : client 요쳥정보, request, response 객체가 담겨있음

//        requestMap.put(new AntPathRequestMatcher("/mypage"),Arrays.asList(new SecurityConfig("ROLE_USER")));
        // requestMap을 DB에서 얻어오는 방식
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        if(requestMap != null){
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)){
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    //DB가 업데이트 되었을 경우 requestMap 다시 가져오는 메서드
    public void reload(){
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();
        // map 데이터 업데이트 위해 기존 데이터 삭제
        requestMap.clear();
        
        while (iterator.hasNext()){
            // entry안에 key, value(권한리스트)있음
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
        
    }
}