package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

@RequiredArgsConstructor
public class IPAddressVoter implements AccessDecisionVoter {

    /**
     * troubleshoot
     * SecurityResourceService 에서 NPE
     * DI를 안해줬음
     * Spring 에서 private final 이 붙은 필드에 한해 생성자 DI를 지원해준다 (@RequiredArgsConstructor와 함께 사용)
     * Bean factory에 해당 bean이 없으면 생성해주기도 함(추가검색필요)
     *
     * 기존에 new SecurityResourceService()로 객체를 생성하는 거 보다 스프링 컨테이너에서 관리하는 bean 에 등록을 하면
     * 객체간 의존관계 설정을 더 편하게 할 수 있음.
     */
    private final SecurityResourceService securityResourceService;

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    // 인증객체정보, 요청정보(FilterInvocation), 자원에접근할때 필요한 권한정보(FilterInvocationMetadataSOurce?) 순으로 paramter가 넘어온다.
    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {

        // details에 client의 ip주소 값이 저장되어있음.
        WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();
        // client의 ip정보와 db에 저장된 접근가능한 ip 주소가 일치하는지 검사
        List<String> accessIPList = securityResourceService.getAccessIPList();

        int result = ACCESS_DENIED;

        for (String ipAddress : accessIPList) {
            if(remoteAddress.equals(ipAddress)){
                // ip만 허용된 것이지 자원 접근권한에 대한 심의는 하지 않았기 때문에 ACCESS_GRANTED 대신 ABSTAIN으로 return하는 것이 맞음.
                result = ACCESS_ABSTAIN;
            }
        }

        if(result==ACCESS_DENIED){
            // 접근이 안되는 ip라면 서버의 모든 자원에 접근하지 못하도록 exception 발생
            throw new AccessDeniedException("InvalidIpAddress");
        }
        return result;
    }
}
