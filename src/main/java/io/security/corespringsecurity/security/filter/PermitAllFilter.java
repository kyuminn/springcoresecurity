package io.security.corespringsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
// 부모 클래스인 AbstractFilterSecurityInterceptor가 accessDecisionManager로 하여금 인가처리를 시키기 전에!
// 요청한 경로가 인증/인가처리가 없는 경로인지 먼저 판단하고 permitAll 해주는 filter
// FilterSecurityInterceptor 내용 복사하고, 필요없는 부분만 살짝 지움
// 실제로 구현되어 있는 class 내용을 가져와서 customize 할수도 있구나 .. implements 개념만 생각했었는데

public class PermitAllFilter extends FilterSecurityInterceptor {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;
    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();
    public PermitAllFilter(String...permitAllResources) {
        // String... -> String[] 인데 들어오는 개수를 모를때 ...로 쓴다.
        for(String resource : permitAllResources){
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {
        // 매개변수 object는 FilterInvocation 타입, 사용자 요청정보를 가져올 수 있다.
        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for (RequestMatcher permitAllRequestMatcher : permitAllRequestMatchers) {
            if(permitAllRequestMatcher.matches(request)){
                permitAll = true; // 인가처리 할 필요 없음
                break;
            }
        }

        if(permitAll){
            return null; // 권한심사 하지 않도록 null return
        }
        return super.beforeInvocation(object);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if (fi.getRequest() != null && fi.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null && this.observeOncePerRequest) {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            if (fi.getRequest() != null && this.observeOncePerRequest) {
                fi.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            // 62번째줄 super 부분이 부모 class인 AbstractFilterSecurityInterceptor의 beforeInvacation()으로 가는 부분
            // beforeInvocaton()에서 AccessDecisionManager의 decide()를 호출하여 인가처리를 위임한다.
            // 아래 코드가 실행되기 전에 미리 ! requestMatcher 객체를 검사해야 하므로 부모 클래스의 메서드를 호출하지 않고 
            // 오버라이딩 해서 beforeInvacation()을 직접 구현
//            InterceptorStatusToken token = super.beforeInvocation(fi);
            InterceptorStatusToken token = beforeInvocation(fi);


            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object) null);
        }

    }

}
