package telran.java2022.security.service.filters;

import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import telran.java2022.security.service.CustomWebSecurity;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

@Component
@RequiredArgsConstructor
public class CheckDateFilter  implements Filter {
    final CustomWebSecurity customSecurity;
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;
        String path = request.getServletPath();
        if(customSecurity.checkUserPasswordDate(request.getUserPrincipal().getName()) && checkEndPoint(path,request.getMethod())){
            response.sendError(403,"password time has expired, please change it");
        }
        chain.doFilter(request,response);
    }

    private boolean checkEndPoint(String method,String servletPath){
        return !(servletPath.matches("/account/password/\\w+/?") && method.equalsIgnoreCase("Put"));
    }
}
