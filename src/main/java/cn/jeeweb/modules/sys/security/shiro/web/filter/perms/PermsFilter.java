package cn.jeeweb.modules.sys.security.shiro.web.filter.perms;

import cn.jeeweb.core.model.AjaxJson;
import cn.jeeweb.core.security.shiro.authz.annotation.RequiresMethodPermissions;
import cn.jeeweb.core.security.shiro.authz.annotation.RequiresPathPermission;
import cn.jeeweb.core.utils.PropertiesUtil;
import cn.jeeweb.modules.sys.utils.UserUtils;
import com.alibaba.fastjson.JSON;
import org.apache.http.util.TextUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Set;

/**
 * Created by hexin on 2018/8/3.
 */

public class PermsFilter extends PermissionsAuthorizationFilter {
    private boolean isAjax(ServletRequest request){
        return "XMLHttpRequest".equalsIgnoreCase(((HttpServletRequest) request).getHeader("X-Requested-With"));
    }

    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        if(!TextUtils.isEmpty(httpServletRequest.getParameter("callbackType"))
                && httpServletRequest.getParameter("callbackType").equalsIgnoreCase("json")){

            String baseUrl = httpServletRequest.getParameter("baseUrl");
            String actionType = httpServletRequest.getParameter("actionType");
            String permsUrl = baseUrl + "/" + actionType;
            /**
             * 读取shiro登录默认首地址，如/admin
             */
            PropertiesUtil propertiesUtil = new PropertiesUtil("shiro.properties");
            String rootUrl = propertiesUtil.getString("shiro.default.success.url");
            if(!rootUrl.endsWith("/")){
                rootUrl = rootUrl + "/";
            }
            String perm = permsUrl.replace(rootUrl, "");
            perm = perm.replace("/",":");
            Set<String> permsList = UserUtils.getPermissionsList("all");
            boolean queryPerm = false;
            for(String perms : permsList){
                if(perms.indexOf(perm) != -1){
                    queryPerm = true;
                    break;
                }
            }
            return queryPerm;
        }
        return super.isAccessAllowed(request, response, mappedValue);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        if(!TextUtils.isEmpty(httpServletRequest.getParameter("callbackType"))
                && httpServletRequest.getParameter("callbackType").equalsIgnoreCase("json")){
            AjaxJson ajaxJson = new AjaxJson();
            ajaxJson.fail("没有相应的操作权限！请联系管理员分配权限...");
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            httpServletResponse.setCharacterEncoding("UTF-8");
            httpServletResponse.setHeader("Content-type", "application/json;charset=UTF-8");
            PrintWriter out = httpServletResponse.getWriter();
            out.println(JSON.toJSONString(ajaxJson));
            out.flush();
            out.close();
            return false;
        }
        return super.onAccessDenied(request, response);
    }
}
