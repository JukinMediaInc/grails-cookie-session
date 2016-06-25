package com.granicus.grails.plugins.cookiesession;

import org.apache.log4j.Logger;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CookieSessionFilter extends OncePerRequestFilter implements InitializingBean, ApplicationContextAware {

    final static Logger log = Logger.getLogger(CookieSessionFilter.class.getName());
    String sessionId = "gsession";

    ApplicationContext applicationContext;
    ArrayList<SessionPersistenceListener> sessionPersistenceListeners;

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException
    {
        if( log.isTraceEnabled() ){ log.trace("setApplicationContext()"); }
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() throws ServletException
    {
      super.afterPropertiesSet();

      if( log.isTraceEnabled() ){ log.trace("afterPropertiesSet()"); }

      sessionPersistenceListeners = new ArrayList<SessionPersistenceListener>();
      // scan the application context for SessionPersistenceListeners
      Map beans = applicationContext.getBeansOfType(SessionPersistenceListener.class);
      for( Object beanName : beans.keySet().toArray() ){
        sessionPersistenceListeners.add((SessionPersistenceListener)beans.get(beanName));
        if( log.isTraceEnabled() ){ log.trace("added listener: " + beanName.toString()); }
      }
    }

    // dependency injected
    private SessionRepository sessionRepository;
    public void setSessionRepository(SessionRepository repository){
      sessionRepository = repository;
    }
    public SessionRepository getSessionRepository(){
      return ( sessionRepository );
    }

    @Override
    protected void initFilterBean() {
    }

    @Override
    protected void doFilterInternal( HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

      if( log.isTraceEnabled() ){ log.trace("doFilterInternal()"); }

      Map config = ((GrailsApplication)applicationContext.getBean("grailsApplication")).getConfig().flatten();
      List blacklistPaths = (List) config.get("grails.plugin.cookiesession.blacklistPathStartsWith");
      Boolean blacklisted = isBlacklisted(request.getServletPath(), blacklistPaths);

      if (blacklisted) {
          log.info("Skipping Cookie Session decoration for path: "+request.getServletPath());
          chain.doFilter(request, response);

      } else {
          log.info("Using Cookie Session decoration for path: "+request.getServletPath());
          SessionRepositoryRequestWrapper requestWrapper = new SessionRepositoryRequestWrapper(request, sessionRepository);
          requestWrapper.setServletContext(this.getServletContext());
          requestWrapper.setSessionPersistenceListeners(this.sessionPersistenceListeners);
          requestWrapper.restoreSession();

          // if spring security integration is supported it is necessary to enforce session creation
          // if one does not exist yet. otherwise the security context will not be persisted and
          // propagated between requests if the application did not happen to use a session yet.

          boolean enforceSession = this.applicationContext.containsBeanDefinition("securityContextSessionPersistenceListener");

          SessionRepositoryResponseWrapper responseWrapper = new SessionRepositoryResponseWrapper(response, sessionRepository, requestWrapper, enforceSession);
          responseWrapper.setSessionPersistenceListeners(this.sessionPersistenceListeners);
          chain.doFilter(requestWrapper, responseWrapper);
      }
    }

    Boolean isBlacklisted(String path, List blacklistPaths) {
        Boolean blacklisted = false;
        if (blacklistPaths != null && blacklistPaths.size() > 0) {
            for (Object blacklistPath : blacklistPaths) {
                if (blacklistPath instanceof String && path.startsWith((String) blacklistPath)) {
                    blacklisted = true;
                    break;
                }
            }
        }
        return blacklisted;
    }
}
