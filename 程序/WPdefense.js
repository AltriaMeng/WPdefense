public interface AuthenticationManager {
    Authentication authenticate(Authentication authentication)
            throws AuthenticationException;
}
public interface Authentication extends Principal, Serializable {
    //#1.权限结合，可使用AuthorityUtils.commaSeparatedStringToAuthorityList("admin,ROLE_ADMIN")返回字符串权限集合
    Collection<? extends GrantedAuthority> getAuthorities();
    //#2.用户名密码认证时可以理解为密码
    Object getCredentials();
    //#3.认证时包含的一些信息。
    Object getDetails();
    //#4.用户名密码认证时可理解时用户名
    Object getPrincipal();
    #5.是否被认证，认证为true    
    boolean isAuthenticated();
    #6.设置是否能被认证
    void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        //#1.获取当前的Authentication的认证类型
        Class<? extends Authentication> toTest = authentication.getClass();
        AuthenticationException lastException = null;
        Authentication result = null;
        boolean debug = logger.isDebugEnabled();
        //#2.遍历所有的providers使用supports方法判断该provider是否支持当前的认证类型，不支持的话继续遍历
        for (AuthenticationProvider provider : getProviders()) {
            if (!provider.supports(toTest)) {
                continue;
            }

            if (debug) {
                logger.debug("Authentication attempt using "
                        + provider.getClass().getName());
            }

            try {
                #3.支持的话调用provider的authenticat方法认证
                result = provider.authenticate(authentication);

                if (result != null) {
                    #4.认证通过的话重新生成Authentication对应的Token
                    copyDetails(authentication, result);
                    break;
                }
            }
            catch (AccountStatusException e) {
                prepareException(e, authentication);
                // SEC-546: Avoid polling additional providers if auth failure is due to
                // invalid account status
                throw e;
            }
            catch (InternalAuthenticationServiceException e) {
                prepareException(e, authentication);
                throw e;
            }
            catch (AuthenticationException e) {
                lastException = e;
            }
        }

        if (result == null && parent != null) {
            // Allow the parent to try.
            try {
                #5.如果#1 没有验证通过，则使用父类型AuthenticationManager进行验证
                result = parent.authenticate(authentication);
            }
            catch (ProviderNotFoundException e) {
                // ignore as we will throw below if no other exception occurred prior to
                // calling parent and the parent
                // may throw ProviderNotFound even though a provider in the child already
                // handled the request
            }
            catch (AuthenticationException e) {
                lastException = e;
            }
        }
        #6. 是否擦出敏感信息
        if (result != null) {
            if (eraseCredentialsAfterAuthentication
                    && (result instanceof CredentialsContainer)) {
                // Authentication is complete. Remove credentials and other secret data
                // from authentication
                ((CredentialsContainer) result).eraseCredentials();
            }

            eventPublisher.publishAuthenticationSuccess(result);
            return result;
        }

        // Parent was null, or didn't authenticate (or throw an exception).

        if (lastException == null) {
            lastException = new ProviderNotFoundException(messages.getMessage(
                    "ProviderManager.providerNotFound",
                    new Object[] { toTest.getName() },
                    "No AuthenticationProvider found for {0}"));
        }

        prepareException(lastException, authentication);

        throw lastException;
    }
public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only UsernamePasswordAuthenticationToken is supported"));

        // Determine username
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
                : authentication.getName();

        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);

        if (user == null) {
            cacheWasUsed = false;

            try {
                #1.获取用户信息由子类实现即DaoAuthenticationProvider
                user = retrieveUser(username,
                        (UsernamePasswordAuthenticationToken) authentication);
            }
            catch (UsernameNotFoundException notFound) {
                logger.debug("User '" + username + "' not found");

                if (hideUserNotFoundExceptions) {
                    throw new BadCredentialsException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.badCredentials",
                            "Bad credentials"));
                }
                else {
                    throw notFound;
                }
            }

            Assert.notNull(user,
                    "retrieveUser returned null - a violation of the interface contract");
        }

        try {
            #2.前检查由DefaultPreAuthenticationChecks类实现（主要判断当前用户是否锁定，过期，冻结User接口）
            preAuthenticationChecks.check(user);
            #3.子类实现
            additionalAuthenticationChecks(user,
                    (UsernamePasswordAuthenticationToken) authentication);
        }
        catch (AuthenticationException exception) {
            if (cacheWasUsed) {
                // There was a problem, so try again after checking
                // we're using latest data (i.e. not from the cache)
                cacheWasUsed = false;
                user = retrieveUser(username,
                        (UsernamePasswordAuthenticationToken) authentication);
                preAuthenticationChecks.check(user);
                additionalAuthenticationChecks(user,
                        (UsernamePasswordAuthenticationToken) authentication);
            }
            else {
                throw exception;
            }
        }
        #4.检测用户密码是否过期对应#2 的User接口
        postAuthenticationChecks.check(user);

        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user;

        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }

        return createSuccessAuthentication(principalToReturn, authentication, user);
    }
//执行过滤链

public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

//获取请求和响应

        HttpServletRequest request = (HttpServletRequest)req;

        HttpServletResponse response = (HttpServletResponse)res;

        if (request.getAttribute("__spring_security_scpf_applied") != null) {

            chain.doFilter(request, response);

        } else {

            boolean debug = this.logger.isDebugEnabled();

            request.setAttribute("__spring_security_scpf_applied", Boolean.TRUE);

            if (this.forceEagerSessionCreation) {

                HttpSession session = request.getSession();

                if (debug && session.isNew()) {

                    this.logger.debug("Eagerly created session: " + session.getId());

                }

            }

//包装request 和response

            HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);

            //从安全上下文长裤中获取SecurityContext容器

            SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);

            boolean var13 = false;

            try {

                var13 = true;

                // 获取安全响应上下文

                SecurityContextHolder.setContext(contextBeforeChainExecution);

                chain.doFilter(holder.getRequest(), holder.getResponse());

                var13 = false;

            } finally {

                if (var13) {

                //最终清除安全上下文信息

                    SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();

                    SecurityContextHolder.clearContext();

                    this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());

                    request.removeAttribute("__spring_security_scpf_applied");

                    if (debug) {

                        this.logger.debug("SecurityContextHolder now cleared, as request processing completed");

                    }

                }

            }

            SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();

            SecurityContextHolder.clearContext();

            this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());

            request.removeAttribute("__spring_security_scpf_applied");

            if (debug) {

                this.logger.debug("SecurityContextHolder now cleared, as request processing completed");

            }

        }

    }
public class SecurityContextHolder {

//存储策略

    public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";

    public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";

    public static final String MODE_GLOBAL = "MODE_GLOBAL";

    public static final String SYSTEM_PROPERTY = "spring.security.strategy";

    private static String strategyName = System.getProperty("spring.security.strategy");

    private static SecurityContextHolderStrategy strategy;

    private static int initializeCount = 0;

    public SecurityContextHolder() {

    }

//清除上下文

    public static void clearContext() {

        strategy.clearContext();

    }

    private static void initialize() {

        if (!StringUtils.hasText(strategyName)) {

            strategyName = "MODE_THREADLOCAL";

        }

        if (strategyName.equals("MODE_THREADLOCAL")) {

        //创建真正的安全上下文容器

            strategy = new ThreadLocalSecurityContextHolderStrategy();

        } else if (strategyName.equals("MODE_INHERITABLETHREADLOCAL")) {

            strategy = new InheritableThreadLocalSecurityContextHolderStrategy();

        } else if (strategyName.equals("MODE_GLOBAL")) {

            strategy = new GlobalSecurityContextHolderStrategy();

        } else {

            try {

                Class<?> clazz = Class.forName(strategyName);

                Constructor<?> customStrategy = clazz.getConstructor();

                strategy = (SecurityContextHolderStrategy)customStrategy.newInstance();

            } catch (Exception var2) {

                ReflectionUtils.handleReflectionException(var2);

            }

        }

        ++initializeCount;

    }

//....代码省略

//  初始化

    static {

        initialize();

    }

}
@Slf4j

@Service

@Lazy(false)

public class TenantContextHolder implements ApplicationContextAware, DisposableBean {

private static ThreadLocal<String> tenantThreadLocal= new ThreadLocal<>();

private static ApplicationContext applicationContext =null;

@Override

public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {

TenantContextHolder.applicationContext =applicationContext;

}

public static final void setTenant(String schema){

tenantThreadLocal.set(schema);

}

public static final String getTenant(){

String schema = tenantThreadLocal.get();

if(schema == null){

schema = "";

}

return schema;

}

@Override

public void destroy() throws Exception {

TenantContextHolder.clearHolder();

}

public static void clearHolder() {

if (log.isDebugEnabled()) {

log.debug("清除TenantContextHolder中的ApplicationContext:" + applicationContext);

}

applicationContext = null;

}

}
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean implements ApplicationEventPublisherAware, MessageSourceAware {

//事件发布器



        //判断当前的filter是否可以处理当前请求，不可以的话则交给下一个filter处理

        if (!this.requiresAuthentication(request, response)) {

            chain.doFilter(request, response);

        } else {

            if (this.logger.isDebugEnabled()) {

                this.logger.debug("Request is to process authentication");

            }

            Authentication authResult;

            try {

            //对权限进行校验

                authResult = this.attemptAuthentication(request, response);

                if (authResult == null) {

                    return;

                }

//认证成功

            this.sessionStrategy.onAuthentication(authResult, request, response);



            if (this.continueChainBeforeSuccessfulAuthentication) {

                chain.doFilter(request, response);

            }

            this.successfulAuthentication(request, response, chain, authResult);

        }

    }

//权限校验的方法

    public abstract Authentication attemptAuthentication(HttpServletRequest var1, HttpServletResponse var2) throws AuthenticationException, IOException, ServletException;

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {

        this.authenticationManager = authenticationManager;

    }

}
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";

    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private String usernameParameter = "username";

    private String passwordParameter = "password";

    private boolean postOnly = true;

//在webconfig里，配置http.login 并且路径为/login、方法为post 就会被这个拦截器拦截

    public UsernamePasswordAuthenticationFilter() {

        super(new AntPathRequestMatcher("/login", "POST"));

    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (this.postOnly && !request.getMethod().equals("POST")) {

            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());

        } else {

            String username = this.obtainUsername(request);

            String password = this.obtainPassword(request);

            if (username == null) {

                username = "";

            }

            if (password == null) {

                password = "";

            }

            // 注意 划重点

//获取用户名和密码 并将用户名和密码封装成一个UsernamePasswordAuthenticationToken这么个token

            username = username.trim();

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

            this.setDetails(request, authRequest);

            //将校验交由AuthenticationManger的authenticate方法去执行

            return this.getAuthenticationManager().authenticate(authRequest);

        }

    }
public class ProviderManager implements AuthenticationManager, MessageSourceAware,
		InitializingBean {

	private List<AuthenticationProvider> providers = Collections.emptyList();
	private AuthenticationManager parent;
	private boolean eraseCredentialsAfterAuthentication = true;

    // 遍历Providers
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		
        
		for (AuthenticationProvider provider : getProviders()) {
		    // 如果Authentication不符合，跳过后边步骤，继续循环
			if (!provider.supports(toTest)) {
				continue;
			}

            // 如果Authentication符合，则使用该Provider进行authenticate操作
			result = provider.authenticate(authentication);
            
			if (result != null) {
                copyDetails(authentication, result);
            	break;
			}
		}

		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				((CredentialsContainer) result).eraseCredentials();
			}
			return result;
		}
	}
	
}
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

// 代码省略 ....

    public ProviderManager(List<AuthenticationProvider> providers) {

        this(providers, (AuthenticationManager)null);

    }

    public ProviderManager(List<AuthenticationProvider> providers, AuthenticationManager parent) {

        this.eventPublisher = new ProviderManager.NullEventPublisher();

        this.providers = Collections.emptyList();

        this.messages = SpringSecurityMessageSource.getAccessor();

        this.eraseCredentialsAfterAuthentication = true;

        Assert.notNull(providers, "providers list cannot be null");

        this.providers = providers;

        this.parent = parent;

        this.checkState();

    }

//权限校验

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    //获取当前认证的类型

        Class<? extends Authentication> toTest = authentication.getClass();

        AuthenticationException lastException = null;

        Authentication result = null;

        boolean debug = logger.isDebugEnabled();

        //获取迭代器

        Iterator var6 = this.getProviders().iterator();

//循环获取 这里和4.x版本有所不同个 有兴趣的可以看看4.x的版本

        while(var6.hasNext()) {

            AuthenticationProvider provider = (AuthenticationProvider)var6.next();

            if (provider.supports(toTest)) {

                if (debug) {

                    logger.debug("Authentication attempt using " + provider.getClass().getName());

                }

                try {

                    result = provider.authenticate(authentication);

                    //通过当前类型获取到认证信息且不为null 则停止循环

                    if (result != null) {

                    将result装换成Authentication信息

                        this.copyDetails(authentication, result);

                        break;

                    }

                } catch (AccountStatusException var11) {

                    this.prepareException(var11, authentication);

                    throw var11;

                } catch (InternalAuthenticationServiceException var12) {

                    this.prepareException(var12, authentication);

                    throw var12;

                } catch (AuthenticationException var13) {

                    lastException = var13;

                }

            }

        }

//如果结果为空 则调用父类的authenticate方法 这里可以理解成递归

        if (result == null && this.parent != null) {

            try {



                result = this.parent.authenticate(authentication);

            } catch (ProviderNotFoundException var9) {

                ;

            } catch (AuthenticationException var10) {

                lastException = var10;

            }

        }

//获取到结果

        if (result != null) {

            if (this.eraseCredentialsAfterAuthentication && result instanceof CredentialsContainer) {

              //移除密码

              ((CredentialsContainer)result).eraseCredentials();

            }

//发布验证成功事件 并返回结果

            this.eventPublisher.publishAuthenticationSuccess(result);

            return result;

        } else {

        //执行到此，说明没有认证成功，包装异常信息

            if (lastException == null) {

                lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound", new Object[]{toTest.getName()}, "No AuthenticationProvider found for {0}"));

            }

            this.prepareException((AuthenticationException)lastException, authentication);

            throw lastException;

        }

    }

    public List<AuthenticationProvider> getProviders() {

        return this.providers;

    }

// .................

}
public interface Authentication extends Principal, Serializable {

//权限信息集合

    Collection<? extends GrantedAuthority> getAuthorities();

//获取凭证

    Object getCredentials();

//获取详情

    Object getDetails();

//获取当前用户

    Object getPrincipal();

//是否认证

    boolean isAuthenticated();

    void setAuthenticated(boolean var1) throws IllegalArgumentException;

}
public interface UserDetailsService {

    UserDetails loadUserByUsername(String var1) throws UsernameNotFoundException;

}
public class User implements UserDetails, CredentialsContainer {

    private static final long serialVersionUID = 500L;

    private static final Log logger = LogFactory.getLog(User.class);

    private String password;

    private final String username;

    private final Set<GrantedAuthority> authorities;

    private final boolean accountNonExpired;

    private final boolean accountNonLocked;

    private final boolean credentialsNonExpired;

    private final boolean enabled;

    public User(String username, String password, Collection<? extends GrantedAuthority> authorities) {

        this(username, password, true, true, true, true, authorities);

    }

    public User(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {

        if (username != null && !"".equals(username) && password != null) {

            this.username = username;

            this.password = password;

            this.enabled = enabled;

            this.accountNonExpired = accountNonExpired;

            this.credentialsNonExpired = credentialsNonExpired;

            this.accountNonLocked = accountNonLocked;

            this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));

        } else {

            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");

        }

    }

// 代码省略.............

}
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

    //问价加解密处理

    private PasswordEncoder passwordEncoder;

    private volatile String userNotFoundEncodedPassword;

    //注入UserDetailsService 调用子类的loadUserByUsername方法 获得UserDetails对象

    private UserDetailsService userDetailsService;

    public DaoAuthenticationProvider() {

    //密码处理

        this.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());

    }
protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        if (authentication.getCredentials() == null) {

            this.logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));

        } else {

            String presentedPassword = authentication.getCredentials().toString();

            if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {

                this.logger.debug("Authentication failed: password does not match stored value");

                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));

            }

        }

    }

    protected void doAfterPropertiesSet() throws Exception {

        Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");

    }

    protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        this.prepareTimingAttackProtection();

        try {

        //在这里通过用户名从数据库中拿到UserDetails 然后交给additionalAuthenticationChecks去验证

            UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);

            if (loadedUser == null) {

                throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");

            } else {

                return loadedUser;

            }

    // ..........................

}
