using DotNetCasClient.Security;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Security;

namespace DotNetCasClient
{
    /// <summary>
    /// Simulate User Account
    /// </summary>
    public sealed class SimulateAuthentication
    {
        private static readonly string SimulateAuthenticationSecret = System.Configuration.ConfigurationManager.AppSettings["SimulateAuthenticationSecret"] ?? "SimulateAuthenticationSecret";

        [ThreadStatic]
        private static CasPrincipal currentPrincipal;

        /// <summary>
        /// Current authenticated principal or null if current user is unauthenticated.
        /// </summary>
        public static CasPrincipal CurrentPrincipal
        {
            get { return currentPrincipal; }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>是否继续执行CasAuthentication</returns>
        internal static bool ProcessRequestAuthentication()
        {
            bool continueProcess = true;
            HttpContext context = HttpContext.Current;
            HttpApplication application = context.ApplicationInstance;

            FormsAuthenticationTicket formsAuthenticationTicket = GetFormsAuthenticationTicket();
            if (formsAuthenticationTicket != null)
            {
                SimulateUserData userData = GetUserData(formsAuthenticationTicket.UserData);
                if (userData != null)
                {
                    continueProcess = false;
                    CasPrincipal principal = new CasPrincipal(new Assertion(userData.UserName));

                    context.User = principal;
                    Thread.CurrentPrincipal = principal;
                    currentPrincipal = principal;

                    if (principal == null)
                    {
                        // Remove the cookie from the client
                        ClearAuthCookie();
                    }
                    else
                    {
                        // Extend the expiration of the cookie if FormsAuthentication is configured to do so.
                        if (FormsAuthentication.SlidingExpiration)
                        {
                            FormsAuthenticationTicket newTicket = FormsAuthentication.RenewTicketIfOld(formsAuthenticationTicket);
                            if (newTicket != null && newTicket != formsAuthenticationTicket)
                            {
                                SetAuthCookie(newTicket);
                            }
                        }
                    }
                }
            }
            return continueProcess;
        }

        /// <summary>
        /// Simulate User Account
        /// </summary>
        /// <param name="context"></param>
        /// <param name="userData"></param>
        public static void Simulate(HttpContext context, SimulateUserData userData)
        {
            CasPrincipal principal = new CasPrincipal(new Assertion(userData.UserName));
            context.User = principal;
            Thread.CurrentPrincipal = principal;

            userData.Token = Encrypt(userData.UserName);
            FormsAuthenticationTicket formsAuthTicket = CreateFormsAuthenticationTicket(userData.UserName,
                FormsAuthentication.FormsCookiePath,
                JsonConvert.SerializeObject(userData),
                null, null);

            SetAuthCookie(formsAuthTicket);
        }

        private static string Encrypt(string userName)
        {
            return MD5Encrypt($"{userName}{SimulateAuthenticationSecret}{userName}");
        }

        /// <summary>
        /// 8小时有效
        /// </summary>
        /// <param name="netId"></param>
        /// <param name="cookiePath"></param>
        /// <param name="userData"></param>
        /// <param name="validFromDate"></param>
        /// <param name="validUntilDate"></param>
        /// <returns></returns>
        public static FormsAuthenticationTicket CreateFormsAuthenticationTicket(string netId, string cookiePath, string userData, DateTime? validFromDate, DateTime? validUntilDate)
        {
            DateTime fromDate = validFromDate.HasValue ? validFromDate.Value : DateTime.Now;
            DateTime toDate = validUntilDate.HasValue ? validUntilDate.Value : fromDate.AddHours(8);

            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                2,
                netId,
                fromDate,
                toDate,
                false,
                userData,
                cookiePath ?? FormsAuthentication.FormsCookiePath
            );

            return ticket;
        }

        private static FormsAuthenticationTicket GetFormsAuthenticationTicket()
        {
            HttpContext context = HttpContext.Current;
            HttpCookie cookie = context.Request.Cookies[FormsAuthentication.FormsCookieName];

            if (cookie == null)
            {
                return null;
            }

            if (cookie.Expires != DateTime.MinValue && cookie.Expires < DateTime.Now)
            {
                ClearAuthCookie();
                return null;
            }

            if (String.IsNullOrEmpty(cookie.Value))
            {
                ClearAuthCookie();
                return null;
            }

            FormsAuthenticationTicket formsAuthTicket;
            try
            {
                formsAuthTicket = FormsAuthentication.Decrypt(cookie.Value);
            }
            catch
            {
                ClearAuthCookie();
                return null;
            }

            if (formsAuthTicket == null)
            {
                ClearAuthCookie();
                return null;
            }

            if (formsAuthTicket.Expired)
            {
                ClearAuthCookie();
                return null;
            }

            if (String.IsNullOrEmpty(formsAuthTicket.UserData))
            {
                ClearAuthCookie();
                return null;
            }

            return formsAuthTicket;
        }

        private static void SetAuthCookie(FormsAuthenticationTicket clientTicket)
        {
            HttpContext current = HttpContext.Current;

            if (!current.Request.IsSecureConnection && FormsAuthentication.RequireSSL)
            {
                throw new HttpException("Connection not secure while creating secure cookie");
            }

            // Obtain the forms authentication cookie from the ticket
            HttpCookie authCookie = GetAuthCookie(clientTicket);
            // Clear the previous cookie from the current HTTP request
            current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);
            // Store the new cookie in both the request and response objects
            current.Request.Cookies.Add(authCookie);
            current.Response.Cookies.Add(authCookie);
        }

        private static HttpCookie GetAuthCookie(FormsAuthenticationTicket ticket)
        {
            string str = FormsAuthentication.Encrypt(ticket);

            if (String.IsNullOrEmpty(str))
            {
                throw new HttpException("Unable to encrypt cookie ticket");
            }

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, str);

            // Per http://support.microsoft.com/kb/900111 :
            // In ASP.NET 2.0, forms authentication cookies are HttpOnly cookies. 
            // HttpOnly cookies cannot be accessed through client script. This 
            // functionality helps reduce the chances of replay attacks.
            cookie.HttpOnly = true;

            cookie.Path = FormsAuthentication.FormsCookiePath;
            cookie.Secure = FormsAuthentication.RequireSSL;

            if (FormsAuthentication.CookieDomain != null)
            {
                cookie.Domain = FormsAuthentication.CookieDomain;
            }

            if (ticket.IsPersistent)
            {
                cookie.Expires = ticket.Expiration;
            }

            return cookie;
        }

        private static void ClearAuthCookie()
        {
            HttpContext current = HttpContext.Current;

            // Don't let anything see the incoming cookie 
            current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);

            // Remove the cookie from the response collection (by adding an expired/empty version).
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName);
            cookie.Expires = DateTime.Now.AddMonths(-1);
            cookie.Domain = FormsAuthentication.CookieDomain;
            cookie.Path = FormsAuthentication.FormsCookiePath;
            current.Response.Cookies.Add(cookie);
        }

        internal static SimulateUserData GetUserData(string userDataStr)
        {
            SimulateUserData userData = null;
            try
            {
                userData = JsonConvert.DeserializeObject<SimulateUserData>(userDataStr);
            }
            catch (Exception)
            {
            }
            if (userData == null)
            {
                return null;
            }

            // 验证逻辑
            var token = Encrypt(userData.UserName);
            if (token != userData.Token)
            {
                return null;
            }

            return userData;
        }

        private static string MD5Encrypt(string strText)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(strText));
            return BitConverter.ToString(result).Replace("-", "");// System.Text.Encoding.Default.GetString(result) ;
        }
    }

    public class SimulateUserData
    {
        public string UserName { get; set; }
        public string Token { get; set; }
        //public string TimeStamp { get; set; }
    }

    public class SimulatePrincipal : IPrincipal
    {
        public IIdentity Identity
        {
            get;
            private set;
        }

        public bool IsInRole(string role)
        {
            // Delegate to a role provider if this is a Web context and one is configured
            if (Roles.Provider != null)
            {
                return Roles.Provider.IsUserInRole(Identity.Name, role);
            }
            return false;
        }

        #region Constructors

        /// <summary>
        /// Constructs a new Principal backed by the supplied Assertion.
        /// </summary>
        /// <param name="assertion">
        /// the Assertion that backs this Principal
        /// </param>
        public SimulatePrincipal(string principalName)
        {
            Identity = new GenericIdentity(principalName, "Simulate");
        }

        #endregion
    }
}