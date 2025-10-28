# Copyright 2015 LasLabs Inc.
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

import logging
import re

from werkzeug.exceptions import BadRequest

from odoo import http, _
from odoo.http import request, AccessDenied

from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.web.controllers.home import ensure_db
from odoo.addons.auth_totp.controllers import home as web_home
from odoo.addons.auth_totp.controllers.home import TRUSTED_DEVICE_COOKIE, TRUSTED_DEVICE_AGE

_logger = logging.getLogger(__name__)


class PasswordSecurityHome(AuthSignupHome):
    def do_signup(self, qcontext):
        """Check whether the password complies with policy when signup or reset password"""

        password = qcontext.get("password")
        login = qcontext.get("login")
        token = qcontext.get('token')
        if token:
            user_id = request.env['res.users'].sudo().search([('login', '=', login)], limit=1)
        else:
            user_id = request.env.user
        user_id._check_password(password)

        return super(PasswordSecurityHome, self).do_signup(qcontext)

    @http.route()
    def web_login(self, *args, **kw):
        """If password expired, redirect to reset password"""

        ensure_db()
        response = super(PasswordSecurityHome, self).web_login(*args, **kw)

        if not request.params.get("login_success"):
            return response
        if not request.env.user:
            return response
        # Now, I'm an authenticated user
        if not request.env.user._password_has_expired():
            return response

        # My password is expired, kick me out
        request.env.user.action_expire_password()
        request.session.logout(keep_db=True)
        # I was kicked out, so set login_success in request params to False
        request.params["login_success"] = False
        redirect = request.env.user.partner_id.signup_url

        return request.redirect(redirect)

    @http.route()
    def web_auth_signup(self, *args, **kw):
        """Try to catch all the possible exceptions not already handled in the parent method"""

        try:
            qcontext = self.get_auth_signup_qcontext()
        except Exception:
            raise BadRequest from None  # HTTPError: 400 Client Error: BAD REQUEST

        try:
            return super(PasswordSecurityHome, self).web_auth_signup(*args, **kw)
        except Exception as e:
            # Here we catch any generic exception since UserError is already
            # handled in parent method web_auth_signup()
            qcontext["error"] = str(e)
            response = request.render("auth_signup.signup", qcontext)
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
            return response


class Home(web_home.Home):

    # @http.route()
    # def web_totp(self, *args, **kw):
    #     """If password expired, redirect to reset password in case your organization use 2FA"""
    #
    #     ensure_db()
    #     response = super(Home, self).web_totp(*args, **kw)
    #
    #     if not request.params.get("redirect"):
    #         return response
    #     if not request.env.user or request.env.user.id == 4:
    #         return response
    #     # Now, I'm an authenticated user
    #     if not request.env.user._password_has_expired():
    #         return response
    #
    #     # My password is expired, kick me out
    #     request.env.user.action_expire_password()
    #     request.session.logout(keep_db=True)
    #     # I was kicked out, redirect me to reset password
    #     redirect = request.env.user.partner_id.signup_url
    #
    #     return request.redirect(redirect)

    @http.route(
        '/web/login/totp',
        type='http', auth='public', methods=['GET', 'POST'], sitemap=False,
        website=True, multilang=False  # website breaks the login layout...
    )
    def web_totp(self, redirect=None, **kwargs):
        if request.session.uid:
            return request.redirect(self._login_redirect(request.session.uid, redirect=redirect))

        if not request.session.pre_uid:
            return request.redirect('/web/login')

        error = None

        # user = request.env['res.users'].browse(request.session.pre_uid)
        user = request.env['res.users'].sudo().search([('id', '=', request.session.pre_uid)], limit=1)
        if user and request.httprequest.method == 'GET':
            cookies = request.httprequest.cookies
            key = cookies.get(TRUSTED_DEVICE_COOKIE)
            if key:
                user_match = request.env['auth_totp.device']._check_credentials_for_uid(
                    scope="browser", key=key, uid=user.id)
                if user_match:
                    request.session.finalize(request.env)
                    return request.redirect(self._login_redirect(request.session.uid, redirect=redirect))

        elif user and request.httprequest.method == 'POST' and kwargs.get('totp_token'):
            try:
                with user._assert_can_auth(user=user.id):
                    user._totp_check(int(re.sub(r'\s', '', kwargs['totp_token'])))
            except AccessDenied as e:
                error = str(e)
            except ValueError:
                error = _("Invalid authentication code format.")
            else:
                request.session.finalize(request.env)
                request.update_env(user=request.session.uid)
                request.update_context(**request.session.context)
                response = request.redirect(self._login_redirect(request.session.uid, redirect=redirect))
                if kwargs.get('remember'):
                    name = _("%(browser)s on %(platform)s",
                             browser=request.httprequest.user_agent.browser.capitalize(),
                             platform=request.httprequest.user_agent.platform.capitalize(),
                             )

                    if request.geoip.city.name:
                        name += f" ({request.geoip.city.name}, {request.geoip.country_name})"

                    key = request.env['auth_totp.device']._generate("browser", name)
                    response.set_cookie(
                        key=TRUSTED_DEVICE_COOKIE,
                        value=key,
                        max_age=TRUSTED_DEVICE_AGE,
                        httponly=True,
                        samesite='Lax'
                    )
                # Crapy workaround for unupdatable Odoo Mobile App iOS (Thanks Apple :@)
                request.session.touch()
                if user._password_has_expired():
                    user.action_expire_password()
                    request.session.logout(keep_db=True)
                    request.params["login_success"] = False
                    response = request.redirect(user.partner_id.signup_url)
                return response

        # Crapy workaround for unupdatable Odoo Mobile App iOS (Thanks Apple :@)
        request.session.touch()
        return request.render('auth_totp.auth_totp_form', {
            'user': user,
            'error': error,
            'redirect': redirect,
        })