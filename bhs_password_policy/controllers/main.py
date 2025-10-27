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

    @http.route('/web/login/totp', type='http', auth='public', methods=['GET', 'POST'], sitemap=False, website=True,
                multilang=False)
    def web_totp(self, redirect=None, **kwargs):
        """
        Handle 2FA login and check for password expiration before finalizing the session.
        If password is expired, redirect to reset password without completing 2FA.
        """
        ensure_db()
        # Check if there is a pre-authenticated user
        if not request.session.pre_uid:
            return request.redirect('/web/login')
        user = request.env['res.users'].sudo().search([('id', '=', request.session.pre_uid)])
        # user = request.env['res.users'].browse(request.session.pre_uid)
        if not user:
            return request.redirect('/web/login')
        # Check if password is expired before proceeding with 2FA
        if user._password_has_expired():
            # Trigger password expiration and redirect to reset password
            user.action_expire_password()
            request.session.logout(keep_db=True)
            redirect_url = user.partner_id.signup_url
            return request.redirect(redirect_url)
        # If password is not expired, proceed with original 2FA flow
        response = super(Home, self).web_totp(redirect=redirect, **kwargs)
        return response