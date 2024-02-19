# -*- coding: utf-8 -*-

import odoo
from odoo import api, http, models
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo.service import security
import werkzeug
import werkzeug.exceptions
import werkzeug.routing
import logging

_logger = logging.getLogger(__name__)


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _authenticate(cls, endpoint):
        auth = 'none' if http.is_cors_preflight(request, endpoint) else endpoint.routing['auth']

        try:
            if request.session.uid is not None:
                user = request.env['res.users'].browse(request.session.uid)

                # revoke all device if password expire
                if user._password_has_expired():
                    user._revoke_all_devices()
                    user.action_expire_password()
                    request.session.logout(keep_db=True)
                    request.env = api.Environment(request.env.cr, None, request.session.context)
                    redirect = user.partner_id.signup_url
                    return request.redirect(redirect)

                if not security.check_session(request.session, request.env):
                    request.session.logout(keep_db=True)
                    request.env = api.Environment(request.env.cr, None, request.session.context)
            getattr(cls, f'_auth_method_{auth}')()
        except (AccessDenied, http.SessionExpiredException, werkzeug.exceptions.HTTPException):
            raise
        except Exception:
            _logger.info("Exception during request Authentication.", exc_info=True)
            raise AccessDenied()
