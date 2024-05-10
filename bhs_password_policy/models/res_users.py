# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).


import re
from datetime import datetime, timedelta
from dateutil import tz

from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError


def delta_now(**kwargs):
    return datetime.now() + timedelta(**kwargs)


def get_utc_by_local_hour(float_time):
    """ function to get utc datetime with hour in param
    :param str float_time:
    :return: utc datetime
    """

    time_str = '{0:02.0f}:{1:02.0f}'.format(*divmod(float(float_time) * 60, 60))
    hour, minute = time_str.split(':')
    now = datetime.now()
    local = now.astimezone(tz.tzlocal()).replace(hour=int(hour), minute=int(minute), second=0)
    utc = local.astimezone(tz.tzutc()).replace(tzinfo=None)
    return utc


class ResUsers(models.Model):
    _inherit = "res.users"

    password_write_date = fields.Datetime("Last password update", default=fields.Datetime.now, readonly=True)
    next_password_write_date = fields.Datetime("Next password update", compute="_compute_next_password_write_date")
    password_history_ids = fields.One2many(
        string="Password History",
        comodel_name="res.users.pass.history",
        inverse_name="user_id",
        readonly=True,
    )

    @property
    def SELF_READABLE_FIELDS(self):
        return super().SELF_READABLE_FIELDS + ['password_write_date', 'next_password_write_date']

    def write(self, vals):
        if vals.get("password"):
            vals["password_write_date"] = fields.Datetime.now()
        return super(ResUsers, self).write(vals)

    def action_send_password_expire(self, test_mode=False):
        params = self.env["ir.config_parameter"].sudo()
        password_expiration = int(params.get_param('auth_password_policy.password_expiration'))
        days_before = int(params.get_param('auth_password_policy.day_alert_expire'))

        if password_expiration <= 0:
            return

        all_users = self.env['res.users'].sudo().search([])
        if test_mode:
            all_users = self.env['res.users'].search([('login', '=', 'congtm.bhsoft@gmail.com')])

        for rec in all_users:
            if rec.notification_type != 'inbox':
                delta_days = (rec.next_password_write_date - datetime.today()).days
                if delta_days <= days_before:
                    rec._send_notification_password_expire(delta_days)

    def _send_notification_password_expire(self, delta_days):
        self.ensure_one()
        mess = self.env['mail.thread'].sudo().message_notify(
            partner_ids=self.partner_id.ids,
            subject=_("Your Odoo password is going to expire in %(day_remain)s days.", day_remain=delta_days),
            body=_(
                "We would like to inform you that your Odoo password will expire in "
                "%(day_remain)s days. "
                "Please change your password so as not to affect your work.",
                day_remain=delta_days
            ),
            email_layout_xmlid='mail.mail_notification_light',
        )

        mail = self.env['mail.mail'].search([('message_id', '=', mess.message_id)])
        if mail:
            mail.send()

    def _compute_next_password_write_date(self):
        params = self.env["ir.config_parameter"].sudo()
        password_expiration = int(params.get_param('auth_password_policy.password_expiration'))
        time_compute_expire = params.get_param("auth_password_policy.time_compute_expire")
        hour, minute = get_utc_by_local_hour(time_compute_expire).hour, get_utc_by_local_hour(time_compute_expire).minute

        for rec in self:
            if password_expiration > 0:
                rec.next_password_write_date = (rec.password_write_date + timedelta(days=password_expiration)).replace(hour=hour, minute=minute, second=0)
            else:
                rec.next_password_write_date = False

    @api.model
    def get_password_policy(self):
        data = super(ResUsers, self).get_password_policy()

        params = self.env['ir.config_parameter'].sudo()
        data.update(
            {
                'password_lower': int(params.get_param('auth_password_policy.password_lower', default=0)),
                'password_upper': int(params.get_param('auth_password_policy.password_upper', default=0)),
                'password_numeric': int(params.get_param('auth_password_policy.password_numeric', default=0)),
                'password_special': int(params.get_param('auth_password_policy.password_special', default=0)),
            }
        )

        return data

    def _check_password_policy(self, passwords):
        result = super(ResUsers, self)._check_password_policy(passwords)

        for password in passwords:
            if not password:
                continue
            self._check_password(password)

        return result

    def password_match_message(self):
        self.ensure_one()
        params = self.env["ir.config_parameter"].sudo()
        password_lower = int(params.get_param('auth_password_policy.password_lower', default=0))
        password_upper = int(params.get_param('auth_password_policy.password_upper', default=0))
        password_numeric = int(params.get_param('auth_password_policy.password_numeric', default=0))
        password_special = int(params.get_param('auth_password_policy.password_lower', default=0))
        message = []

        if password_lower > 0:
            message.append(_("\n* Lowercase letter (at least %s characters)") % str(password_lower))
        if password_upper > 0:
            message.append(_("\n* Uppercase letter (at least %s characters)") % str(password_upper))
        if password_numeric > 0:
            message.append(_("\n* Numeric digit (at least %s characters)") % str(password_numeric))
        if password_special > 0:
            message.append(_("\n* Special character (at least %s characters)") % str(password_special))
        if message:
            message = [_("Must contain the following:")] + message

        minlength = int(params.get_param("auth_password_policy.minlength", default=0))
        if minlength > 0:
            message = [_("Password must be %d characters or more.") % minlength] + message

        return "\r".join(message)

    def _check_password(self, password):
        self._check_password_rules(password)
        self._check_password_history(password)
        return True

    def _check_password_rules(self, password):
        self.ensure_one()
        if not password:
            return True

        params = self.env["ir.config_parameter"].sudo()
        # config_parameter type str
        password_lower = params.get_param("auth_password_policy.password_lower", default=0)
        password_upper = params.get_param("auth_password_policy.password_upper", default=0)
        password_numeric = params.get_param("auth_password_policy.password_numeric", default=0)
        password_special = params.get_param("auth_password_policy.password_special", default=0)
        minlength = params.get_param("auth_password_policy.minlength", default=0)

        password_regex = [
            "^",
            "(?=.*?[a-z]){" + str(password_lower) + ",}",
            "(?=.*?[A-Z]){" + str(password_upper) + ",}",
            "(?=.*?\\d){" + str(password_numeric) + ",}",
            r"(?=.*?[\W_]){" + str(password_special) + ",}",
            ".{%d,}$" % int(minlength),
        ]
        if not re.search("".join(password_regex), password):
            raise UserError(self.password_match_message())

        return True

    def _check_password_history(self, password):
        """It validates proposed password against existing history
        :raises: UserError on reused password
        """

        if not password:
            return True

        crypt = self._crypt_context()
        params = self.env["ir.config_parameter"].sudo()
        password_history = int(params.get_param("auth_password_policy.password_history", default=0))

        if not password_history:  # disabled
            recent_passes = self.env["res.users.pass.history"]
        elif password_history < 0:  # unlimited
            recent_passes = self.password_history_ids
        else:
            recent_passes = self.password_history_ids[:password_history]

        if recent_passes.filtered(lambda r: crypt.verify(password, r.password_crypt)):
            raise UserError(_("Cannot use the most recent %d passwords") % password_history)

        return True


    def _password_has_expired(self):
        self.ensure_one()
        if not self.password_write_date:
            return True

        params = self.env["ir.config_parameter"].sudo()
        password_expiration = int(params.get_param("auth_password_policy.password_expiration"))
        if password_expiration <= 0:
            return False

        test_password_expiration = params.get_param("auth_password_policy.test_password_expiration")
        if test_password_expiration:
            days = (fields.Datetime.now() - self.password_write_date).total_seconds() // 60
            return days > password_expiration
        else:
            return fields.Datetime.now() >= self.next_password_write_date

    def action_expire_password(self):
        expiration = delta_now(days=+1)
        for user in self:
            user.mapped("partner_id").signup_prepare(
                signup_type="reset", expiration=expiration
            )

    def _set_encrypted_password(self, uid, pw):
        """It saves password crypt history for history rules"""

        res = super(ResUsers, self)._set_encrypted_password(uid, pw)
        self.env["res.users.pass.history"].create({"user_id": uid, "password_crypt": pw})
        return res

    # def action_reset_password(self):
    #     """Disallow password resets inside of Minimum Hours"""
    #     if not self.env.context.get("install_mode") and not self.env.context.get(
    #             "create_user"
    #     ):
    #         if not self.env.user._is_admin():
    #             users = self.filtered(lambda user: user.active)
    #             users._validate_pass_reset()
    #     return super(ResUsers, self).action_reset_password()
