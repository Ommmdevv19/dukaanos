

from django.urls import path
from . import views

urlpatterns = [
    # ── Registration ──────────────────────────────────────────────
    path('register/check/',          views.register_check,      name='register_check'),
    path('otp/send/',                views.otp_send,            name='otp_send'),
    path('otp/verify/register/',     views.otp_verify_register, name='otp_verify_register'),

    # ── Login ─────────────────────────────────────────────────────
    path('login/check/',             views.login_check,         name='login_check'),
    path('otp/verify/login/',        views.otp_verify_login,    name='otp_verify_login'),

    path('otp/verify/profile/',      views.profile_otp_verify,  name='profile_otp_verify'),

    # ── Forgot Password ───────────────────────────────────────────
    path('forgot/init/',             views.forgot_password_init,   name='forgot_init'),
    path('forgot/verify/',           views.forgot_password_verify, name='forgot_verify'),
    path('forgot/reset/',            views.forgot_password_reset,  name='forgot_reset'),

    # ── Session ───────────────────────────────────────────────────
    path('logout/',                  views.logout,              name='logout'),
    path('sessions/',                views.sessions_list,       name='sessions_list'),
    path('sessions/logout-all/',     views.logout_all_devices,  name='logout_all_devices'),
    path('me/',                      views.me,                  name='me'),
    path('change-password/',         views.change_password,     name='change_password'),

    # ── Categories ────────────────────────────────────────────────
    path('categories/',              views.categories,          name='categories'),
    path('bulk-upload/',             views.bulk_upload,         name='bulk_upload'),
    path('categories/<int:cat_id>/delete/', views.category_delete, name='category_delete'),

    # ── Items (v2 API) ────────────────────────────────────────────
    path('items/',                   views.items_list,          name='items_list'),
    path('items/<int:item_id>/',     views.item_detail,         name='item_detail'),
    path('items/<int:item_id>/stock/', views.add_stock,         name='add_stock'),
    path('low-stock-alerts/',        views.low_stock_alerts,    name='low_stock_alerts'),

    # ── Bills ─────────────────────────────────────────────────────
    path('bills/',                   views.bills,               name='bills'),
    path('export-report/',           views.export_report_data,  name='export_report_data'),

    # ── /products/ compatibility shim ─────────────────────────────
    # The frontend (index.html) still calls /products/ with old field names
    # (name, stock, price, wholesale). These routes translate them to the
    # v2 items + stock tables so index.html needs no changes.
    path('products/',                views.products_compat,       name='products_compat'),
    path('products/<int:prod_id>/',  views.product_detail_compat, name='product_detail_compat'),

    # ── Stock entries (Add Stock history log) ─────────────────────
    path('stock-entries/',           views.stock_entries_list,    name='stock_entries_list'),
]
