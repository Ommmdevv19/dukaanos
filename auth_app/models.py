"""
DukaanOS Auth Models — Schema v2
Unmanaged models (managed = False): Django reads/writes to your existing
MySQL tables but does NOT create or migrate them.
All table structures come from dukaanos_schema_v2.sql.
"""

from django.db import models


# ──────────────────────────────────────────────────────────────
#  1. USERS & AUTH
# ──────────────────────────────────────────────────────────────

class User(models.Model):
    """Maps to TABLE: users"""
    user_id    = models.BigAutoField(primary_key=True)
    first_name = models.CharField(max_length=50)
    last_name  = models.CharField(max_length=50, null=True, blank=True)
    is_active  = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'users'

    def __str__(self):
        return f"{self.first_name} {self.last_name or ''} (id={self.user_id})"


class UserCredential(models.Model):
    """Maps to TABLE: user_credentials"""
    credential_id = models.BigAutoField(primary_key=True)
    user          = models.ForeignKey(User, on_delete=models.CASCADE,
                                      db_column='user_id',
                                      related_name='credentials')
    phone_number  = models.CharField(max_length=15, unique=True)
    email         = models.EmailField(max_length=100, unique=True,
                                       null=True, blank=True)
    password_hash = models.CharField(max_length=255)
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'user_credentials'

    def __str__(self):
        return f"Credentials(user={self.user_id}, phone={self.phone_number})"


class UserContactVerification(models.Model):
    """Maps to TABLE: user_contact_verification — used for OTPs"""
    TYPE_CHOICES = [('phone', 'Phone'), ('email', 'Email')]

    verification_id = models.BigAutoField(primary_key=True)
    user            = models.ForeignKey(User, on_delete=models.CASCADE,
                                        db_column='user_id')
    type            = models.CharField(max_length=10, choices=TYPE_CHOICES)
    otp_hash        = models.CharField(max_length=255)
    is_verified     = models.BooleanField(default=False)
    expires_at      = models.DateTimeField()
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'user_contact_verification'

    def __str__(self):
        return f"OTP[{self.type}] user={self.user_id}"


class LoginSession(models.Model):
    """Maps to TABLE: login_sessions"""
    STATUS_CHOICES = [('SUCCESS', 'Success'), ('FAILED', 'Failed')]

    session_id  = models.BigAutoField(primary_key=True)
    user        = models.ForeignKey(User, on_delete=models.CASCADE,
                                    db_column='user_id')
    login_time  = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    ip_address  = models.CharField(max_length=45, null=True, blank=True)
    device_info = models.CharField(max_length=255, null=True, blank=True)
    status      = models.CharField(max_length=10, choices=STATUS_CHOICES)

    class Meta:
        managed  = False
        db_table = 'login_sessions'

    def __str__(self):
        return f"Session user={self.user_id} [{self.status}]"


# ──────────────────────────────────────────────────────────────
#  2. STORES
# ──────────────────────────────────────────────────────────────

class Store(models.Model):
    """Maps to TABLE: stores"""
    store_id     = models.BigAutoField(primary_key=True)
    user         = models.ForeignKey(User, on_delete=models.CASCADE,
                                     db_column='user_id',
                                     related_name='stores')
    store_name   = models.CharField(max_length=100)
    location     = models.CharField(max_length=255, null=True, blank=True)
    pincode      = models.CharField(max_length=10, null=True, blank=True)
    gst_number   = models.CharField(max_length=20, null=True, blank=True)
    fssai_number = models.CharField(max_length=20, null=True, blank=True)
    is_active    = models.BooleanField(default=True)
    created_at   = models.DateTimeField(auto_now_add=True)
    updated_at   = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'stores'

    def __str__(self):
        return f"{self.store_name} (id={self.store_id})"


# ──────────────────────────────────────────────────────────────
#  3. CATEGORIES & ITEMS
# ──────────────────────────────────────────────────────────────

class Category(models.Model):
    """Maps to TABLE: categories"""
    category_id = models.BigAutoField(primary_key=True)
    store       = models.ForeignKey(Store, on_delete=models.CASCADE,
                                    db_column='store_id')
    name        = models.CharField(max_length=100)
    description = models.CharField(max_length=255, null=True, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'categories'

    def __str__(self):
        return f"{self.name} (store={self.store_id})"


class Item(models.Model):
    """Maps to TABLE: items"""
    item_id        = models.BigAutoField(primary_key=True)
    store          = models.ForeignKey(Store, on_delete=models.CASCADE,
                                       db_column='store_id')
    category       = models.ForeignKey(Category, on_delete=models.CASCADE,
                                       db_column='category_id')
    item_name      = models.CharField(max_length=100)
    brand          = models.CharField(max_length=100)
    gst_percentage = models.DecimalField(max_digits=5, decimal_places=2,
                                         default=0.00)
    created_at     = models.DateTimeField(auto_now_add=True)
    updated_at     = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'items'

    def __str__(self):
        return f"{self.item_name} — {self.brand}"


# ──────────────────────────────────────────────────────────────
#  4. STOCK
# ──────────────────────────────────────────────────────────────

class Stock(models.Model):
    """Maps to TABLE: stock — one row per item, total qty + avg prices"""
    stock_id         = models.BigAutoField(primary_key=True)
    category         = models.ForeignKey(Category, on_delete=models.CASCADE,
                                         db_column='category_id')
    item             = models.OneToOneField(Item, on_delete=models.CASCADE,
                                            db_column='item_id',
                                            related_name='stock')
    current_quantity = models.DecimalField(max_digits=10, decimal_places=2,
                                           default=0)
    wholesale_price  = models.DecimalField(max_digits=10, decimal_places=2)
    selling_price    = models.DecimalField(max_digits=10, decimal_places=2)
    created_at       = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True)

    class Meta:
        managed  = False
        db_table = 'stock'

    def __str__(self):
        return f"Stock item={self.item_id} qty={self.current_quantity}"


class StockEntry(models.Model):
    """Maps to TABLE: stock_entries — audit log for every stock addition"""
    entry_id       = models.BigAutoField(primary_key=True)
    stock          = models.ForeignKey(Stock, on_delete=models.CASCADE,
                                       db_column='stock_id')
    quantity_added = models.DecimalField(max_digits=10, decimal_places=2)
    purchase_price = models.DecimalField(max_digits=10, decimal_places=2,
                                         null=True, blank=True)
    selling_price  = models.DecimalField(max_digits=10, decimal_places=2,
                                         null=True, blank=True)
    supplier       = models.CharField(max_length=100, null=True, blank=True)
    notes          = models.CharField(max_length=500, null=True, blank=True)
    created_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'stock_entries'

    def __str__(self):
        return f"StockEntry stock={self.stock_id} +{self.quantity_added}"


# ──────────────────────────────────────────────────────────────
#  5. BILLING
# ──────────────────────────────────────────────────────────────

class Bill(models.Model):
    """Maps to TABLE: bills"""
    STATUS_CHOICES = [('COMPLETED', 'Completed'), ('CANCELLED', 'Cancelled')]

    bill_id         = models.BigAutoField(primary_key=True)
    store           = models.ForeignKey(Store, on_delete=models.CASCADE,
                                        db_column='store_id')
    bill_number     = models.CharField(max_length=50, unique=True)
    total_amount    = models.DecimalField(max_digits=10, decimal_places=2)
    total_gst       = models.DecimalField(max_digits=10, decimal_places=2,
                                          default=0)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2,
                                          default=0)
    final_amount    = models.DecimalField(max_digits=10, decimal_places=2)
    status          = models.CharField(max_length=10, choices=STATUS_CHOICES,
                                       default='COMPLETED')
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'bills'

    def __str__(self):
        return f"Bill#{self.bill_number} store={self.store_id}"


class BillItem(models.Model):
    """Maps to TABLE: bill_items"""
    bill_item_id   = models.BigAutoField(primary_key=True)
    bill           = models.ForeignKey(Bill, on_delete=models.CASCADE,
                                       db_column='bill_id',
                                       related_name='bill_items')
    category       = models.ForeignKey(Category, on_delete=models.DO_NOTHING,
                                       db_column='category_id')
    item           = models.ForeignKey(Item, on_delete=models.DO_NOTHING,
                                       db_column='item_id')
    quantity       = models.DecimalField(max_digits=10, decimal_places=2)
    price_at_sale  = models.DecimalField(max_digits=10, decimal_places=2)
    gst_percentage = models.DecimalField(max_digits=5, decimal_places=2,
                                         null=True, blank=True)
    gst_amount     = models.DecimalField(max_digits=10, decimal_places=2,
                                         null=True, blank=True)
    total_price    = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        managed  = False
        db_table = 'bill_items'

    def __str__(self):
        return f"BillItem bill={self.bill_id} item={self.item_id}"


class Payment(models.Model):
    """Maps to TABLE: payments"""
    METHOD_CHOICES = [('UPI', 'UPI'), ('CASH', 'Cash'), ('OTHER', 'Other')]

    payment_id      = models.BigAutoField(primary_key=True)
    bill            = models.ForeignKey(Bill, on_delete=models.CASCADE,
                                        db_column='bill_id',
                                        related_name='payments')
    method          = models.CharField(max_length=10, choices=METHOD_CHOICES)
    amount          = models.DecimalField(max_digits=10, decimal_places=2)
    upi_reference   = models.CharField(max_length=100, null=True, blank=True)
    cash_received   = models.DecimalField(max_digits=10, decimal_places=2,
                                          null=True, blank=True)
    change_returned = models.DecimalField(max_digits=10, decimal_places=2,
                                          null=True, blank=True)
    note            = models.CharField(max_length=255, null=True, blank=True)
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'payments'

    def __str__(self):
        return f"Payment bill={self.bill_id} {self.method} {self.amount}"


# ──────────────────────────────────────────────────────────────
#  6. DAILY METRICS
# ──────────────────────────────────────────────────────────────

class DailyMetric(models.Model):
    """Maps to TABLE: daily_metrics"""
    metric_id          = models.BigAutoField(primary_key=True)
    store              = models.ForeignKey(Store, on_delete=models.CASCADE,
                                           db_column='store_id')
    date               = models.DateField()
    total_sales        = models.DecimalField(max_digits=12, decimal_places=2,
                                             default=0)
    total_profit       = models.DecimalField(max_digits=12, decimal_places=2,
                                             default=0)
    total_transactions = models.IntegerField(default=0)
    top_item           = models.ForeignKey(Item, on_delete=models.SET_NULL,
                                           db_column='top_item_id',
                                           null=True, blank=True)

    class Meta:
        managed  = False
        db_table = 'daily_metrics'
        unique_together = [('store', 'date')]

    def __str__(self):
        return f"Metrics store={self.store_id} date={self.date}"


# ──────────────────────────────────────────────────────────────
#  7. AUDIT TABLES
# ──────────────────────────────────────────────────────────────

class AuditLogin(models.Model):
    """Maps to TABLE: audit_login"""
    STATUS_CHOICES = [('SUCCESS', 'Success'), ('FAILED', 'Failed')]

    audit_id     = models.BigAutoField(primary_key=True)
    user         = models.ForeignKey(User, on_delete=models.SET_NULL,
                                     db_column='user_id',
                                     null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    status       = models.CharField(max_length=10, choices=STATUS_CHOICES,
                                    null=True, blank=True)
    ip_address   = models.CharField(max_length=45, null=True, blank=True)
    device_info  = models.CharField(max_length=255, null=True, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'audit_login'


class AuditPasswordChange(models.Model):
    """Maps to TABLE: audit_password_changes"""
    audit_id   = models.BigAutoField(primary_key=True)
    user       = models.ForeignKey(User, on_delete=models.CASCADE,
                                   db_column='user_id')
    changed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)

    class Meta:
        managed  = False
        db_table = 'audit_password_changes'


class AuditContactChange(models.Model):
    """Maps to TABLE: audit_contact_changes"""
    audit_id   = models.BigAutoField(primary_key=True)
    user       = models.ForeignKey(User, on_delete=models.CASCADE,
                                   db_column='user_id')
    old_phone  = models.CharField(max_length=15, null=True, blank=True)
    new_phone  = models.CharField(max_length=15, null=True, blank=True)
    old_email  = models.CharField(max_length=100, null=True, blank=True)
    new_email  = models.CharField(max_length=100, null=True, blank=True)
    verified   = models.BooleanField(default=False)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'audit_contact_changes'


class AuditStockChange(models.Model):
    """Maps to TABLE: audit_stock_changes"""
    CHANGE_CHOICES = [('ADD', 'Add'), ('REMOVE', 'Remove'), ('SALE', 'Sale')]

    audit_id     = models.BigAutoField(primary_key=True)
    item         = models.ForeignKey(Item, on_delete=models.CASCADE,
                                     db_column='item_id')
    old_quantity = models.DecimalField(max_digits=10, decimal_places=2,
                                       null=True, blank=True)
    new_quantity = models.DecimalField(max_digits=10, decimal_places=2,
                                       null=True, blank=True)
    change_type  = models.CharField(max_length=10, choices=CHANGE_CHOICES,
                                    null=True, blank=True)
    reference_id = models.BigIntegerField(null=True, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'audit_stock_changes'


class AuditPriceChange(models.Model):
    """Maps to TABLE: audit_price_changes"""
    audit_id   = models.BigAutoField(primary_key=True)
    item       = models.ForeignKey(Item, on_delete=models.CASCADE,
                                   db_column='item_id')
    old_price  = models.DecimalField(max_digits=10, decimal_places=2,
                                     null=True, blank=True)
    new_price  = models.DecimalField(max_digits=10, decimal_places=2,
                                     null=True, blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed  = False
        db_table = 'audit_price_changes'
